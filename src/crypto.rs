use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::{
    aead::{Aead, AeadCore},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use p384::{
    ecdh::EphemeralSecret,
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    PublicKey, SecretKey,
};
use pin_project::pin_project;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::{io, mem::size_of, pin::Pin, task::Poll};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::io::{poll_read_buf, poll_write_buf};
use tracing::trace;

const LENGTH_SIZE: usize = size_of::<u32>();
const NONCE_SIZE: usize = size_of::<XNonce>();
const HEADER_SIZE: usize = NONCE_SIZE + LENGTH_SIZE;
const MSG_MAX_SIZE: usize = 4096;

pub struct Key {
    secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl Key {
    pub fn new(secret_key: SecretKey) -> Self {
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }
}

/// Handshake used to establish encrypted communication.
#[derive(Serialize, Deserialize)]
struct Handshake {
    verifier: VerifyingKey,
    signature: Signature,
    ephemeral_pubkey: PublicKey,
}

impl Handshake {
    /// Generate a new handshake.
    fn new(key: &Key, ephemeral_pubkey: PublicKey) -> Result<Self, Error> {
        let signing_key = SigningKey::from(&key.secret_key);
        let mut sign_data = [0u8; 1024];
        let sign_data = postcard::to_slice(&ephemeral_pubkey, &mut sign_data).map_err(|e| {
            Error::InvalidKey {
                reason: "serializing public key failed",
                source: e,
            }
        })?;

        let signature: Signature = signing_key.sign(sign_data);

        let hs = Self {
            verifier: VerifyingKey::from(key.public_key),
            signature,
            ephemeral_pubkey,
        };

        Ok(hs)
    }

    /// Insert a serialized handshake into a buffer.
    fn insert_buf(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let mut serialized_buf = [0u8; 1024];
        let handshake =
            postcard::to_slice(self, &mut serialized_buf).map_err(|e| Error::InvalidHandshake {
                reason: "serializing handshake failed",
                source: e,
            })?;

        buf.reserve(handshake.len() + 4);
        buf.put_u32(handshake.len() as u32);
        buf.extend_from_slice(handshake);
        Ok(())
    }
}

impl TryFrom<&[u8]> for Handshake {
    type Error = Error;

    /// Attempt to convert some bytes to a structured handshake
    ///
    /// The sender is authenticated using the signature.
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let handshake: Self = postcard::from_bytes(value).map_err(|e| Error::InvalidHandshake {
            reason: "deserializing handshake failed",
            source: e,
        })?;

        let mut signed_data = [0u8; 1024];
        let signed_data = postcard::to_slice(&handshake.ephemeral_pubkey, &mut signed_data)
            .map_err(|e| Error::InvalidKey {
                reason: "serializing public key failed",
                source: e,
            })?;

        handshake
            .verifier
            .verify(signed_data, &handshake.signature)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

        Ok(handshake)
    }
}

fn compute_cipher(
    eph_key: EphemeralSecret,
    peer_eph_pubkey: PublicKey,
) -> Result<XChaCha20Poly1305, Error> {
    let shared_secret = eph_key.diffie_hellman(&peer_eph_pubkey);
    let kdf = shared_secret.extract::<blake3::Hasher>(None);

    let mut symmetric_key = [0; 32];
    kdf.expand(&[], &mut symmetric_key)
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{e}")))?;
    let symmetric_key = chacha20poly1305::Key::from_slice(&symmetric_key);
    Ok(XChaCha20Poly1305::new(symmetric_key))
}

#[pin_project]
pub struct CryptoStream {
    #[pin]
    io: TcpStream,
    readbuf: BytesMut,
    writebuf: BytesMut,
    cipher: XChaCha20Poly1305,
}

impl CryptoStream {
    pub async fn new(key: &Key, mut io: TcpStream) -> Result<Self, Error> {
        trace!("performing handshake");

        let mut buf = BytesMut::with_capacity(1024);

        let ephemeral_key = EphemeralSecret::random(thread_rng());
        let handshake = Handshake::new(key, ephemeral_key.public_key())?;
        handshake.insert_buf(&mut buf)?;

        io.write_all_buf(&mut buf).await?;

        buf.clear();

        let length = io.read_u32().await?;

        buf.reserve(length as usize);
        while buf.len() < length as usize {
            io.read_buf(&mut buf).await?;
        }

        let peer_handshake = Handshake::try_from(&buf[..])?;

        let cipher = compute_cipher(ephemeral_key, peer_handshake.ephemeral_pubkey)?;

        trace!("handshake complete");

        Ok(Self {
            io,
            readbuf: BytesMut::with_capacity(4096),
            writebuf: BytesMut::with_capacity(4096),
            cipher,
        })
    }
}

impl AsyncRead for CryptoStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        trace!("begin read");

        let this = self.project();
        match poll_read_buf(this.io, cx, this.readbuf) {
            Poll::Ready(Ok(_)) => (),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }

        trace!("obtained {} bytes from stream", this.readbuf.len());

        if this.readbuf.len() <= HEADER_SIZE {
            return Poll::Pending;
        }

        let mut length = [0u8; 4];
        length.copy_from_slice(&this.readbuf[..4]);
        let length = u32::from_le_bytes(length);

        if length as usize > MSG_MAX_SIZE {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame of length {length} is too large."),
            ))?;
        }

        if this.readbuf.len() < HEADER_SIZE + length as usize {
            return Poll::Pending;
        }

        let nonce = XNonce::clone_from_slice(&this.readbuf[4..NONCE_SIZE + 4]);

        let plaintext: Vec<u8> = this
            .cipher
            .decrypt(
                &nonce,
                &this.readbuf[HEADER_SIZE..HEADER_SIZE + length as usize],
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;

        this.readbuf.advance(length as usize + HEADER_SIZE);

        trace!("decrypted {} bytes", plaintext.len());

        buf.put_slice(&plaintext);

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CryptoStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, io::Error>> {
        let this = self.project();

        if buf.len() > MSG_MAX_SIZE {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame of length {} is too large.", buf.len()),
            ))?;
        }

        trace!("encrypting {} bytes", buf.len());

        let nonce: XNonce = XChaCha20Poly1305::generate_nonce(thread_rng());

        let ciphertext = this
            .cipher
            .encrypt(&nonce, buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;

        let length: [u8; 4] = u32::to_le_bytes(ciphertext.len() as u32);

        this.writebuf.reserve(HEADER_SIZE + ciphertext.len());

        this.writebuf.extend_from_slice(&length);
        this.writebuf.extend_from_slice(&nonce);
        this.writebuf.extend_from_slice(&ciphertext);

        trace!(
            "attempting to flush buffer of {} bytes",
            this.writebuf.len()
        );

        match poll_write_buf(this.io, cx, this.writebuf) {
            Poll::Ready(Ok(n)) => n,
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        };
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        let this = self.project();

        trace!("flushing buffer of {} bytes", this.writebuf.len());

        match poll_write_buf(this.io, cx, this.writebuf) {
            Poll::Ready(Ok(_)) => (),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }

        if this.writebuf.has_remaining() {
            return Poll::Pending;
        }

        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        self.project().io.poll_shutdown(cx)
    }
}

/// Error used for the crypto module.
#[derive(Debug)]
pub enum Error {
    InvalidHandshake {
        reason: &'static str,
        source: postcard::Error,
    },
    InvalidKey {
        reason: &'static str,
        source: postcard::Error,
    },
    Io {
        reason: &'static str,
        source: io::Error,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHandshake { reason, source } => write!(f, "{reason}: {source}"),
            Self::InvalidKey { reason, source } => write!(f, "{reason}: {source}"),
            Self::Io { reason, source } => write!(f, "{reason}: {source}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io {
            reason: "IO failed",
            source: value,
        }
    }
}
