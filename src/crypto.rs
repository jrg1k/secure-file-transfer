use aead::{
    stream::{DecryptorLE31, EncryptorLE31, NewStream, StreamLE31, StreamPrimitive},
    KeyInit, Payload,
};
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::XChaCha20Poly1305;
use elliptic_curve::sec1::ToEncodedPoint;
use p384::{
    ecdh::EphemeralSecret,
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    PublicKey, SecretKey,
};
use pin_project_lite::pin_project;
use rand::prelude::*;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::task::Context;
use std::{collections::HashSet, mem::size_of};
use std::{io, pin::Pin, task::Poll};
use tokio::{
    io::AsyncRead,
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
use tokio_util::io::{poll_read_buf, poll_write_buf};
use tracing::debug;

type Aead = XChaCha20Poly1305;
type Stream = StreamLE31<Aead>;
type StreamNonce = aead::stream::Nonce<Aead, Stream>;
type Encryptor = EncryptorLE31<XChaCha20Poly1305>;
type Decryptor = DecryptorLE31<XChaCha20Poly1305>;

const MSG_MAX_SIZE: usize = 8192;
const TAG_SIZE: usize = 16;

pub struct AsymKey {
    secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl AsymKey {
    pub fn new(secret_key: SecretKey) -> Self {
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Kex {
    ephemeral_pubkey: PublicKey,
    nonce: StreamNonce,
    random: [u8; 32],
}

/// Handshake used to establish encrypted communication.
#[derive(Serialize, Deserialize)]
struct Handshake {
    verifier: PublicKey,
    signature: Signature,
    kex: Kex,
}

impl Handshake {
    /// Generate a new handshake.
    fn new(key: &AsymKey, ephemeral_pubkey: PublicKey, nonce: StreamNonce) -> Result<Self, Error> {
        let mut random = [0u8; 32];
        thread_rng().fill_bytes(&mut random);

        let kex = Kex {
            ephemeral_pubkey,
            nonce,
            random,
        };

        let signing_key: SigningKey = (&key.secret_key).into();

        let mut sign_buf = [0u8; size_of::<Kex>() * 2];
        let sign_data = postcard::to_slice(&kex, &mut sign_buf)
            .expect("serialization buffer should be large enough");

        let hs = Self {
            verifier: key.public_key,
            signature: signing_key.sign(sign_data),
            kex,
        };

        Ok(hs)
    }

    /// Insert a serialized handshake into a buffer.
    fn insert_buf(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let mut serialized_buf = [0u8; size_of::<Self>() * 2];
        let handshake = postcard::to_slice(self, &mut serialized_buf)
            .expect("serialization buffer should be large enough");

        buf.reserve(4 + handshake.len());
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
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let handshake: Self = postcard::from_bytes(value).map_err(|e| Error::InvalidHandshake {
            reason: "deserializing handshake failed",
            source: e,
        })?;

        let mut sign_buf = [0u8; size_of::<Kex>() * 2];
        let signed_data = postcard::to_slice(&handshake.kex, &mut sign_buf)
            .expect("serialization buffer should be large enough");

        VerifyingKey::from(handshake.verifier)
            .verify(signed_data, &handshake.signature)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

        Ok(handshake)
    }
}

fn compute_cipher(
    eph_key: EphemeralSecret,
    peer_hs: Handshake,
    enc_nonce: StreamNonce,
) -> Result<(Encryptor, Decryptor), Error> {
    let shared_secret = eph_key.diffie_hellman(&peer_hs.kex.ephemeral_pubkey);
    let kdf = shared_secret.extract::<blake3::Hasher>(None);

    let mut symmetric_key = [0; 32];
    kdf.expand(b"\xDE\xAD\xBE\xFF", &mut symmetric_key)
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{e}")))?;

    let cipher: Aead = Aead::new_from_slice(&symmetric_key).expect("key should be 32 bytes");

    let enc_stream = StreamLE31::from_aead(cipher.clone(), &enc_nonce);
    let dec_stream = StreamLE31::from_aead(cipher, &peer_hs.kex.nonce);

    let encryptor = enc_stream.encryptor();
    let decryptor = dec_stream.decryptor();

    Ok((encryptor, decryptor))
}

pin_project! {
    pub struct CryptoStream {
        io: TcpStream,
        readbuf: BytesMut,
        writebuf: BytesMut,
        encryptor: Encryptor,
        decryptor: Decryptor,
    }
}

impl CryptoStream {
    pub async fn new(
        key: &AsymKey,
        auth: &HashSet<blake3::Hash>,
        mut io: TcpStream,
    ) -> Result<Self, Error> {
        debug!("performing handshake");

        let mut buf = BytesMut::with_capacity(1024);

        let ephemeral_key = EphemeralSecret::random(thread_rng());
        let mut nonce = StreamNonce::default();
        thread_rng().fill_bytes(&mut nonce);

        let handshake = Handshake::new(key, ephemeral_key.public_key(), nonce)?;
        handshake.insert_buf(&mut buf)?;

        io.write_all_buf(&mut buf).await?;

        buf.clear();

        let length = io.read_u32().await?;

        buf.reserve(length as usize);
        while buf.len() < length as usize {
            io.read_buf(&mut buf).await?;
        }

        let peer_handshake = Handshake::try_from(&buf[..])?;

        let hash = blake3::hash(peer_handshake.verifier.to_encoded_point(false).as_bytes());
        if !auth.contains(&hash) {
            return Err(Error::AuthenticationFailure(hash));
        }

        let (encryptor, decryptor) = compute_cipher(ephemeral_key, peer_handshake, nonce)?;

        debug!("handshake complete");

        Ok(Self {
            io,
            readbuf: BytesMut::with_capacity(4096),
            writebuf: BytesMut::with_capacity(4096),
            encryptor,
            decryptor,
        })
    }
}

impl AsyncRead for CryptoStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();

        match poll_read_buf(Pin::new(this.io), cx, this.readbuf) {
            Poll::Ready(Ok(_)) => (),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }

        if this.readbuf.len() <= 4 {
            return Poll::Pending;
        }

        let mut length_buf = [0u8; 4];
        length_buf.copy_from_slice(&this.readbuf[..4]);
        let length = u32::from_le_bytes(length_buf) as usize;

        if length > MSG_MAX_SIZE {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame of length {length} is too large."),
            ))?;
        }

        if this.readbuf.len() < 4 + length {
            this.readbuf.reserve(4 + length - this.readbuf.len());
            return Poll::Pending;
        }

        debug!("decrypting {} bytes from stream", length);

        let plaintext = this
            .decryptor
            .decrypt_next(Payload {
                msg: &this.readbuf[4..4 + length],
                aad: &length_buf,
            })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;

        buf.put_slice(&plaintext);

        this.readbuf.advance(4 + length);
        this.readbuf.reserve(4 + length);

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CryptoStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();

        if buf.len() > MSG_MAX_SIZE {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("frame of length {} is too large.", buf.len()),
            ))?;
        }

        match this.io.poll_write_ready(cx) {
            Poll::Ready(Ok(_)) => (),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }

        debug!("encrypting {} bytes", buf.len());

        let length = buf.len() + TAG_SIZE;
        let length_buf: [u8; 4] = u32::to_le_bytes(length as u32);

        let ciphertext = this
            .encryptor
            .encrypt_next(Payload {
                aad: &length_buf,
                msg: buf,
            })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;

        debug_assert_eq!(ciphertext.len(), length);

        this.writebuf.reserve(4 + length);
        this.writebuf.extend_from_slice(&length_buf);
        this.writebuf.extend_from_slice(&ciphertext);

        match poll_write_buf(Pin::new(this.io), cx, this.writebuf) {
            Poll::Ready(Ok(n)) => n,
            Poll::Pending => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "expected stream to be writable",
                )));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        };

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.project();

        debug!("flushing buffer of {} bytes", this.writebuf.len());

        while this.writebuf.has_remaining() {
            match poll_write_buf(Pin::new(this.io), cx, this.writebuf) {
                Poll::Ready(Ok(n)) => n,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            };
        }

        if this.writebuf.has_remaining() {
            return Poll::Pending;
        }

        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(self.project().io).poll_shutdown(cx)
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
    AuthenticationFailure(blake3::Hash),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHandshake { reason, source } => write!(f, "{reason}: {source}"),
            Self::InvalidKey { reason, source } => write!(f, "{reason}: {source}"),
            Self::Io { reason, source } => write!(f, "{reason}: {source}"),
            Self::AuthenticationFailure(h) => {
                write!(f, r#"failed to authenticate peer with pubkey hash "{h}""#)
            }
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
