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
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::{io, mem::size_of};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tower::pipeline::Client;
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::log::trace;

type Result<T> = std::result::Result<T, Error>;

pub type CryptoFrame<T> = Framed<T, CryptoCodec>;
pub type CryptoError<T> = tokio_tower::Error<CryptoFrame<T>, Vec<u8>>;
pub type ClientService<T> = Client<CryptoFrame<T>, CryptoError<T>, Vec<u8>>;

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
    fn new(key: &Key, ephemeral_pubkey: PublicKey) -> Result<Self> {
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
    fn insert_buf(&self, buf: &mut BytesMut) -> Result<()> {
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
) -> Result<XChaCha20Poly1305> {
    let shared_secret = eph_key.diffie_hellman(&peer_eph_pubkey);
    let kdf = shared_secret.extract::<blake3::Hasher>(None);

    let mut symmetric_key = [0; 32];
    kdf.expand(&[], &mut symmetric_key)
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{e}")))?;
    let symmetric_key = chacha20poly1305::Key::from_slice(&symmetric_key);
    Ok(XChaCha20Poly1305::new(symmetric_key))
}

pub struct CryptoCodec {
    cipher: XChaCha20Poly1305,
}

impl CryptoCodec {
    pub async fn new<T>(key: &Key, mut io: T) -> Result<Framed<T, Self>>
    where
        T: AsyncRead + AsyncWrite + Sized + Unpin,
    {
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

        Ok(Self { cipher }.framed(io))
    }
}

impl Decoder for CryptoCodec {
    type Item = Vec<u8>;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() <= HEADER_SIZE {
            return Ok(None);
        }

        let mut length = [0; LENGTH_SIZE];
        length.copy_from_slice(&src[..LENGTH_SIZE]);
        let length = u32::from_le_bytes(length);

        if length as usize > MSG_MAX_SIZE {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame of length {length} is too large."),
            ))?;
        }

        if src.len() < HEADER_SIZE + length as usize {
            return Ok(None);
        }

        let nonce = XNonce::clone_from_slice(&src[LENGTH_SIZE..NONCE_SIZE + LENGTH_SIZE]);

        src.advance(HEADER_SIZE);

        let plaintext: Vec<u8> = self
            .cipher
            .decrypt(&nonce, &src[..length as usize])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;

        src.advance(length as usize);

        Ok(Some(plaintext))
    }
}

impl Encoder<Vec<u8>> for CryptoCodec {
    type Error = Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<()> {
        if item.len() > MSG_MAX_SIZE {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame of length {} is too large.", item.len()),
            ))?;
        }

        let nonce: XNonce = XChaCha20Poly1305::generate_nonce(thread_rng());

        let ciphertext = self
            .cipher
            .encrypt(&nonce, item.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;

        let length: [u8; 4] = u32::to_le_bytes(ciphertext.len() as u32);

        dst.reserve(HEADER_SIZE + ciphertext.len());

        dst.extend_from_slice(&length);
        dst.extend_from_slice(&nonce);
        dst.extend_from_slice(&ciphertext);
        Ok(())
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
