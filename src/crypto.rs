use bincode::Options;
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
use tracing::debug;

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

#[derive(Serialize, Deserialize)]
struct Handshake {
    peer_key: PublicKey,
    signature: Signature,
    eph_key: PublicKey,
}

impl Handshake {
    fn create(buf: &mut BytesMut, key: &Key, eph_key: &EphemeralSecret) -> io::Result<()> {
        let signing_key = SigningKey::from(&key.secret_key);
        let eph_pubkey = eph_key.public_key();
        let signature: Signature = signing_key.sign(eph_pubkey.to_string().as_bytes());

        let hs = Self {
            peer_key: key.public_key,
            signature,
            eph_key: eph_pubkey,
        };
        let hs = bincode::DefaultOptions::new()
            .with_limit(4096)
            .serialize(&hs)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e))?;

        buf.put_u32(hs.len() as u32);
        buf.reserve(hs.len());
        buf.extend_from_slice(&hs);
        Ok(())
    }

    fn read(buf: &[u8]) -> io::Result<Self> {
        let handshake: Handshake = bincode::DefaultOptions::new()
            .with_limit(4096)
            .deserialize(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        VerifyingKey::from(handshake.peer_key)
            .verify(
                handshake.eph_key.to_string().as_bytes(),
                &handshake.signature,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

        Ok(handshake)
    }
}

pub struct CryptoCodec {
    cipher: XChaCha20Poly1305,
}

impl CryptoCodec {
    pub async fn server<T>(key: &Key, mut io: T) -> io::Result<Framed<T, Self>>
    where
        T: AsyncRead + AsyncWrite + Sized + Unpin,
    {
        debug!("performing handshake");
        let length = io.read_u32().await?;

        let mut buf = BytesMut::with_capacity(length as usize);
        while buf.len() < length as usize {
            io.read_buf(&mut buf).await?;
        }

        let peer_hs = Handshake::read(&buf)?;
        buf.clear();

        let eph_key = EphemeralSecret::random(thread_rng());
        Handshake::create(&mut buf, key, &eph_key)?;

        io.write_all_buf(&mut buf).await?;

        let shared_secret = eph_key.diffie_hellman(&peer_hs.eph_key);
        let kdf = shared_secret.extract::<blake3::Hasher>(None);

        let mut symmetric_key = [0; 32];
        kdf.expand(&[], &mut symmetric_key)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{e}")))?;
        let symmetric_key = chacha20poly1305::Key::from_slice(&symmetric_key);
        let cipher = XChaCha20Poly1305::new(symmetric_key);

        debug!("handshake complete");
        Ok(Self { cipher }.framed(io))
    }

    pub async fn client<T>(key: &Key, mut io: T) -> io::Result<Framed<T, Self>>
    where
        T: AsyncRead + AsyncWrite + Sized + Unpin,
    {
        debug!("performing handshake");
        let mut buf = BytesMut::new();
        let eph_key = EphemeralSecret::random(thread_rng());
        Handshake::create(&mut buf, key, &eph_key)?;
        io.write_all_buf(&mut buf).await?;

        let length = io.read_u32().await?;

        buf.clear();
        buf.reserve(length as usize);

        while buf.len() < length as usize {
            io.read_buf(&mut buf).await?;
        }

        let peer_hs = Handshake::read(&buf)?;

        let shared_secret = eph_key.diffie_hellman(&peer_hs.eph_key);
        let kdf = shared_secret.extract::<blake3::Hasher>(None);

        let mut symmetric_key = [0; 32];
        kdf.expand(&[], &mut symmetric_key)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{e}")))?;
        let symmetric_key = chacha20poly1305::Key::from_slice(&symmetric_key);
        let cipher = XChaCha20Poly1305::new(symmetric_key);

        debug!("handshake complete");
        Ok(Self { cipher }.framed(io))
    }
}

impl Decoder for CryptoCodec {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
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
    type Error = io::Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
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
