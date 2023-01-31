use async_bincode::tokio::AsyncBincodeReader;
use bincode::Options;
use bytes::{Buf, BytesMut};
use chacha20poly1305::{
    aead::{Aead, AeadCore},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use p384::{
    ecdh::{diffie_hellman, EphemeralSecret},
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
use tokio_util::codec::{Decoder, Encoder, Framed};

struct CryptoCodec {
    cipher: XChaCha20Poly1305,
}

const LENGTH_SIZE: usize = size_of::<u32>();
const NONCE_SIZE: usize = size_of::<XNonce>();
const HEADER_SIZE: usize = NONCE_SIZE + LENGTH_SIZE;
const MSG_MAX_SIZE: usize = 4096;
const PUBKEY_SIZE: usize = size_of::<PublicKey>();
const SIG_SIZE: usize = size_of::<Signature>();

#[derive(Serialize, Deserialize)]
struct Handshake {
    peer_key: PublicKey,
    signature: Signature,
    peer_eph_key: PublicKey,
}

impl Handshake {
    fn new(privkey: &SecretKey, eph_key: &EphemeralSecret) -> Self {
        let signing_key = SigningKey::from(privkey);
        let eph_pubkey = eph_key.public_key();
        let signature: Signature = signing_key.sign(eph_pubkey.to_string().as_bytes());

        Self {
            peer_key: privkey.public_key(),
            signature,
            peer_eph_key: eph_pubkey,
        }
    }
}

impl CryptoCodec {
    pub async fn server<T>(privkey: SecretKey, mut io: T) -> io::Result<Framed<T, Self>>
    where
        T: AsyncRead + AsyncWrite + Sized + Unpin + Clone,
    {
        let mut length = [0; 4];
        io.read_exact(&mut length).await?;
        let length = u32::from_le_bytes(length);

        let mut buf = vec![0; length as usize];
        io.read_exact(&mut buf).await?;

        let handshake: Handshake = bincode::DefaultOptions::new()
            .with_limit(4096)
            .deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        VerifyingKey::from(handshake.peer_key)
            .verify(
                handshake.peer_eph_key.to_string().as_bytes(),
                &handshake.signature,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

        let eph_key = EphemeralSecret::random(thread_rng());

        let hs_msg = Handshake::new(&privkey, &eph_key);
        let hs_msg = bincode::DefaultOptions::new()
            .with_limit(4096)
            .serialize(&hs_msg)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e))?;

        let length: [u8; 4] = u32::to_le_bytes(hs_msg.len() as u32);

        io.write_all(&length).await?;
        io.write_all(&hs_msg).await?;

        let shared_secret = eph_key.diffie_hellman(&handshake.peer_eph_key);
        let kdf = shared_secret.extract::<blake3::Hasher>(None);

        let mut key = [0; 32];
        kdf.expand(&[], &mut key)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e))?;
        let key = chacha20poly1305::Key::from(&key);
        let cipher = XChaCha20Poly1305::new(&key);

        Ok(Self { cipher }.framed(io))
    }

    pub async fn client<T>(privkey: SecretKey, mut io: T) -> io::Result<Framed<T, Self>>
    where
        T: AsyncRead + AsyncWrite + Sized + Unpin + Clone,
    {
        let eph_key = EphemeralSecret::random(thread_rng());

        let hs_msg = Handshake::new(&privkey, &eph_key);
        let hs_response = bincode::DefaultOptions::new()
            .with_limit(4096)
            .serialize(&hs_msg)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e))?;

        let length: [u8; 4] = u32::to_le_bytes(hs_response.len() as u32);

        io.write_all(&length).await?;
        io.write_all(&hs_response).await?;

        let mut length = [0; 4];
        io.read_exact(&mut length).await?;
        let length = u32::from_le_bytes(length);

        let mut buf = vec![0; length as usize];
        io.read_exact(&mut buf).await?;

        let handshake: Handshake = bincode::DefaultOptions::new()
            .with_limit(4096)
            .deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        VerifyingKey::from(handshake.peer_key)
            .verify(
                handshake.peer_eph_key.to_string().as_bytes(),
                &handshake.signature,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

        let shared_secret = eph_key.diffie_hellman(&handshake.peer_eph_key);
        let kdf = shared_secret.extract::<blake3::Hasher>(None);

        let mut key = [0; 32];
        kdf.expand(&[], &mut key)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e))?;
        let key = chacha20poly1305::Key::from(&key);
        let cipher = XChaCha20Poly1305::new(&key);

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
                format!("frame of length {} is too large.", length),
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
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?;

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
        let length: [u8; 4] = u32::to_le_bytes(item.len() as u32);

        let nonce: XNonce = XChaCha20Poly1305::generate_nonce(thread_rng());

        let ciphertext = self
            .cipher
            .encrypt(&nonce, item.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?;

        dst.reserve(HEADER_SIZE + ciphertext.len());

        dst.extend_from_slice(&length);
        dst.extend_from_slice(&nonce);
        dst.extend_from_slice(&ciphertext);
        Ok(())
    }
}
