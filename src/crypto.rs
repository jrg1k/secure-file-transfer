use std::mem::size_of;

use aead::{Aead, AeadCore, OsRng};
use bytes::{Buf, BytesMut};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder, Framed};

struct CryptoCodec {
    cipher: XChaCha20Poly1305,
}

impl CryptoCodec {
    pub fn stream<T>(cipher: XChaCha20Poly1305, io: T) -> Framed<T, Self>
    where
        T: AsyncRead + AsyncWrite + Sized,
    {
        Self { cipher }.framed(io)
    }
}

impl Decoder for CryptoCodec {
    type Item = Vec<u8>;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() <= size_of::<XNonce>() + 4 {
            return Ok(None);
        }

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_le_bytes(length_bytes) as usize;

        if length > 4096 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame of length {} is too large.", length),
            ));
        }

        if src.len() < size_of::<XNonce>() + length + 4 {
            return Ok(None);
        }

        src.advance(4);
        let nonce = XNonce::clone_from_slice(&src[..size_of::<XNonce>()]);
        src.advance(size_of::<XNonce>());
        let plaintext: Result<Vec<u8>, chacha20poly1305::Error> =
            self.cipher.decrypt(&nonce, &src[..length]);
        let plaintext = plaintext
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}", e)))?;

        Ok(Some(plaintext))
    }
}

impl Encoder<Vec<u8>> for CryptoCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.len() > 4096 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame of length {} is too large.", item.len()),
            ));
        }
        let len_slice = u32::to_le_bytes(item.len() as u32);

        let nonce: XNonce = XChaCha20Poly1305::generate_nonce(OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, item.as_ref())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}", e)))?;

        dst.reserve(4 + size_of::<XNonce>() + ciphertext.len());

        dst.extend_from_slice(&len_slice);
        dst.extend_from_slice(&nonce);
        dst.extend_from_slice(&ciphertext);
        Ok(())
    }
}
