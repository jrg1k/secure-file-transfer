use aead::{AeadCore, AeadInPlace, KeyInit};
use bytes::BytesMut;
use chacha20poly1305::XChaCha20Poly1305;
use p384::ecdsa::Signature;
use rand::rngs::OsRng;
use std::mem::size_of;

fn main() {
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let mut buffer = BytesMut::with_capacity(128);
    buffer.extend_from_slice(b"plaintext message that is a bit long");

    // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
    cipher
        .encrypt_in_place(&nonce, b"yo", &mut buffer)
        .expect("failed");

    dbg!(buffer.len());
    dbg!(size_of::<Signature>());

    // `buffer` now contains the message ciphertext
    assert_ne!(&buffer[..], b"plaintext message");

    // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
    cipher
        .decrypt_in_place(&nonce, b"yo", &mut buffer)
        .expect("decryption to succeed");
    assert_eq!(&buffer[..], b"plaintext message that is a bit long");
}
