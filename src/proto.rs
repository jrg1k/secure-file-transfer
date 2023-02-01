use std::sync::Arc;

use anyhow::anyhow;
use bincode::Options;
use p384::{
    ecdh::{diffie_hellman, EphemeralSecret},
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::debug;

const BUFFER_SIZE: usize = 4096;

#[derive(Serialize, Deserialize, Debug)]
pub enum Frame {
    Handshake(PublicKey, Signature, PublicKey),
    Error(String),
}

impl Frame {
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::DefaultOptions::new()
            .with_limit(BUFFER_SIZE as u64)
            .deserialize(bytes)?)
    }

    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(bincode::DefaultOptions::new()
            .with_limit(BUFFER_SIZE as u64)
            .serialize(self)?)
    }
}

pub struct MessageHandler {
    key: Arc<Key>,
    buffer: [u8; BUFFER_SIZE],
    stream: TcpStream,
    random_key: Option<EphemeralSecret>,
}

impl MessageHandler {
    pub fn new(key: Arc<Key>, stream: TcpStream) -> Self {
        Self {
            key,
            buffer: [0; 4096],
            stream,
            random_key: None,
        }
    }

    pub fn generate_handshake(&mut self) -> Frame {
        let signing_key = SigningKey::from(&self.key.secret_key);
        let random = EphemeralSecret::random(OsRng);
        let random_pk = random.public_key();
        let signature: Signature = signing_key.sign(random_pk.to_string().as_bytes());

        self.random_key = Some(random);

        Frame::Handshake(self.key.public_key, signature, random_pk)
    }

    pub fn handshake(
        &mut self,
        peer_key: PublicKey,
        peer_singature: Signature,
        peer_random: PublicKey,
    ) -> anyhow::Result<Frame> {
        VerifyingKey::from(peer_key).verify(peer_random.to_string().as_bytes(), &peer_singature)?;

        let handshake = self.generate_handshake();

        self.random_key = None;

        Ok(self.generate_handshake())
    }

    pub async fn read(&mut self) -> anyhow::Result<usize> {
        Ok(self.stream.read(&mut self.buffer).await?)
    }

    pub async fn send(&mut self, response: Frame) -> anyhow::Result<usize> {
        Ok(self.stream.write(&response.to_bytes()?).await?)
    }

    pub fn parse(&self, size: usize) -> anyhow::Result<Frame> {
        Frame::from_bytes(&self.buffer[..size])
    }

    pub fn response(&mut self, request: Frame) -> anyhow::Result<Frame> {
        match request {
            Frame::Handshake(pubkey, signature, random) => {
                self.handshake(pubkey, signature, random)
            }
            Frame::Error(errmsg) => {
                debug!("{}", errmsg);
                Err(anyhow!("error: {}", errmsg))
            }
        }
    }
}
