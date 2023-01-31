mod proto;

use std::sync::Arc;

use p384::{elliptic_curve::rand_core::OsRng, SecretKey};
use proto::{Key, MessageHandler};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let stream = TcpStream::connect("127.0.0.1:8080").await?;
    let key = Key::new(SecretKey::random(OsRng));
    let mut handler = MessageHandler::new(Arc::new(key), stream);

    let handshake = handler.generate_handshake();
    handler.send(handshake).await?;
    let n = handler.read().await?;
    let request = handler.parse(n)?;
    dbg!(request);

    Ok(())
}
