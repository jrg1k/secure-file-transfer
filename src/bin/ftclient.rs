use std::path::PathBuf;

use p384::SecretKey;
use rand::thread_rng;
use secure_file_transfer::{client::Client, crypto::Key, proto::Msg};
use tokio::net::TcpStream;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let stream = TcpStream::connect("127.0.0.1:8080").await?;
    let key = Key::new(SecretKey::random(thread_rng()));

    let mut client = Client::new(&key, stream).await?;

    client
        .request(Msg::RequestFile {
            path: PathBuf::from("/some/patj"),
        })
        .await?;

    Ok(())
}
