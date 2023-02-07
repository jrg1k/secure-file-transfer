use p384::SecretKey;
use rand::thread_rng;
use secure_file_transfer::{Client, Key};
use tokio::net::TcpStream;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let stream = TcpStream::connect("127.0.0.1:8080").await?;
    let key = Key::new(SecretKey::random(thread_rng()));
    let mut client = Client::new(stream, &key).await?;
    let resp = client.message(b"hello from client".to_vec()).await?;
    dbg!(std::str::from_utf8(&resp).unwrap());
    let resp = client.message(b"hello from client 2".to_vec()).await?;
    dbg!(std::str::from_utf8(&resp).unwrap());

    Ok(())
}
