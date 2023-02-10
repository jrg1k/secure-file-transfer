use p384::SecretKey;
use rand::thread_rng;
use secure_file_transfer::{crypto::CryptoStream, Key};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let stream = TcpStream::connect("127.0.0.1:8080").await?;
    let key = Key::new(SecretKey::random(thread_rng()));
    let mut stream = CryptoStream::new(&key, stream).await?;

    let _n = stream.write(b"hello from client").await?;
    let _n = stream.write(b"hello from client 2").await?;

    Ok(())
}
