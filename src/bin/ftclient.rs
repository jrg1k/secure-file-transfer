use p384::SecretKey;
use rand::thread_rng;
use secure_file_transfer::{client::Client, crypto::AsymKey, proto::Msg, BoxRes};
use std::path::PathBuf;
use tokio::net::TcpStream;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> BoxRes<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let stream = TcpStream::connect("127.0.0.1:8080").await?;
    let key = AsymKey::new(SecretKey::random(thread_rng()));

    let mut client = Client::encrypted(&key, stream).await?;

    let res = client
        .request(Msg::RequestFile {
            path: PathBuf::from("/from/client"),
        })
        .await?;

    dbg!(res);

    Ok(())
}
