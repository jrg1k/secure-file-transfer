use p384::SecretKey;
use rand::thread_rng;
use secure_file_transfer::crypto::Key;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

use tracing::{debug, error};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let secret_key = SecretKey::random(thread_rng());
    let key = Arc::new(Key::new(secret_key));
    let listener = TcpListener::bind("0.0.0.0:8080").await?;

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("{}", e);
                continue;
            }
        };

        let key = Arc::clone(&key);
        tokio::spawn(async move {
            if let Err(e) = handle_client(addr.to_string(), stream, key).await {
                debug!("client {}", e)
            }
        });
    }
}

#[tracing::instrument(level = "info", skip_all, fields(addr = addr))]
async fn handle_client(addr: String, stream: TcpStream, key: Arc<Key>) -> anyhow::Result<()> {
    debug!("handling connection from {}", addr);

    secure_file_transfer::server::serve(&key, stream).await?;

    Ok(())
}
