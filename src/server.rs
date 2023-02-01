mod crypto;

use p384::SecretKey;
use rand::thread_rng;
use secure_file_transfer::{Key, Server};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    ServerState::bind(&"127.0.0.1:8080".parse().unwrap())
        .await?
        .serve()
        .await;

    Ok(())
}

struct ServerState {
    listener: TcpListener,
    key: Arc<Key>,
}

impl ServerState {
    async fn bind(addr: &SocketAddr) -> tokio::io::Result<Self> {
        let listener = TcpListener::bind(&addr).await?;

        let secret_key = SecretKey::random(thread_rng());
        let key = Arc::new(Key::new(secret_key));

        info!("server listening on {}", addr);
        Ok(Self { listener, key })
    }

    async fn serve(&self) {
        loop {
            let (stream, addr) = match self.listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    debug!("{}", e);
                    continue;
                }
            };
            debug!("accepted connection from {}", addr);

            let key = Arc::clone(&self.key);
            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, key).await {
                    debug!("client {}", e)
                }
                debug!("dropping connection from {}", addr);
            });
        }
    }
}

async fn handle_client(stream: TcpStream, key: Arc<Key>) -> anyhow::Result<()> {
    Server::new(stream, &key).await?.serve().await?;
    Ok(())
}
