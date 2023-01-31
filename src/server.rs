mod proto;
mod crypto;

use p384::elliptic_curve::rand_core::OsRng;
use p384::SecretKey;
use proto::{Key, MessageHandler};
use std::{error::Error, net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    Server::bind(&"127.0.0.1:8080".parse().unwrap())
        .await?
        .serve()
        .await;

    Ok(())
}

struct Server {
    listener: TcpListener,
    key: Arc<Key>,
}

impl Server {
    async fn bind(addr: &SocketAddr) -> tokio::io::Result<Self> {
        let listener = TcpListener::bind(&addr).await?;

        let secret_key = SecretKey::random(OsRng);
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
            });
        }
    }
}

async fn handle_client(stream: TcpStream, key: Arc<Key>) -> anyhow::Result<()> {
    let mut handler = MessageHandler::new(key, stream);
    loop {
        let n = handler.read().await?;
        let request = handler.parse(n)?;
        let response = handler.response(request)?;
        handler.send(response).await?;
    }
}
