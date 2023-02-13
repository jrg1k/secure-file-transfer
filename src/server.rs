use crate::{
    crypto::{self, Key},
    proto::{self, Msg},
};
use std::{
    future::{ready, Ready},
    path::PathBuf,
    task::{Context, Poll},
};
use tokio::net::TcpStream;
use tokio_tower::pipeline;
use tokio_util::codec::Decoder;
use tower::Service;
use tracing::debug;

/// serve the client over a plaintext transport
pub async fn serve_plain(stream: TcpStream) -> anyhow::Result<()> {
    let transport = proto::Codec.framed(stream);
    pipeline::Server::new(transport, ServerSvc).await.unwrap();
    Ok(())
}

/// serve the client over an encrypted transport
pub async fn serve_encrypted(key: &Key, stream: TcpStream) -> anyhow::Result<()> {
    let stream = crypto::CryptoStream::new(key, stream).await?;
    let transport = proto::Codec.framed(stream);
    pipeline::Server::new(transport, ServerSvc).await.unwrap();
    Ok(())
}

struct ServerSvc;

impl Service<Msg> for ServerSvc {
    type Response = Msg;
    type Error = anyhow::Error;
    type Future = Ready<Result<Msg, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Msg) -> Self::Future {
        debug!("{req:#?}");
        ready(Ok(Msg::RequestFile {
            path: PathBuf::from("/oogaboga"),
        }))
    }
}
