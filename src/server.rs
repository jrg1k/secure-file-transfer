use crate::proto::Transport;
use crate::{
    crypto,
    crypto::{AsymKey, CryptoStream},
    proto,
    proto::Msg,
};
use std::{
    fmt::Formatter,
    future::Future,
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::net::TcpStream;
use tokio_tower::pipeline;
use tokio_util::codec::Decoder;
use tower::Service;
use tracing::debug;

/// serve the client over a plaintext transport
pub async fn serve_plain(stream: TcpStream) -> Result<(), Error> {
    let transport = proto::Codec.framed(stream);
    pipeline::Server::new(transport, ServerSvc).await?;
    Ok(())
}

/// serve the client over an encrypted transport
pub async fn serve_encrypted(key: &AsymKey, stream: TcpStream) -> Result<(), Error> {
    let stream = CryptoStream::new(key, stream).await?;
    let transport = proto::Codec.framed(stream);
    pipeline::Server::new(transport, ServerSvc).await?;
    Ok(())
}

pub struct ServerSvc;

impl Service<Msg> for ServerSvc {
    type Response = Msg;
    type Error = Box<dyn std::error::Error + Send>;
    type Future = Pin<Box<dyn Future<Output = Result<Msg, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Msg) -> Self::Future {
        let fut = async move {
            debug!("{req:#?}");
            Ok(Msg::RequestFile {
                path: PathBuf::from("/from/server"),
            })
        };
        Box::pin(fut)
    }
}

type HandlerError<T> = pipeline::server::Error<Transport<T>, ServerSvc>;

#[derive(Debug)]
pub enum Error {
    HandlerErrorPlain(HandlerError<TcpStream>),
    HandlerErrorCrypto(HandlerError<CryptoStream>),
    HandshakeError(crypto::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::HandlerErrorPlain(e) => write!(f, "{e}"),
            Error::HandlerErrorCrypto(e) => write!(f, "{e}"),
            Error::HandshakeError(e) => write!(f, "handshake failed: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<HandlerError<TcpStream>> for Error {
    fn from(value: HandlerError<TcpStream>) -> Self {
        Self::HandlerErrorPlain(value)
    }
}

impl From<HandlerError<CryptoStream>> for Error {
    fn from(value: HandlerError<CryptoStream>) -> Self {
        Self::HandlerErrorCrypto(value)
    }
}

impl From<crypto::Error> for Error {
    fn from(value: crypto::Error) -> Self {
        Self::HandshakeError(value)
    }
}
