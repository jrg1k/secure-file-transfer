use crate::proto::{StatusKind, Transport};
use crate::{
    crypto,
    crypto::{AsymKey, CryptoStream},
    proto,
    proto::Msg,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::{
    fmt::Formatter,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{fs::File, io::AsyncReadExt, io::AsyncWriteExt, net::TcpStream, sync::Mutex};
use tokio_tower::pipeline;
use tokio_util::codec::Decoder;
use tower::Service;

/// serve the client over a plaintext transport
pub async fn serve_plain(stream: TcpStream) -> Result<(), Error> {
    let transport = proto::Codec.framed(stream);
    pipeline::Server::new(transport, ServerSvc::new()).await?;
    Ok(())
}

/// serve the client over an encrypted transport
pub async fn serve_encrypted(
    key: &AsymKey,
    auth: &HashSet<blake3::Hash>,
    stream: TcpStream,
) -> Result<(), Error> {
    let stream = CryptoStream::new(key, auth, stream).await?;
    let transport = proto::Codec.framed(stream);
    pipeline::Server::new(transport, ServerSvc::new()).await?;
    Ok(())
}

pub struct ServerSvc {
    files: Arc<Mutex<HashMap<PathBuf, File>>>,
}

impl ServerSvc {
    fn new() -> Self {
        Self {
            files: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Service<Msg> for ServerSvc {
    type Response = Msg;
    type Error = Box<dyn std::error::Error + Send>;
    type Future = Pin<Box<dyn Future<Output = Result<Msg, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Msg) -> Self::Future {
        let files = Arc::clone(&self.files);
        let fut = async move {
            let mut files = files.lock().await;
            match req {
                Msg::NewSendFile { path } => {
                    let file = match File::create(&path).await {
                        Ok(f) => f,
                        Err(_) => return Ok(Msg::Status(StatusKind::FileError)),
                    };
                    files.insert(path, file);
                    Ok(Msg::Status(StatusKind::OK))
                }
                Msg::NewGetFile { path } => {
                    let file = match File::open(&path).await {
                        Ok(f) => f,
                        Err(_) => return Ok(Msg::Status(StatusKind::FileError)),
                    };
                    files.insert(path, file);
                    Ok(Msg::Status(StatusKind::OK))
                }
                Msg::FileEnd { path } => {
                    files.remove(&path);
                    Ok(Msg::Status(StatusKind::OK))
                }
                Msg::FilePart { path, data } => {
                    let file = match files.get_mut(&path) {
                        Some(f) => f,
                        None => return Ok(Msg::Status(StatusKind::FileError)),
                    };

                    match file.write_all(&data).await {
                        Ok(_) => Ok(Msg::Status(StatusKind::OK)),
                        Err(_) => Ok(Msg::Status(StatusKind::FileError)),
                    }
                }
                Msg::GetFilePart { path } => {
                    let file = match files.get_mut(&path) {
                        Some(f) => f,
                        None => return Ok(Msg::Status(StatusKind::FileError)),
                    };

                    let mut buf = [0u8; 4096];
                    let n = match file.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return Ok(Msg::Status(StatusKind::FileError)),
                    };

                    if n == 0 {
                        return Ok(Msg::FileEnd { path });
                    }

                    Ok(Msg::FilePart {
                        path,
                        data: buf[..n].into(),
                    })
                }
                _ => todo!(),
            }
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
