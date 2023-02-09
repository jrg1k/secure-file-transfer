pub mod crypto;

pub use crypto::Key;

use crypto::{CryptoCodec, CryptoError};
use futures_util::never::Never;
use std::{
    future::{poll_fn, ready, Ready},
    io,
    task::{Context, Poll},
};
use tokio::net::TcpStream;
use tower::Service;
use tracing::debug;

pub struct Client {
    svc: crypto::ClientService<TcpStream>,
}

impl Client {
    pub async fn new(stream: TcpStream, key: &Key) -> io::Result<Self> {
        let stream = CryptoCodec::new(key, stream).await.unwrap();

        Ok(Client {
            svc: crypto::ClientService::new(stream),
        })
    }

    pub async fn message(&mut self, msg: Vec<u8>) -> Result<Vec<u8>, CryptoError<TcpStream>> {
        poll_fn(|cx| self.svc.poll_ready(cx)).await?;
        self.svc.call(msg).await
    }
}

pub struct ServerSvc;

impl Service<Vec<u8>> for ServerSvc {
    type Response = Vec<u8>;
    type Error = Never;
    type Future = Ready<Result<Vec<u8>, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Vec<u8>) -> Self::Future {
        let req = std::str::from_utf8(&req).unwrap();
        debug!("{req}");
        ready(Ok(b"Hello from server".to_vec()))
    }
}
