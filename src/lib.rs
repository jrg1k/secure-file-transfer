pub mod crypto;

pub use crypto::Key;
use futures_util::never::Never;
use std::{
    future::{ready, Ready},
    task::{Context, Poll},
};

use tower::Service;
use tracing::debug;

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
