use crate::{
    crypto::{self, CryptoStream},
    proto::{self, Msg},
};
use std::future::poll_fn;
use tokio::net::TcpStream;
use tokio_tower::pipeline;
use tokio_util::codec::Decoder;
use tower::Service;

type Transport = proto::Transport<CryptoStream>;
type ClientError = tokio_tower::Error<Transport, Msg>;
pub type ClientSvc = pipeline::Client<Transport, ClientError, Msg>;

pub struct Client {
    svc: ClientSvc,
}

impl Client {
    pub async fn new(key: &crypto::Key, io: TcpStream) -> anyhow::Result<Self> {
        let stream = crypto::CryptoStream::new(key, io).await?;
        let transport = proto::Codec.framed(stream);
        let svc: ClientSvc = pipeline::Client::new(transport);

        Ok(Self { svc })
    }

    pub async fn request(&mut self, msg: Msg) -> anyhow::Result<()> {
        poll_fn(|cx| self.svc.poll_ready(cx)).await?;
        self.svc.call(msg).await?;
        Ok(())
    }
}
