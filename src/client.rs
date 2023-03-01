use crate::{
    crypto::{AsymKey, CryptoStream},
    proto::{self, Msg},
    BoxRes,
};
use std::future::poll_fn;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_tower::pipeline;
use tokio_util::codec::Decoder;
use tower::Service;

type Transport<T> = proto::Transport<T>;
type ClientError<T> = tokio_tower::Error<Transport<T>, Msg>;
pub type ClientSvc<T> = pipeline::Client<Transport<T>, ClientError<T>, Msg>;

pub struct Client<T>
where
    T: AsyncRead + AsyncWrite,
{
    svc: ClientSvc<T>,
}

impl Client<TcpStream> {
    /// connect to a server over a plaintext transport
    pub async fn plain(stream: TcpStream) -> BoxRes<Self> {
        let transport = proto::Codec.framed(stream);
        let svc: ClientSvc<TcpStream> = pipeline::Client::new(transport);

        Ok(Self { svc })
    }
}

impl Client<CryptoStream> {
    /// connect to a server over an encrypted transport
    pub async fn encrypted(key: &AsymKey, stream: TcpStream) -> BoxRes<Self> {
        let stream = CryptoStream::new(key, stream).await?;
        let transport: Transport<CryptoStream> = proto::Codec.framed(stream);
        let svc: ClientSvc<CryptoStream> = pipeline::Client::new(transport);

        Ok(Client { svc })
    }
}

impl<T> Client<T>
where
    for<'a> T: AsyncRead + AsyncWrite + 'a,
{
    pub async fn request(&mut self, msg: Msg) -> BoxRes<Msg> {
        poll_fn(|cx| self.svc.poll_ready(cx)).await?;
        Ok(self.svc.call(msg).await?)
    }
}
