use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::trace;

pub type Transport<T> = Framed<T, Codec>;

pub struct Codec;

impl Decoder for Codec {
    type Item = Msg;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!("decode: {} bytes in buffer", src.len());
        if src.len() <= 4 {
            return Ok(None);
        }

        let mut length = [0; 4];
        length.copy_from_slice(&src[..4]);
        let length = u32::from_le_bytes(length);

        if src.len() < 4 + length as usize {
            return Ok(None);
        }

        let msg: Msg = postcard::from_bytes(&src[4..]).map_err(|e| Error::SerializeFailure {
            reason: "deserialization failed",
            source: e,
        })?;

        src.advance(4 + length as usize);

        trace!("decode: Msg::{:?}", msg);

        Ok(Some(msg))
    }
}

impl Encoder<Msg> for Codec {
    type Error = Error;

    fn encode(&mut self, item: Msg, dst: &mut BytesMut) -> Result<(), Self::Error> {
        trace!("encode: Msg::{:?}", item);
        let mut buf = [0u8; 1024];

        let n = postcard::to_slice(&item, &mut buf)
            .map_err(|e| Error::SerializeFailure {
                reason: "serialization failed",
                source: e,
            })?
            .len();

        dst.reserve(4 + n);
        dst.put_u32_le(n as u32);
        dst.extend_from_slice(&buf[..n]);

        trace!("encode: {} bytes added to buffer", n);

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Msg {
    RequestFile { path: PathBuf },
}

/// Error used for the crypto module.
#[derive(Debug)]
pub enum Error {
    SerializeFailure {
        reason: &'static str,
        source: postcard::Error,
    },
    Io {
        reason: &'static str,
        source: io::Error,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializeFailure { reason, source } => write!(f, "{reason}: {source}"),
            Self::Io { reason, source } => write!(f, "{reason}: {source}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io {
            reason: "underlying io-operation failed",
            source: value,
        }
    }
}
