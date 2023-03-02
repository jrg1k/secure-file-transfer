use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::debug;

pub type Transport<T> = Framed<T, Codec>;

#[derive(Serialize, Deserialize, Debug)]
pub enum Msg {
    NewSendFile { path: PathBuf },
    NewGetFile { path: PathBuf },
    FilePart { path: PathBuf, data: Vec<u8> },
    GetFilePart { path: PathBuf },
    FileEnd { path: PathBuf },
    Status(StatusKind),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum StatusKind {
    OK,
    FileError,
}

pub struct Codec;

impl Decoder for Codec {
    type Item = Msg;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() <= 4 {
            return Ok(None);
        }

        let mut length_buf = [0; 4];
        length_buf.copy_from_slice(&src[..4]);
        let length = u32::from_le_bytes(length_buf) as usize;

        if src.len() < 4 + length {
            src.reserve(4 + length - src.len());
            return Ok(None);
        }

        debug!("decoding {} bytes ", length);

        let msg: Msg =
            postcard::from_bytes(&src[4..4 + length]).map_err(Error::DeserializeFilure)?;

        src.advance(4 + length);
        src.reserve(4 + length);

        Ok(Some(msg))
    }
}

impl Encoder<Msg> for Codec {
    type Error = Error;

    fn encode(&mut self, item: Msg, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut buf = [0u8; 4096];

        let msg = postcard::to_slice(&item, &mut buf).map_err(Error::SerializeFailure)?;

        dst.reserve(4 + msg.len());
        dst.put_u32_le(msg.len() as u32);
        dst.extend_from_slice(msg);

        debug!("encoded {} bytes", msg.len());

        Ok(())
    }
}

/// Error used for the crypto module.
#[derive(Debug)]
pub enum Error {
    SerializeFailure(postcard::Error),
    DeserializeFilure(postcard::Error),
    Io {
        reason: &'static str,
        source: io::Error,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializeFailure(e) => write!(f, "failed to serialize message: {e}"),
            Self::DeserializeFilure(e) => write!(f, "failed to deserialize bytes to message: {e}"),
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
