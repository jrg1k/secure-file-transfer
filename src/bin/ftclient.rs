use p384::SecretKey;
use secure_file_transfer::auth::load_auth;
use secure_file_transfer::proto::StatusKind;
use secure_file_transfer::{client::Client, crypto::AsymKey, proto::Msg, BoxRes};
use std::{net::SocketAddr, path::PathBuf, str::FromStr};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing_subscriber::EnvFilter;

#[derive(Debug)]
struct Args {
    remote: SocketAddr,
    src: PathBuf,
    dst: PathBuf,
    conf_dir: PathBuf,
    kind: TransferKind,
}

#[derive(Debug)]
enum TransferKind {
    Send,
    Get,
}

#[tokio::main]
async fn main() -> BoxRes<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let mut args = parse_args()?;

    args.conf_dir.push("key.priv");
    let sk_str = fs::read_to_string(&args.conf_dir).await?;
    args.conf_dir.pop();

    let stream = TcpStream::connect(args.remote).await?;

    let sk = SecretKey::from_sec1_pem(&sk_str)?;
    let key = AsymKey::new(sk);

    let auth = load_auth(&mut args.conf_dir).await?;

    let client = Client::encrypted(&key, auth, stream).await?;

    match args.kind {
        TransferKind::Send => send(client, args).await?,
        TransferKind::Get => get(client, args).await?,
    }

    Ok(())
}

async fn get<T>(mut client: Client<T>, args: Args) -> BoxRes<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + 'static,
{
    let mut file = fs::File::create(args.dst).await?;

    let res = client
        .request(Msg::NewGetFile {
            path: args.src.clone(),
        })
        .await?;

    match res {
        Msg::Status(StatusKind::OK) => (),
        _ => Err("getting file failed")?,
    }

    loop {
        let resp = client
            .request(Msg::GetFilePart {
                path: args.src.clone(),
            })
            .await?;
        if let Msg::FileEnd { path: _ } = resp {
            break;
        }

        if let Msg::FilePart { path: _, data } = resp {
            file.write_all(&data).await?;
        }
    }

    Ok(())
}

async fn send<T>(mut client: Client<T>, args: Args) -> BoxRes<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + 'static,
{
    let mut file = fs::File::open(args.src).await?;

    let res = client
        .request(Msg::NewSendFile {
            path: args.dst.clone(),
        })
        .await?;

    match res {
        Msg::Status(StatusKind::OK) => (),
        _ => Err("sending file failed")?,
    }

    let mut buf = [0u8; 256];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        dbg!(n);

        client
            .request(Msg::FilePart {
                path: args.dst.clone(),
                data: buf[..n].into(),
            })
            .await?;
    }
    client.request(Msg::FileEnd { path: args.dst }).await?;

    Ok(())
}

fn parse_args() -> Result<Args, lexopt::Error> {
    use lexopt::prelude::*;

    let mut src = None;
    let mut dst = None;
    let mut conf_dir = None;
    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Value(val) => {
                if src.is_none() {
                    src = Some(val.string()?);
                } else if dst.is_none() {
                    dst = Some(val.string()?);
                } else {
                    Err("unexpected SRC/DST")?;
                }
            }
            Short('c') | Long("conf-dir") => {
                conf_dir = Some(parser.value()?.parse()?);
            }
            Long("help") => {
                println!("Usage: ftclient -c|--conf-dir=CONF_DIR [REMOTE]:SRC [REMOTE]:DST");
                std::process::exit(0);
            }
            _ => return Err(arg.unexpected()),
        }
    }

    let src = src.ok_or("SOURCE must be provided")?;
    let dst = dst.ok_or("DESTINATION must be provided")?;

    let (src, r1) = parse_remote(&src)?;
    let (dst, r2) = parse_remote(&dst)?;

    let (remote, kind) = match (r1, r2) {
        (Some(_), Some(_)) => Err("duplicate REMOTE")?,
        (Some(r), None) => (r, TransferKind::Get),
        (None, Some(r)) => (r, TransferKind::Send),
        _ => Err("missing REMOTE")?,
    };

    Ok(Args {
        remote,
        src,
        dst,
        conf_dir: conf_dir.ok_or("missing CONF_DIR")?,
        kind,
    })
}

fn parse_remote(path: &str) -> Result<(PathBuf, Option<SocketAddr>), lexopt::Error> {
    match path.rsplit_once(':') {
        Some((r, p)) => Ok((
            PathBuf::from(p),
            Some(SocketAddr::from_str(r).map_err(|_| "invalid REMOTE")?),
        )),
        None => Ok((PathBuf::from(path), None)),
    }
}
