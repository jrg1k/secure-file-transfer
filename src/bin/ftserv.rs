use p384::SecretKey;
use secure_file_transfer::{auth::load_auth, crypto::AsymKey, BoxRes};
use std::{collections::HashSet, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{
    fs,
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error};
use tracing_subscriber::EnvFilter;

#[derive(Debug)]
struct Args {
    listen_addr: SocketAddr,
    conf_dir: PathBuf,
}

struct State {
    key: AsymKey,
    auth: HashSet<blake3::Hash>,
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
    let sk = SecretKey::from_sec1_pem(&sk_str)?;

    let shared_state = Arc::new(State {
        key: AsymKey::new(sk),
        auth: load_auth(&mut args.conf_dir).await?,
    });
    let listener = TcpListener::bind(args.listen_addr).await?;

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("{}", e);
                continue;
            }
        };

        let state = Arc::clone(&shared_state);
        tokio::spawn(async move {
            if let Err(e) = handle_client(addr.to_string(), stream, state).await {
                debug!("client {}", e)
            }
        });
    }
}

#[tracing::instrument(level = "info", skip_all, fields(addr = addr))]
async fn handle_client(addr: String, stream: TcpStream, state: Arc<State>) -> BoxRes<()> {
    debug!("handling connection from {}", addr);

    secure_file_transfer::server::serve_encrypted(&state.key, &state.auth, stream).await?;

    Ok(())
}

fn parse_args() -> Result<Args, lexopt::Error> {
    use lexopt::prelude::*;

    let mut listen_addr = None;
    let mut conf_dir = None;
    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('c') | Long("conf-dir") => {
                conf_dir = Some(parser.value()?.parse()?);
            }
            Short('l') | Long("listen-address") => {
                listen_addr = Some(parser.value()?.parse()?);
            }
            Long("help") => {
                println!("Usage: ftserv -c|--conf-dir=CONF_DIR -l|--listen-address=LISTEN_ADDRESS");
                std::process::exit(0);
            }
            _ => return Err(arg.unexpected()),
        }
    }

    Ok(Args {
        listen_addr: listen_addr.ok_or("missing LISTEN_ADDRESS")?,
        conf_dir: conf_dir.ok_or("missing CONF_DIR")?,
    })
}
