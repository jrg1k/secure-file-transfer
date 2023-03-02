use elliptic_curve::sec1::ToEncodedPoint;
use p384::SecretKey;
use rand::thread_rng;
use secure_file_transfer::BoxRes;
use std::{fs, path::PathBuf};

struct Args {
    out: PathBuf,
}

fn parse_args() -> Result<Args, lexopt::Error> {
    use lexopt::prelude::*;

    let mut out = None;
    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('o') | Long("out") => {
                out = Some(parser.value()?.parse()?);
            }
            Long("help") => {
                println!("Usage: keygen -o|--out=OUT");
                std::process::exit(0);
            }
            _ => return Err(arg.unexpected()),
        }
    }

    Ok(Args {
        out: out.ok_or("missing OUT")?,
    })
}

fn main() -> BoxRes<()> {
    let mut args = parse_args()?;

    let privkey = SecretKey::random(thread_rng());
    let pubkey = privkey.public_key();

    args.out.push("key.priv");
    fs::write(&args.out, privkey.to_pem(Default::default())?.as_bytes())?;

    args.out.pop();

    args.out.push("key.pub");
    let pk_hash = blake3::hash(pubkey.to_encoded_point(false).as_bytes());

    fs::write(&args.out, pk_hash.to_hex().as_bytes())?;

    Ok(())
}
