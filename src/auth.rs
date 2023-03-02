use std::{collections::HashSet, path::PathBuf, str::FromStr};
use tokio::{fs, io};

pub async fn load_auth(conf_dir: &mut PathBuf) -> io::Result<HashSet<blake3::Hash>> {
    conf_dir.push("auth");
    let hashes = fs::read_to_string(&conf_dir).await?;
    conf_dir.pop();
    Ok(HashSet::from_iter(
        hashes
            .lines()
            .filter_map(|h| blake3::Hash::from_str(h).ok()),
    ))
}
