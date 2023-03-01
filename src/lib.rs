pub mod client;
pub mod crypto;
pub mod proto;
pub mod server;

pub type BoxRes<T> = Result<T, Box<dyn std::error::Error>>;
