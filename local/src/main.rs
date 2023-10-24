use beam_lib::{BeamClient, AppId};
use clap::Parser;
use config::Config;
use once_cell::sync::Lazy;


mod config;

pub static CONFIG: Lazy<Config> = Lazy::new(Config::parse);

pub static BEAM_CLIENT: Lazy<BeamClient> = Lazy::new(|| BeamClient::new(
    &AppId::new_unchecked(format!("secret-sync.{}", CONFIG.proxy_id)),
    "NotSecret",
    "http://localhost:8081".parse().unwrap()
));

#[tokio::main]
async fn main() {
    todo!()
}
