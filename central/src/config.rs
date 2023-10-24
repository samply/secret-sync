use std::{net::SocketAddr, convert::Infallible};

use beam_lib::{AppId, reqwest::Url};
use clap::Parser;

/// Central secret sync
#[derive(Debug, Parser)]
pub struct Config {
    /// Address the server should bind to
    #[clap(env, default_value = "0.0.0.0:8080")]
    pub bind_addr: SocketAddr,

    /// Url of the local beam proxy which is required to have sockets enabled
    #[clap(env, default_value = "http://beam-proxy:8081")]
    pub beam_url: Url,

    /// Url of the local Keycloak
    #[clap(env, default_value = "http://keycloak:8080")] // TODO: Find the right default url
    pub keycloak_url: Url,

    /// Beam api key
    #[clap(env)]
    pub beam_secret: String,

    /// The app id of this application
    #[clap(long, env, value_parser=|id: &str| Ok::<_, Infallible>(AppId::new_unchecked(id)))]
    pub beam_id: AppId,
}
