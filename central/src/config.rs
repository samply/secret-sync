use std::{net::SocketAddr, convert::Infallible};

use beam_lib::{AppId, reqwest::Url};
use clap::Parser;
use shared::SecretResult;

use crate::keycloak::{KeyCloakConfig, self};

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

#[derive(Clone, Debug)]
pub enum OIDCProvider {
    Keycloak(KeyCloakConfig)
}

impl OIDCProvider {
    pub fn try_init() -> Option<Self> {
        KeyCloakConfig::try_parse().map_err(|e| println!("{e}")).ok().map(Self::Keycloak)
    }

    pub async fn create_client(&self, name: &str, redirect_urls: Vec<String>) -> Result<SecretResult, String> {
        match self {
            OIDCProvider::Keycloak(conf) => keycloak::create_client(name, redirect_urls, conf).await,
        }.map_err(|e| {
            println!("Failed to create client: {e}");
            "Error creating OIDC client".into()
        })
    }
}
