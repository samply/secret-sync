use std::{collections::HashMap, convert::Infallible, net::SocketAddr};

use beam_lib::{reqwest::Url, AppId};
use clap::Parser;
use serde::{Deserialize, Serialize};
use shared::{OIDCConfig, SecretResult};

use crate::{
    auth::keycloak::{self, KeyCloakConfig},
    get_beamclient,
};

use super::authentik::{self, AuthentikConfig};

/// Central secret sync
#[derive(Debug, Parser)]
pub struct Config {
    /// Address the server should bind to
    #[clap(env, long, default_value = "0.0.0.0:8080")]
    pub bind_addr: SocketAddr,

    /// Url of the local beam proxy which is required to have sockets enabled
    #[clap(env, long, default_value = "http://beam-proxy:8081")]
    pub beam_url: Url,

    /// Beam api key
    #[clap(env, long)]
    pub beam_secret: String,

    /// The app id of this application
    #[clap(long, env, value_parser=|id: &str| Ok::<_, Infallible>(AppId::new_unchecked(id)))]
    pub beam_id: AppId,
}

#[derive(Clone, Debug)]
pub enum OIDCProvider {
    Keycloak(KeyCloakConfig),
    Authentik(AuthentikConfig),
}

impl OIDCProvider {
    pub fn try_init() -> Option<Self> {
        match (KeyCloakConfig::try_parse(), AuthentikConfig::try_parse()) {
            (Ok(key), _) => Some(OIDCProvider::Keycloak(key)),
            (_, Ok(auth)) => Some(OIDCProvider::Authentik(auth)),
            (Err(e), _) => {
                eprintln!("{e:#?}");
                None
            }
        }
    }

    pub async fn create_client(
        &self,
        name: &str,
        oidc_client_config: OIDCConfig,
    ) -> Result<SecretResult, String> {
        match self {
            OIDCProvider::Keycloak(conf) => {
                keycloak::create_client(name, oidc_client_config, conf).await
            }
            OIDCProvider::Authentik(conf) => {
                authentik::create_app_provider(name, oidc_client_config, conf).await
            }
        }
        .map_err(|e| {
            println!("Failed to create client: {e}");
            "Error creating OIDC client".into()
        })
    }

    pub async fn validate_client(
        &self,
        name: &str,
        secret: &str,
        oidc_client_config: &OIDCConfig,
    ) -> Result<bool, String> {
        match self {
            OIDCProvider::Keycloak(conf) => {
                keycloak::validate_client(name, oidc_client_config, secret, conf)
                    .await
                    .map_err(|e| {
                        eprintln!("Failed to validate client {name}: {e}");
                        "Failed to validate client. See upstrean logs.".into()
                    })
            }
            OIDCProvider::Authentik(conf) => {
                authentik::validate_application(name, oidc_client_config, conf, &get_beamclient())
                    .await
                    .map_err(|e| {
                        eprintln!("Failed to validate client {name}: {e}");
                        "Failed to validate client. See upstrean logs.".into()
                    })
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FlowPropertymapping {
    pub authorization_flow: String,
    pub property_mapping: HashMap<String, String>,
}
