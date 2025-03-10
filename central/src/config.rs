use std::{convert::Infallible, path::PathBuf};

use beam_lib::{reqwest::Url, AppId};
use clap::Parser;
use shared::{OIDCConfig, SecretResult};

use crate::auth::{
    authentik::{self, AuthentikConfig},
    keycloak::{self, KeyCloakConfig},
};

/// Central secret sync
#[derive(Debug, Parser)]
pub struct Config {
    /// Url of the local beam proxy which is required to have sockets enabled
    #[clap(env, long, default_value = "http://beam-proxy:8081")]
    pub beam_url: Url,

    /// Beam api key
    #[clap(env, long)]
    pub beam_secret: String,

    /// The app id of this application
    #[clap(long, env, value_parser=|id: &str| Ok::<_, Infallible>(AppId::new_unchecked(id)))]
    pub beam_id: AppId,

    /// Path of the icinga config file
    #[clap(env, long, default_value = "/run/secrets/icinga.toml")]
    pub icinga_config_path: PathBuf,
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
                authentik::validate_application(name, oidc_client_config, secret, conf)
                    .await
                    .map_err(|e| {
                        eprintln!("Failed to validate client {name}: {e}");
                        "Failed to validate client. See upstrean logs.".into()
                    })
            }
        }
    }
}
