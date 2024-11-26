use std::{convert::Infallible, path::PathBuf, str::FromStr};

use beam_lib::AppId;
use clap::Parser;
use shared::{OIDCConfig, SecretRequest};

/// Local secret sync
#[derive(Debug, Parser)]
pub struct Config {
    /// Will be used to create this apps beam app id and is already required by the beam proxy
    #[clap(long, env, hide(true))]
    pub proxy_id: String,

    /// A \xF1 separated list of secret definitions. See the Readme for a detailed explanation
    #[clap(long, env)]
    pub secret_definitions: SecretDefinitions,

    /// Path where the cached secrets are (to be mounted inside this container with write access)
    #[clap(long, env, default_value = "/usr/local/cache")]
    pub cache_path: PathBuf,

    /// The app id of this application
    #[clap(long, env, value_parser=|id: &str| Ok::<_, Infallible>(AppId::new_unchecked(id)))]
    pub oidc_provider: Option<AppId>,
}

#[derive(Debug, Clone)]
pub struct SecretDefinitions(pub Vec<SecretArg>);

impl FromStr for SecretDefinitions {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.split('\x1E')
            .filter(|s| !s.is_empty())
            .map(SecretArg::from_str)
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

#[derive(Debug, Clone)]
pub struct SecretArg {
    pub name: String,
    pub request: SecretRequest,
}

impl FromStr for SecretArg {
    type Err = String;

    /// keyloak:KEYCLOAK_TEILER_SECRET:$SITE_ID-teiler,...
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let [secret_type, name, args] = s.splitn(3, ':').collect::<Vec<_>>()[..] else {
            return Err(format!("'{s}' is not a valid secret specifier. Syntax is <secret_type>:<OUTPUT_VAR_NAME>:<args>"));
        };

        // Add new `SecretRequest` variants here
        let request = match secret_type {
            "OIDC" => {
                let (is_public, args) = match args.split_once(';') {
                    Some(("public", args)) => (true, args),
                    Some(("private", args)) => (false, args),
                    _ => return Err(format!("Invalid OIDC parameters '{args}'. Syntax is <public|private>;<redirect_url1,redirect_url2,...>")),
                };
                let redirect_urls = args.split(',').map(ToString::to_string).collect();
                Ok(SecretRequest::OpenIdConnect(OIDCConfig {
                    redirect_urls,
                    is_public,
                }))
            }
            _ => Err(format!("Unknown secret type {secret_type}")),
        }?;

        Ok(SecretArg {
            name: name.to_string(),
            request,
        })
    }
}
