use std::{path::PathBuf, convert::Infallible};

use beam_lib::AppId;
use clap::Parser;
use shared::SecretArg;

/// Local secret sync
#[derive(Debug, Parser)]
pub struct Config {
    /// Will be used to create this apps beam app id and is already required by the beam proxy
    #[clap(long, env, hide(true))]
    pub proxy_id: String,

    /// Positional args used to specify several Secrets. Example keycloak:OUTPUTVARNAME:extrainfo??
    pub args: Vec<SecretArg>,

    /// Path where the cached secrets are (to be mounted inside this container with write access)
    #[clap(long, env, default_value = "/usr/local/central_auth.txt")]
    pub cache_path: PathBuf,

    /// The app id of this application
    #[clap(long, env, value_parser=|id: &str| Ok::<_, Infallible>(AppId::new_unchecked(id)))]
    pub central_beam_id: AppId,
}

