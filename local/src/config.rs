use clap::Parser;
use shared::SecretArg;

/// Local secret sync
#[derive(Debug, Parser)]
pub struct Config {
    /// Will be used to create this apps beam app id and is already required by the beam proxy
    #[clap(long, env)]
    pub proxy_id: String,

    /// Positional args used to specify several Secrets. Example keycloak:OUTPUTVARNAME:extrainfo??
    pub args: Vec<SecretArg>
}

