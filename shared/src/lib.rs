use std::str::FromStr;

use serde::{Serialize, Deserialize};


#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SecretRequest {
    KeyCloak {
        args: String
    }
}

#[derive(Debug, Clone)]
pub struct SecretArg {
    pub name: String,
    pub request: SecretRequest
}

impl FromStr for SecretArg {
    type Err = String;

    /// keyloak:KEYCLOAK_TEILER_SECRET:$SITE_ID-teiler,...
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let [secret_type, name, args] = s.splitn(2, ':').collect::<Vec<_>>()[..] else {
            return Err(format!("'{s}' is not a valid secret specifier. Syntax is <secret_type>:<OUTPUT_VAR_NAME>:<args>"));
        };

        // Add new `SecretRequest` variants here
        let request = match secret_type {
            "keycloak" => Ok(SecretRequest::KeyCloak { args: args.to_string() }),
            _ => Err(format!("Unknown secret type {secret_type}"))
        }?;

        Ok(SecretArg { name: name.to_string(), request })
    }
}
