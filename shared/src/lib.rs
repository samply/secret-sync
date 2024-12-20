use std::ops::Deref;

use serde::{Serialize, Deserialize};


#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SecretRequest {
    OpenIdConnect(OIDCConfig),
    GitLabProjectAccessToken(GitLabProject),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OIDCConfig {
    pub is_public: bool,
    pub redirect_urls: Vec<String>,
}

/// Describes the GitLab project for which a token is requested
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum GitLabProject {
    /// Request a token for the bridgehead configuration repository of the respective site. The repository
    /// is derived from the beam id of the secret sync local component that requests the token.
    BridgeheadConfiguration,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SecretResult {
    AlreadyValid,
    Created(String),
    AlreadyExisted(String)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SecretRequestType {
    ValidateOrCreate {
        current: String,
        request: SecretRequest
    },
    Create(SecretRequest)
}

impl Deref for SecretRequestType {
    type Target = SecretRequest;

    fn deref(&self) -> &Self::Target {
        match self {
            SecretRequestType::ValidateOrCreate { request, .. } |
            SecretRequestType::Create(request) => request,
        }
    }
}
