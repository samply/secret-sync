use std::ops::Deref;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SecretRequest {
    OpenIdConnect(OIDCConfig),
    GitLabProjectAccessToken(GitLabClientConfig),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OIDCConfig {
    pub is_public: bool,
    pub redirect_urls: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GitLabClientConfig {
    pub provider: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SecretResult {
    AlreadyValid,
    Created(String),
    AlreadyExisted(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SecretRequestType {
    ValidateOrCreate {
        current: String,
        request: SecretRequest,
    },
    Create(SecretRequest),
}

impl Deref for SecretRequestType {
    type Target = SecretRequest;

    fn deref(&self) -> &Self::Target {
        match self {
            SecretRequestType::ValidateOrCreate { request, .. }
            | SecretRequestType::Create(request) => request,
        }
    }
}
