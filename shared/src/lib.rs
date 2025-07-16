use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SecretType {
    OpenIdConnect(OIDCConfig),
    GitLabProjectAccessToken(GitlabClientConfig),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OIDCConfig {
    pub is_public: bool,
    pub redirect_urls: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GitlabClientConfig {
    /// Which GitLab server to use, e.g. 'verbis' or 'bbmri'
    pub gitlab_instance: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SecretResult {
    AlreadyValid,
    Created(String),
    AlreadyExisted(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RequestType {
    ValidateOrCreate(String),
    Create,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretRequest {
    pub request_type: RequestType,
    pub secret_type: SecretType,
}
