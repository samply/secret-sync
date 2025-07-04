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
impl OIDCConfig {
    pub fn client_type(&self, name: &str) -> String {
        format!("{}-{}", name, if self.is_public { "public" } else { "private" })
    }
    pub fn secret_type(&self, name: &str) -> String {
        if !self.is_public {
            generate_secret()
        } else {
            String::with_capacity(0)
        }
    }
    //use case federation id 
    pub fn flipped_client_type(&self, name: &str) -> String {
        format!("{}-{}", name, if self.is_public { "private" } else { "public" })
    }
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

pub fn generate_secret() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";
    const PASSWORD_LEN: usize = 30;
    let mut rng = rand::rng();

    (0..PASSWORD_LEN)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}
