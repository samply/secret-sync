use beam_lib::{reqwest::Url, AppId};
use clap::Parser;
use serde::Deserialize;
use serde_json::json;
use shared::SecretResult;

#[derive(Parser)]
struct GitLabApiConfig {
    /// The base URL for API calls, e.g. "https://gitlab.com/"
    #[clap(long, env)]
    pub gitlab_url: Url,
    /// A long-living personal (or impersonation) access token that is used to create short-living project access tokens. Requires at least the "api" scope. Note that group access tokens and project access tokens cannot be used to create project access tokens.
    #[clap(long, env)]
    pub gitlab_api_access_token: String,
}

#[derive(Deserialize)]
struct GitLabApiReponseBody {
    token: String,
}

pub struct GitLabProjectAccessTokenProvider {
    config: GitLabApiConfig,
    client: reqwest::Client,
}

/// Derive the bridgehead configuration repository from the beam id of the requester.
/// Example return value: "bridgehead-configurations/bridgehead-config-berlin"
fn derive_bridgehead_config_repo_from_beam_id(requester: &AppId) -> Result<String, String> {
    let mut parts = requester.as_ref().splitn(3, '.');
    let (_app, proxy, broker) = (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap());

    let group = match broker {
        "broker.ccp-it.dktk.dkfz.de" => "bridgehead-configurations", // ccp
        "broker.bbmri.sample.de" => "bbmri-bridgehead-configs", // bbmri
        "broker.bbmri.de" => "bbmri-bridgehead-configs", // gbn
        "test-no-real-data.broker.samply.de" => "bridgehead-configurations", // cce, itcc, kr
        "broker.hector.dkfz.de" => "dhki", // dhki
        _ => return Err(format!("Bridgehead configuration repository group not known for broker {broker}")),
    };

    Ok(match group {
        "bridgehead-configurations" => format!("{group}/bridgehead-config-{proxy}"),
        "dhki" => format!("{group}/{proxy}-bk"),
        _ => format!("{group}/{proxy}"),
    })
}

impl GitLabProjectAccessTokenProvider {
    pub fn try_init() -> Option<Self> {
        match GitLabApiConfig::try_parse() {
            Ok(config) => Some(Self {
                config,
                client: reqwest::Client::new(),
            }),
            Err(e) => {
                println!("{e}");
                None
            }
        }
    }

    /// Create a project access token using the GitLab API
    pub async fn create_token(
        &self,
        requester: &AppId,
    ) -> Result<SecretResult, String> {
        let project_path = derive_bridgehead_config_repo_from_beam_id(requester)?;

        // Expire in 1 week
        let expires_at = (chrono::Local::now() + chrono::TimeDelta::weeks(1))
            .format("%Y-%m-%d")
            .to_string();

        let response = self
            .client
            .post(
                self.config
                    .gitlab_url
                    .join(&format!(
                        "api/v4/projects/{}/access_tokens",
                        urlencoding::encode(&project_path)
                    ))
                    .map_err(|e| e.to_string())?,
            )
            .header("PRIVATE-TOKEN", &self.config.gitlab_api_access_token)
            .json(&json!({
                "name": requester,
                // The "read_repository" scope is required for git clone/pull permissions
                "scopes": ["read_repository"],
                // Access level 20 (Reporter) is the lowest level that allows git clone/pull
                "access_level": 20,
                "expires_at": expires_at,
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if response.status().is_success() {
            let body: GitLabApiReponseBody = response.json().await.map_err(|e| e.to_string())?;
            Ok(SecretResult::Created(body.token))
        } else {
            Err(format!(
                "HTTP status error {} for url {} with body {}",
                response.status(),
                response.url().clone(),
                response.text().await.map_err(|e| e.to_string())?
            ))
        }
    }

    /// Simulate a git fetch to check the validity of the token
    pub async fn validate_token(
        &self,
        requester: &AppId,
        secret: &str,
    ) -> Result<bool, String> {
        let project_path = derive_bridgehead_config_repo_from_beam_id(requester)?;

        let response = self
            .client
            .get(
                self.config
                    .gitlab_url
                    .join(&format!(
                        "{}.git/info/refs?service=git-upload-pack",
                        project_path
                    ))
                    .map_err(|e| e.to_string())?,
            )
            .basic_auth("placeholder-for-samply-secret-sync", Some(secret))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        Ok(response.status().is_success())
    }
}
