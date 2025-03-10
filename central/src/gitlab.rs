use beam_lib::{reqwest::Url, AppId};
use clap::Parser;
use icinga_client::{IcingaProcessResult, IcingaServiceState, IcingaState};
use serde::Deserialize;
use serde_json::json;
use shared::SecretResult;
use tracing::warn;

use crate::{CONFIG, ICINGA_CLIENT};

#[derive(Parser)]
struct GitLabApiConfig {
    /// The base URL for API calls, e.g. "https://gitlab.com/"
    #[clap(long, env)]
    pub gitlab_url: Url,
    /// Format of the repository name on GitLab. Must contain a "#" which is replaced with the site name. Example: "bridgehead-configurations/bridgehead-config-#"
    #[clap(long, env)]
    pub gitlab_repo_format: String,
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
    pub async fn create_token(&self, requester: &AppId) -> Result<SecretResult, String> {
        let name = requester.as_ref().split('.').nth(1).unwrap();
        let gitlab_repo = self.config.gitlab_repo_format.replace('#', name);

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
                        urlencoding::encode(&gitlab_repo)
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
            report_to_icinga(
                requester,
                IcingaServiceState::Ok,
                format!("Site {name} has successfully retrieved a new GitLab token"),
                "rotate",
            )
            .await;
            Ok(SecretResult::Created(body.token))
        } else {
            let err_msg = format!(
                "HTTP status error {} for url {} with body {}",
                response.status(),
                response.url().clone(),
                response.text().await.map_err(|e| e.to_string())?
            );
            report_to_icinga(
                requester,
                IcingaServiceState::Warning,
                format!("Site {name} requested a GitLab token but it could not be created: {err_msg}"),
                "rotate",
            )
            .await;
            Err(err_msg)
        }
    }

    /// Simulate a git fetch to check the validity of the token
    pub async fn validate_token(&self, requester: &AppId, secret: &str) -> Result<bool, String> {
        let name = requester.as_ref().split('.').nth(1).unwrap();
        let gitlab_repo = self.config.gitlab_repo_format.replace('#', name);

        let response = self
            .client
            .get(
                self.config
                    .gitlab_url
                    .join(&format!(
                        "{}.git/info/refs?service=git-upload-pack",
                        gitlab_repo
                    ))
                    .map_err(|e| e.to_string())?,
            )
            .basic_auth("placeholder-for-samply-secret-sync", Some(secret))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        report_to_icinga(
            requester,
            IcingaServiceState::Ok,
            format!("Site {name} has successfully validated an existing GitLab token"),
            "validate",
        )
        .await;

        Ok(response.status().is_success())
    }
}

pub async fn report_to_icinga(requester: &AppId, state: IcingaServiceState, message: String, action: &str) {
    let Some(icinga_client) = ICINGA_CLIENT.as_ref() else {
        return;
    };

    // send site report
    icinga_client
        .report_to_icinga(&IcingaProcessResult {
            exit_status: IcingaState::Service(state),
            plugin_output: message.clone(),
            filter: format!(
                "host.address==\"{}\" && service.name==\"bridgehead-git-access-token-rotation-{}\"",
                requester.proxy_id(),
                action,
            ),
            ..Default::default()
        })
        .await
        .inspect_err(|e| warn!("Failed to report to icinga: {e}"))
        .ok();

    // send central report
    icinga_client
        .report_to_icinga(&IcingaProcessResult {
            exit_status: IcingaState::Service(state),
            plugin_output: message,
            filter: format!(
                "host.address==\"{}\" && service.name==\"git-access-token-rotator\"",
                CONFIG.beam_id
            ),
            ..Default::default()
        })
        .await
        .inspect_err(|e| warn!("Failed to report to icinga: {e}"))
        .ok();
}
