use std::collections::HashMap;

use beam_lib::{reqwest::Url, AppId};
use clap::Parser;
use icinga_client::{IcingaProcessResult, IcingaServiceState, IcingaState};
use serde::Deserialize;
use serde_json::json;
use shared::SecretResult;
use tracing::warn;

use crate::{CONFIG, ICINGA_CLIENT};

struct GitLabServerConfig {
    /// The base URL for API calls, e.g. "https://gitlab.com/"
    pub gitlab_url: Url,
    /// Format of the repository name on GitLab. Must contain a "#" which is replaced with the site name. Example: "bridgehead-configurations/bridgehead-config-#"
    pub gitlab_repo_format: String,
    /// A long-living personal (or impersonation) access token that is used to create short-living project access tokens. Requires at least the "api" scope. Note that group access tokens and project access tokens cannot be used to create project access tokens.
    pub gitlab_api_access_token: String,
}

#[derive(Deserialize)]
struct GitLabApiReponseBody {
    token: String,
}

pub struct GitLabProjectAccessTokenProvider {
    configs: HashMap<String, GitLabServerConfig>,
    client: reqwest::Client,
}

fn parse_env_vars() -> HashMap<String, GitLabServerConfig> {
    let mut configs = HashMap::new();
    let env_vars: HashMap<String, String> = std::env::vars().collect();
    for (name, value) in &env_vars {
        if let Some(prefix) = name.strip_suffix("_GITLAB_URL") {
            let gitlab_url = match Url::parse(value) {
                Ok(gitlab_url) => gitlab_url,
                Err(parse_error) => {
                    warn!("Failed to parse URL in environment variable {prefix}_GITLAB_URL: {parse_error}");
                    continue;
                }
            };
            let Some(gitlab_repo_format) = env_vars.get(&format!("{prefix}_GITLAB_REPO_FORMAT")).cloned() else {
                warn!("Because the environment variable {prefix}_GITLAB_URL is present {prefix}_GITLAB_REPO_FORMAT is also required but it is missing");
                continue;
            };
            let Some(gitlab_api_access_token) = env_vars.get(&format!("{prefix}_GITLAB_API_ACCESS_TOKEN")).cloned() else {
                warn!("Because the environment variable {prefix}_GITLAB_URL is present {prefix}_GITLAB_API_ACCESS_TOKEN is also required but it is missing");
                continue;
            };
            configs.insert(prefix.to_string(), GitLabServerConfig {
                gitlab_url,
                gitlab_repo_format,
                gitlab_api_access_token,
            });
        }
    }
    return configs;
}

impl GitLabProjectAccessTokenProvider {
    pub fn try_init() -> Option<Self> {
        let configs = parse_env_vars();
        if configs.is_empty() {
            None
        } else {
            Some(Self {
                configs: configs,
                client: reqwest::Client::new(),
            })
        }
    }

    /// Create a project access token using the GitLab API
    pub async fn create_token(
        &self,
        requester: &AppId,
        provider: &str,
    ) -> Result<SecretResult, String> {
        let Some(config) = self.configs.get(provider) else {
            return Err(format!("A secret sync client requested a project access token for the GitLab provider '{provider}' but it is not configured"));
        };
        let name = requester.as_ref().split('.').nth(1).unwrap();
        let gitlab_repo = config.gitlab_repo_format.replace('#', name);

        // Expire in 1 week
        let expires_at = (chrono::Local::now() + chrono::TimeDelta::weeks(1))
            .format("%Y-%m-%d")
            .to_string();

        let response = self
            .client
            .post(
                config
                    .gitlab_url
                    .join(&format!(
                        "api/v4/projects/{}/access_tokens",
                        urlencoding::encode(&gitlab_repo)
                    ))
                    .map_err(|e| e.to_string())?,
            )
            .header("PRIVATE-TOKEN", &config.gitlab_api_access_token)
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
    pub async fn validate_token(
        &self,
        requester: &AppId,
        provider: &str,
        secret: &str,
    ) -> Result<bool, String> {
        let Some(config) = self.configs.get(provider) else {
            return Err(format!("A secret sync client requested a project access token for the GitLab provider '{provider}' but it is not configured"));
        };
        let name = requester.as_ref().split('.').nth(1).unwrap();
        let gitlab_repo = config.gitlab_repo_format.replace('#', name);

        let response = self
            .client
            .get(
                config
                    .gitlab_url
                    .join(&format!(
                        "{}.git/info/refs?service=git-upload-pack",
                        gitlab_repo
                    ))
                    .map_err(|e| e.to_string())?,
            )
            .basic_auth("secret-sync", Some(secret)) // Any non-empty username works, only the secret matters
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
                CONFIG.beam_id.proxy_id(),
            ),
            ..Default::default()
        })
        .await
        .inspect_err(|e| warn!("Failed to report to icinga: {e}"))
        .ok();
}
