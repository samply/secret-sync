use std::collections::HashMap;

use beam_lib::{reqwest::Url, AppId, ProxyId};
use icinga_client::{IcingaProcessResult, IcingaServiceState, IcingaState};
use serde::Deserialize;
use serde_json::json;
use shared::{GitlabClientConfig, RequestType, SecretResult};
use tracing::warn;

const TOKEN_LIFETIME: chrono::Duration = chrono::Duration::days(30);
const MIN_REMAINING_TIME: chrono::Duration = chrono::Duration::days(15);

use crate::{CONFIG, ICINGA_CLIENT};

struct GitlabConfig {
    /// The base URL for API calls, e.g. "https://gitlab.com/"
    pub gitlab_url: Url,
    /// Format of the repository name on GitLab. Must contain a "#" which is replaced with the site name. Example: "bridgehead-configurations/bridgehead-config-#"
    pub gitlab_repo_format: String,
    /// A long-living personal (or impersonation) access token that is used to create short-living project access tokens. Requires at least the "api" scope. Note that group access tokens and project access tokens cannot be used to create project access tokens.
    pub gitlab_api_access_token: String,
}

#[derive(Deserialize)]
struct CreateTokenResponse {
    token: String,
}

#[derive(Deserialize, Debug)]
struct TokenDetailsResponse {
    expires_at: String,
}

pub struct GitlabTokenProvider {
    gitlab_configs: HashMap<String, GitlabConfig>,
    client: reqwest::Client,
}

fn parse_env_vars() -> HashMap<String, GitlabConfig> {
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
            let Some(gitlab_repo_format) = env_vars
                .get(&format!("{prefix}_GITLAB_REPO_FORMAT"))
                .cloned()
            else {
                warn!("Because the environment variable {prefix}_GITLAB_URL is present {prefix}_GITLAB_REPO_FORMAT is also required but it is missing");
                continue;
            };
            let Some(gitlab_api_access_token) = env_vars
                .get(&format!("{prefix}_GITLAB_API_ACCESS_TOKEN"))
                .cloned()
            else {
                warn!("Because the environment variable {prefix}_GITLAB_URL is present {prefix}_GITLAB_API_ACCESS_TOKEN is also required but it is missing");
                continue;
            };
            configs.insert(
                prefix.to_string(),
                GitlabConfig {
                    gitlab_url,
                    gitlab_repo_format,
                    gitlab_api_access_token,
                },
            );
        }
    }
    return configs;
}

impl GitlabTokenProvider {
    pub fn try_init() -> Option<Self> {
        let configs = parse_env_vars();
        if configs.is_empty() {
            None
        } else {
            Some(Self {
                gitlab_configs: configs,
                client: reqwest::Client::new(),
            })
        }
    }

    pub async fn handle_secret_request(
        &self,
        request_type: RequestType,
        client_config: &GitlabClientConfig,
        from: &AppId,
    ) -> Result<SecretResult, String> {
        let Some(gitlab_config) = self.gitlab_configs.get(&client_config.gitlab_instance) else {
            return Err(format!(
                "GitLab server '{}' is not configured",
                client_config.gitlab_instance
            ));
        };

        match request_type {
            RequestType::ValidateOrCreate(current_token) => {
                self.validate_or_create_workaround(&from.proxy_id(), gitlab_config, &current_token)
                    .await
            }
            RequestType::Create => self.create(&from.proxy_id(), gitlab_config).await,
        }
    }

    // Workaround for https://gitlab.com/gitlab-org/gitlab/-/issues/523871
    // If they ever fix this, we can remove this function and use the validate_or_create function
    async fn validate_or_create_workaround(
        &self,
        site: &ProxyId,
        gitlab_config: &GitlabConfig,
        current_token: &str,
    ) -> Result<SecretResult, String> {
        let gitlab_repo = gitlab_config
            .gitlab_repo_format
            .replace('#', site.as_ref().split('.').nth(0).unwrap());

        // Simulate a git fetch to check if the token is valid
        let response = self
            .client
            .get(
                gitlab_config
                    .gitlab_url
                    .join(&format!(
                        "{}.git/info/refs?service=git-upload-pack",
                        gitlab_repo
                    ))
                    .map_err(|e| e.to_string())?,
            )
            .basic_auth("Secret Sync", Some(current_token))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            // If the token does not work, create a new one
            return self.create(site, gitlab_config).await;
        }

        // List all active tokens with the name "Secret Sync Token for {site}"
        let response = self
            .client
            .get(
                gitlab_config
                    .gitlab_url
                    .join(&format!(
                        "api/v4/projects/{}/access_tokens?state=active&search={}",
                        urlencoding::encode(&gitlab_repo),
                        urlencoding::encode(&format!("Secret Sync Token for {site}"))
                    ))
                    .map_err(|e| e.to_string())?,
            )
            .header("PRIVATE-TOKEN", &gitlab_config.gitlab_api_access_token)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            let err_msg = format!(
                "HTTP status error {} for url {} with body {}",
                response.status(),
                response.url().clone(),
                response.text().await.map_err(|e| e.to_string())?
            );
            report_to_icinga(
                site,
                IcingaServiceState::Warning,
                format!("Failed to list tokens: {err_msg}"),
                "validate",
            )
            .await;
            return Err(format!("Failed to list tokens: {err_msg}"));
        }

        let response: Vec<TokenDetailsResponse> =
            response.json().await.map_err(|e| e.to_string())?;

        // Check if all active tokens are still valid for at least MIN_REMAINING_TIME
        if response.iter().all(|token| {
            let expires_at = chrono::NaiveDate::parse_from_str(&token.expires_at, "%Y-%m-%d")
                .map_err(|e| e.to_string())
                .unwrap();
            expires_at - chrono::Local::now().date_naive() >= MIN_REMAINING_TIME
        }) {
            report_to_icinga(
                site,
                IcingaServiceState::Ok,
                format!(
                    "Site {site} validated their GitLab token for {}{}. The token is valid for at least {} more days.",
                    gitlab_config.gitlab_url,
                    gitlab_repo,
                    MIN_REMAINING_TIME.num_days()
                ),
                "validate",
            )
            .await;
            return Ok(SecretResult::AlreadyValid);
        }

        // Rotate the token
        let response = self
            .client
            .post(
                gitlab_config
                    .gitlab_url
                    .join(&format!(
                        "api/v4/projects/{}/access_tokens/self/rotate",
                        urlencoding::encode(&gitlab_repo)
                    ))
                    .map_err(|e| e.to_string())?,
            )
            .header("PRIVATE-TOKEN", current_token)
            .json(&json!({
                "expires_at": (chrono::Local::now() + TOKEN_LIFETIME).format("%Y-%m-%d").to_string(),
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            // When token rotation was implemented, existing tokens were still missing the "self_rotate" scope
            // meaning that token rotation was not possible. Thus we need to create a new token instead.
            return self.create(site, gitlab_config).await;

            // In the future, we can remove the call to create() and uncomment this code to report the error to Icinga

            // let err_msg = format!(
            //     "HTTP status error {} for url {} with body {}",
            //     response.status(),
            //     response.url().clone(),
            //     response.text().await.map_err(|e| e.to_string())?
            // );
            // report_to_icinga(
            //     site,
            //     IcingaServiceState::Warning,
            //     format!("Failed to rotate the token: {err_msg}"),
            //     "rotate",
            // )
            // .await;
            // return Err(format!("Failed to rotate the token: {err_msg}"));
        }

        let response: CreateTokenResponse = response.json().await.map_err(|e| e.to_string())?;
        Ok(SecretResult::AlreadyExisted(response.token))
    }

    // When GitLab fixes https://gitlab.com/gitlab-org/gitlab/-/issues/523871, we can use this function instead of the workaround
    #[allow(dead_code)]
    async fn validate_or_create(
        &self,
        site: &ProxyId,
        gitlab_config: &GitlabConfig,
        current_token: &str,
    ) -> Result<SecretResult, String> {
        let gitlab_repo = gitlab_config
            .gitlab_repo_format
            .replace('#', site.as_ref().split('.').nth(0).unwrap());

        // Check when the token will expire
        let response = self
            .client
            .get(
                gitlab_config
                    .gitlab_url
                    .join(&format!(
                        "api/v4/projects/{}/access_tokens/self",
                        urlencoding::encode(&gitlab_repo)
                    ))
                    .map_err(|e| e.to_string())?,
            )
            .header("PRIVATE-TOKEN", current_token)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            // This means the token is invalid or expired, so we need to create a new one
            return self.create(site, gitlab_config).await;
        }

        // Check if the token is still valid for at least MIN_REMAINING_TIME
        let response: TokenDetailsResponse = response.json().await.map_err(|e| e.to_string())?;
        let expires_at = chrono::NaiveDate::parse_from_str(&response.expires_at, "%Y-%m-%d")
            .map_err(|e| e.to_string())?;
        if expires_at - chrono::Local::now().date_naive() >= MIN_REMAINING_TIME {
            report_to_icinga(
                site,
                IcingaServiceState::Ok,
                format!(
                    "Site {site} validated their GitLab token for {}{}. The token is valid for {} more days.",
                    gitlab_config.gitlab_url,
                    gitlab_repo,
                    (expires_at - chrono::Local::now().date_naive()).num_days()
                ),
                "validate",
            )
            .await;
            return Ok(SecretResult::AlreadyValid);
        }

        // Rotate the token
        let response = self
            .client
            .post(
                gitlab_config
                    .gitlab_url
                    .join(&format!(
                        "api/v4/projects/{}/access_tokens/self/rotate",
                        urlencoding::encode(&gitlab_repo)
                    ))
                    .map_err(|e| e.to_string())?,
            )
            .header("PRIVATE-TOKEN", current_token)
            .json(&json!({
                "expires_at": (chrono::Local::now() + TOKEN_LIFETIME).format("%Y-%m-%d").to_string(),
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            let err_msg = format!(
                "HTTP status error {} for url {} with body {}",
                response.status(),
                response.url().clone(),
                response.text().await.map_err(|e| e.to_string())?
            );
            report_to_icinga(
                site,
                IcingaServiceState::Warning,
                format!("Failed to rotate the token: {err_msg}"),
                "rotate",
            )
            .await;
            return Err(format!("Failed to rotate the token: {err_msg}"));
        }

        let response: CreateTokenResponse = response.json().await.map_err(|e| e.to_string())?;
        Ok(SecretResult::AlreadyExisted(response.token))
    }

    async fn create(
        &self,
        site: &ProxyId,
        gitlab_config: &GitlabConfig,
    ) -> Result<SecretResult, String> {
        let gitlab_repo = gitlab_config
            .gitlab_repo_format
            .replace('#', site.as_ref().split('.').nth(0).unwrap());

        // Create a new token
        let response = self
            .client
            .post(
                gitlab_config
                    .gitlab_url
                    .join(&format!(
                        "api/v4/projects/{}/access_tokens",
                        urlencoding::encode(&gitlab_repo)
                    ))
                    .map_err(|e| e.to_string())?,
            )
            .header("PRIVATE-TOKEN", &gitlab_config.gitlab_api_access_token)
            .json(&json!({
                "name": format!("Secret Sync Token for {site}"),
                // The "read_repository" scope is required for git clone/pull permissions
                "scopes": ["read_repository", "self_rotate"],
                // Access level 20 (Reporter) is the lowest level that allows git clone/pull
                "access_level": 20,
                "expires_at": (chrono::Local::now() + TOKEN_LIFETIME).format("%Y-%m-%d").to_string(),
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            let err_msg = format!(
                "HTTP status error {} for url {} with body {}",
                response.status(),
                response.url().clone(),
                response.text().await.map_err(|e| e.to_string())?
            );
            report_to_icinga(
                site,
                IcingaServiceState::Warning,
                format!("Failed to create the token: {err_msg}"),
                "rotate",
            )
            .await;
            return Err(format!("Failed to create the token: {err_msg}"));
        }

        let response: CreateTokenResponse = response.json().await.map_err(|e| e.to_string())?;
        report_to_icinga(
            site,
            IcingaServiceState::Ok,
            format!(
                "Site {site} created a GitLab token for {}{}. The token is valid for {} more days.",
                gitlab_config.gitlab_url,
                gitlab_repo,
                TOKEN_LIFETIME.num_days()
            ),
            "rotate",
        )
        .await;
        Ok(SecretResult::Created(response.token))
    }
}

pub async fn report_to_icinga(
    site: &ProxyId,
    state: IcingaServiceState,
    message: String,
    action: &str,
) {
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
                site, action,
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
