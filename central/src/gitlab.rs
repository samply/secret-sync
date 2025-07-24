use std::collections::HashMap;

use beam_lib::{reqwest::Url, AppId, ProxyId};
use icinga_client::{IcingaProcessResult, IcingaServiceState, IcingaState};
use serde::Deserialize;
use serde_json::json;
use shared::{GitlabClientConfig, RequestType, SecretResult};
use time::format_description::BorrowedFormatItem;
use tracing::warn;

const TOKEN_LIFETIME: time::Duration = time::Duration::days(30);
const MIN_REMAINING_TIME: time::Duration = time::Duration::days(15);

use crate::{CONFIG, ICINGA_CLIENT};

struct GitlabConfig {
    /// The base URL for API calls, e.g. "https://gitlab.com/"
    pub gitlab_url: Url,
    /// Format of the repository name on GitLab. Must contain a "#" which is replaced with the site name. Example: "bridgehead-configurations/bridgehead-config-#"
    pub gitlab_repo_format: String,
    /// A long-living personal (or impersonation) access token that is used to create short-living project access tokens. Requires at least the "api" scope. Note that group access tokens and project access tokens cannot be used to create project access tokens.
    pub gitlab_api_access_token: String,
}

fn build_gitlab_repo_path(template: &str, site: &ProxyId) -> Result<String, String> {
    let site = site.as_ref().split('.').nth(0).unwrap();
    let placeholder_count = template.matches('#').count();
    
    if placeholder_count == 2 {
        // Split app_id on first '-' for two placeholders
        if let Some((before_dash, after_dash)) = site.split_once('-') {
            Ok(template
                .replacen('#', before_dash, 1)
                .replacen('#', after_dash, 1))
        } else {
            Err(format!("Proxy ID '{}' does not contain '-' required for two-placeholder template '{}'", site, template))
        }
    } else {
        Ok(template.replace('#', site))
    }
}

const ISO_DATE_FORMAT: &[BorrowedFormatItem<'_>] =
    time::macros::format_description!("[year]-[month]-[day]");
time::serde::format_description!(iso_date_format, Date, ISO_DATE_FORMAT);

#[derive(Deserialize, Debug)]
struct TokenDetailsResponse {
    id: u32,
    #[serde(with = "iso_date_format")]
    expires_at: time::Date,
}

#[derive(Deserialize)]
struct CreateTokenResponse {
    token: String,
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
            RequestType::ValidateOrCreate(current_token)
                if self
                    .validate(&from.proxy_id(), gitlab_config, &current_token)
                    .await? =>
            {
                Ok(SecretResult::AlreadyValid)
            }
            _ => {
                self.rotate_newest_or_create(&from.proxy_id(), gitlab_config)
                    .await
            }
        }
    }

    async fn list_active_tokens(
        &self,
        site: &ProxyId,
        gitlab_config: &GitlabConfig,
        action: &str,
    ) -> Result<Vec<TokenDetailsResponse>, String> {
        let gitlab_repo = build_gitlab_repo_path(&gitlab_config.gitlab_repo_format, site)?;

        // List active tokens with the name "Secret Sync Token for {site}"
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
                action,
            )
            .await;
            return Err(format!("Failed to list tokens: {err_msg}"));
        }

        response.json().await.map_err(|e| e.to_string())
    }

    async fn validate(
        &self,
        site: &ProxyId,
        gitlab_config: &GitlabConfig,
        current_token: &str,
    ) -> Result<bool, String> {
        let gitlab_repo = build_gitlab_repo_path(&gitlab_config.gitlab_repo_format, site)?;

        // Simulate a git fetch to check if the token is active
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
            return Ok(false);
        }

        // Check if all active tokens are still valid for at least MIN_REMAINING_TIME
        // We don't know which token we have, so we have to check all of them
        if self
            .list_active_tokens(site, gitlab_config, "validate")
            .await?
            .iter()
            .all(|token| token.expires_at - time::UtcDateTime::now().date() >= MIN_REMAINING_TIME)
        {
            report_to_icinga(
                site,
                IcingaServiceState::Ok,
                format!(
                    "Site {site} validated their GitLab token, which is valid for at least {} more days, for {}{}.",
                    MIN_REMAINING_TIME.whole_days(),
                    gitlab_config.gitlab_url,
                    gitlab_repo
                ),
                "validate",
            )
            .await;
            return Ok(true);
        }

        Ok(false)
    }

    async fn rotate_newest_or_create(
        &self,
        site: &ProxyId,
        gitlab_config: &GitlabConfig,
    ) -> Result<SecretResult, String> {
        let gitlab_repo = build_gitlab_repo_path(&gitlab_config.gitlab_repo_format, site)?;

        // Find the token with the latest expiration date
        if let Some(token) = self
            .list_active_tokens(site, gitlab_config, "rotate")
            .await?
            .iter()
            .max_by_key(|token| token.expires_at)
        {
            // Rotate the token
            let response = self
                .client
                .post(
                    gitlab_config
                        .gitlab_url
                        .join(&format!(
                            "api/v4/projects/{}/access_tokens/{}/rotate",
                            urlencoding::encode(&gitlab_repo),
                            token.id
                        ))
                        .map_err(|e| e.to_string())?,
                )
                .header("PRIVATE-TOKEN", &gitlab_config.gitlab_api_access_token)
                .json(&json!({
                    "expires_at": (time::UtcDateTime::now() + TOKEN_LIFETIME).format(ISO_DATE_FORMAT).unwrap(),
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

            report_to_icinga(
                site,
                IcingaServiceState::Ok,
                format!(
                    "Site {site} rotated their GitLab token, which is valid for {} more days, for {}{}.",
                    TOKEN_LIFETIME.whole_days(),
                    gitlab_config.gitlab_url,
                    gitlab_repo
                ),
                "rotate",
            ).await;

            return Ok(SecretResult::AlreadyExisted(response.token));
        }

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
                "scopes": ["read_repository"],
                // Access level 20 (Reporter) is the lowest level that allows git clone/pull
                "access_level": 20,
                "expires_at": (time::UtcDateTime::now() + TOKEN_LIFETIME).format(ISO_DATE_FORMAT).unwrap(),
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
                "Site {site} created a GitLab token, which is valid for {} more days, for {}{}.",
                TOKEN_LIFETIME.whole_days(),
                gitlab_config.gitlab_url,
                gitlab_repo
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
