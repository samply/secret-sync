use std::{collections::HashSet, fs, time::Duration};

use beam_lib::{reqwest::Client, AppId, BeamClient, BlockingOptions, TaskRequest, TaskResult};
use clap::Parser;
use config::{Config, OIDCProvider};
use gitlab::GitLabProjectAccessTokenProvider;
use icinga_client::IcingaClient;
use once_cell::sync::Lazy;
use shared::{SecretRequest, SecretRequestType, SecretResult};
use tracing::warn;

mod auth;
mod gitlab;

pub(crate) mod config;
pub static CONFIG: Lazy<Config> = Lazy::new(Config::parse);

pub static BEAM_CLIENT: Lazy<BeamClient> = Lazy::new(|| {
    BeamClient::new(
        &CONFIG.beam_id,
        &CONFIG.beam_secret,
        CONFIG.beam_url.clone(),
    )
});

pub static OIDC_PROVIDER: Lazy<Option<OIDCProvider>> = Lazy::new(OIDCProvider::try_init);
pub static GITLAB_PROJECT_ACCESS_TOKEN_PROVIDER: Lazy<Option<GitLabProjectAccessTokenProvider>> =
    Lazy::new(GitLabProjectAccessTokenProvider::try_init);

pub static CLIENT: Lazy<Client> = Lazy::new(Client::new);

pub static ICINGA_CLIENT: Lazy<Option<IcingaClient>> = Lazy::new(try_create_icinga_client);

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    // TODO: Remove once beam feature/stream-tasks is merged
    let mut seen = HashSet::new();
    let block_one = BlockingOptions::from_count(1);
    // TODO: Fast shutdown
    loop {
        match BEAM_CLIENT.poll_pending_tasks(&block_one).await {
            Ok(tasks) => tasks.into_iter().for_each(|task| {
                if !seen.contains(&task.id) {
                    seen.insert(task.id);
                    tokio::spawn(handle_task(task));
                }
            }),
            Err(beam_lib::BeamError::ReqwestError(e)) if e.is_connect() => {
                eprintln!(
                    "Failed to connect to beam proxy on {}. Retrying in 30s",
                    CONFIG.beam_url
                );
                tokio::time::sleep(Duration::from_secs(30)).await
            }
            Err(e) => {
                eprintln!("Error during task polling {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

pub async fn handle_task(task: TaskRequest<Vec<SecretRequestType>>) {
    let from = task.from;
    let results =
        futures::future::join_all(task.body.into_iter().map(|t| handle_secret_task(t, &from)))
            .await;
    let result = BEAM_CLIENT
        .put_result(
            &TaskResult {
                from: CONFIG.beam_id.clone(),
                to: vec![from],
                task: task.id,
                status: beam_lib::WorkStatus::Succeeded,
                body: results,
                metadata: ().try_into().unwrap(),
            },
            &task.id,
        )
        .await;

    if let Err(e) = result {
        eprintln!("Failed to respond to task: {e}")
    }
}

pub async fn handle_secret_task(
    task: SecretRequestType,
    from: &AppId,
) -> Result<SecretResult, String> {
    println!("Working on secret task {task:?} from {from}");
    match task {
        SecretRequestType::ValidateOrCreate { current, request }
            if is_valid(&current, &request, from).await? =>
        {
            Ok(SecretResult::AlreadyValid)
        }
        SecretRequestType::ValidateOrCreate { request, .. }
        | SecretRequestType::Create(request) => create_secret(request, from).await,
    }
}

pub async fn create_secret(
    request: SecretRequest,
    requester: &AppId,
) -> Result<SecretResult, String> {
    match request {
        SecretRequest::OpenIdConnect(oidc_client_config) => {
            let Some(oidc_provider) = OIDC_PROVIDER.as_ref() else {
                return Err("No OIDC provider configured!".into());
            };
            let name = requester.as_ref().split('.').nth(1).unwrap();
            oidc_provider.create_client(name, oidc_client_config).await
        }
        SecretRequest::GitLabProjectAccessToken => {
            let Some(gitlab_project_access_token_provider) =
                GITLAB_PROJECT_ACCESS_TOKEN_PROVIDER.as_ref()
            else {
                return Err("No GitLab project access token provider configured!".into());
            };
            gitlab_project_access_token_provider
                .create_token(requester)
                .await
        }
    }
}

pub async fn is_valid(
    secret: &str,
    request: &SecretRequest,
    requester: &AppId,
) -> Result<bool, String> {
    match request {
        SecretRequest::OpenIdConnect(oidc_client_config) => {
            let Some(oidc_provider) = OIDC_PROVIDER.as_ref() else {
                return Err("No OIDC provider configured!".into());
            };
            let name = requester.as_ref().split('.').nth(1).unwrap();
            oidc_provider
                .validate_client(name, secret, oidc_client_config)
                .await
        }
        SecretRequest::GitLabProjectAccessToken => {
            let Some(gitlab_project_access_token_provider) =
                GITLAB_PROJECT_ACCESS_TOKEN_PROVIDER.as_ref()
            else {
                return Err("No GitLab project access token provider configured!".into());
            };
            gitlab_project_access_token_provider
                .validate_token(requester, secret)
                .await
        }
    }
}

fn try_create_icinga_client() -> Option<IcingaClient> {
    let content = match fs::read_to_string(&CONFIG.icinga_config_path) {
        Ok(content) => content,
        Err(err) => {
            warn!("Disabling icinga reporting because reading icinga config failed: {err}");
            return None;
        }
    };
    let icinga_config = match toml::from_str(&content) {
        Ok(icinga_config) => icinga_config,
        Err(err) => {
            warn!("Disabling icinga reporting because parsing icinga config failed: {err}");
            return None;
        }
    };
    match IcingaClient::new(icinga_config) {
        Ok(icinga_client) => Some(icinga_client),
        Err(err) => {
            warn!("Disabling icinga reporting because creating icinga client failed: {err}");
            return None;
        }
    }
}
