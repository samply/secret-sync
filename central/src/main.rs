use std::{collections::HashSet, fs, time::Duration};

use beam_lib::{reqwest::Client, AppId, BeamClient, BlockingOptions, TaskRequest, TaskResult};
use clap::Parser;
use config::{Config, OIDCProvider};
use gitlab::GitlabTokenProvider;
use icinga_client::IcingaClient;
use once_cell::sync::Lazy;
use shared::{SecretType, SecretRequest, SecretResult};
use tracing::{info, warn};

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
pub static GITLAB_PROJECT_ACCESS_TOKEN_PROVIDER: Lazy<Option<GitlabTokenProvider>> =
    Lazy::new(GitlabTokenProvider::try_init);

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
                warn!(
                    "Failed to connect to beam proxy on {}. Retrying in 30s",
                    CONFIG.beam_url
                );
                tokio::time::sleep(Duration::from_secs(30)).await
            }
            Err(e) => {
                warn!("Error during task polling {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

pub async fn handle_task(task: TaskRequest<Vec<SecretRequest>>) {
    let from = task.from;
    let results =
        futures::future::join_all(task.body.into_iter().map(|t| handle_secret_request(t, &from)))
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
        warn!("Failed to respond to task: {e}")
    }
}

pub async fn handle_secret_request(
    request: SecretRequest,
    from: &AppId,
) -> Result<SecretResult, String> {
    info!("Working on secret request {request:?} from {from}");

    match request.secret_type {
        SecretType::OpenIdConnect(oidc_client_config) => {
            let Some(oidc_provider) = OIDC_PROVIDER.as_ref() else {
                return Err("No OIDC provider configured!".into());
            };
            info!("This OIDCConfig is send: {:#?}", oidc_client_config);
            oidc_provider.handle_secret_request(request.request_type, &oidc_client_config, from).await
        }
        SecretType::GitLabProjectAccessToken(client_config) => {
            let Some(gitlab_token_provider) =
                GITLAB_PROJECT_ACCESS_TOKEN_PROVIDER.as_ref()
            else {
                return Err("No GitLab project access token provider configured!".into());
            };
            gitlab_token_provider
                .handle_secret_request(request.request_type, &client_config, from)
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
