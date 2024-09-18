use std::{collections::HashSet, time::Duration};

use beam_lib::{reqwest::Client, BeamClient, BlockingOptions, TaskRequest, TaskResult, AppId};
use clap::Parser;
use config::{Config, OIDCProvider};
use once_cell::sync::Lazy;
use shared::{SecretRequest, SecretResult, SecretRequestType};

mod config;
mod authentik;
mod keycloak;

pub static CONFIG: Lazy<Config> = Lazy::new(Config::parse);

pub static BEAM_CLIENT: Lazy<BeamClient> = Lazy::new(|| {
    BeamClient::new(
        &CONFIG.beam_id,
        &CONFIG.beam_secret,
        CONFIG.beam_url.clone(),
    )
});

pub static OIDC_PROVIDER: Lazy<Option<OIDCProvider>> = Lazy::new(OIDCProvider::try_init);

pub static CLIENT: Lazy<Client> = Lazy::new(Client::new);

#[tokio::main]
async fn main() {
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
    let results = futures::future::join_all(task.body.into_iter().map(|t| handle_secret_task(t, &from))).await;
    let result = BEAM_CLIENT.put_result(
        &TaskResult {
            from: CONFIG.beam_id.clone(),
            to: vec![from],
            task: task.id,
            status: beam_lib::WorkStatus::Succeeded,
            body: results,
            metadata: ().try_into().unwrap(),
        },
        &task.id
    ).await;

    if let Err(e) = result {
        eprintln!("Failed to respond to task: {e}")
    }
}

pub async fn handle_secret_task(task: SecretRequestType, from: &AppId) -> Result<SecretResult, String> {
    let name = from.as_ref().split('.').nth(1).unwrap();
    println!("Working on secret task {task:?} from {from}");
    match task {
        SecretRequestType::ValidateOrCreate { current, request } if is_valid(&current, &request, name).await? => Ok(SecretResult::AlreadyValid),
        SecretRequestType::ValidateOrCreate { request, .. } |
        SecretRequestType::Create(request) => create_secret(request, name).await,
    }
}

pub async fn create_secret(request: SecretRequest, name: &str) -> Result<SecretResult, String> {
    match request {
        SecretRequest::OpenIdConnect(oidc_client_config) => {
            let Some(oidc_provider) = OIDC_PROVIDER.as_ref() else {
                return Err("No OIDC provider configured!".into());
            };
            oidc_provider.create_client(name, oidc_client_config).await
        }
    }
}

pub async fn is_valid(secret: &str, request: &SecretRequest, name: &str) -> Result<bool, String> {
    match request {
        SecretRequest::OpenIdConnect(oidc_client_config) => {
            let Some(oidc_provider) = OIDC_PROVIDER.as_ref() else {
                return Err("No OIDC provider configured!".into());
            };
            oidc_provider.validate_client(name, secret, oidc_client_config).await
        },
    }
}
