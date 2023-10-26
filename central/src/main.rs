use std::{collections::HashSet, time::Duration};

use beam_lib::{reqwest::Client, BeamClient, BlockingOptions, TaskRequest, TaskResult};
use clap::Parser;
use config::Config;
use once_cell::sync::Lazy;
use shared::{SecretRequest, SecretResult, SecretRequestType};

mod config;

pub static CONFIG: Lazy<Config> = Lazy::new(Config::parse);

pub static BEAM_CLIENT: Lazy<BeamClient> = Lazy::new(|| {
    BeamClient::new(
        &CONFIG.beam_id,
        &CONFIG.beam_secret,
        CONFIG.beam_url.clone(),
    )
});

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
                    println!("Generating secrets for {}", task.from);
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
    let results = futures::future::join_all(task.body.into_iter().map(handle_secret_task)).await;
    let result = BEAM_CLIENT.put_result(
        &TaskResult {
            from: CONFIG.beam_id.clone(),
            to: vec![task.from],
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

pub async fn handle_secret_task(task: SecretRequestType) -> Result<SecretResult, String> {
    match task {
        SecretRequestType::ValidateOrCreate { current, request } if is_valid_secret(&current, &request).await? => Ok(SecretResult::AlreadyValid),
        SecretRequestType::ValidateOrCreate { request, .. } |
        SecretRequestType::Create(request) => create_secret(request).await.map(SecretResult::Created),
    }
}

pub async fn create_secret(request: SecretRequest) -> Result<String, String> {
    match request {
        SecretRequest::KeyCloak { args } => {
            let url = CONFIG.keycloak_url.join("/whatever").unwrap();
            // CLIENT.post(url);
            // todo!();
            Ok(args)
        }
    }
}

pub async fn is_valid_secret(current: &str, request: &SecretRequest) -> Result<bool, String> {
    match request {
        SecretRequest::KeyCloak { args } => {
            // todo!("Validate if current was already created")
            Ok(true)
        },
    }
}
