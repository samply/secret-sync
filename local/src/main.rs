use std::{ops::Deref, process::ExitCode, time::Duration};

use beam_lib::{
    reqwest::{self, StatusCode},
    AppId, BeamClient, BeamError, BlockingOptions, MsgId, TaskRequest,
};
use cache::Cache;
use clap::Parser;
use config::{Config, SecretArg};
use futures::TryFutureExt;
use once_cell::sync::Lazy;
use shared::{SecretRequest, SecretRequestType, SecretResult};

mod cache;
mod config;

pub static CONFIG: Lazy<Config> = Lazy::new(Config::parse);
pub static APP_ID: Lazy<AppId> =
    Lazy::new(|| AppId::new_unchecked(format!("secret-sync.{}", CONFIG.proxy_id)));
pub static BEAM_PROXY_URL: &str = "http://localhost:8081";

pub static BEAM_CLIENT: Lazy<BeamClient> =
    Lazy::new(|| BeamClient::new(&APP_ID, "NotSecret", BEAM_PROXY_URL.parse().unwrap()));

#[tokio::main]
async fn main() -> ExitCode {
    let mut cache = Cache::open(&CONFIG.cache_path);
    let tasks: Vec<_> = CONFIG
        .secret_definitions
        .0
        .iter()
        .map(|SecretArg { name, request }| {
            if let Some(current) = cache.get(name) {
                SecretRequestType::ValidateOrCreate {
                    current: current.clone(),
                    request: request.clone(),
                }
            } else {
                SecretRequestType::Create(request.clone())
            }
        })
        .collect();
    if tasks.is_empty() {
        println!("No secrets to generate");
        return ExitCode::SUCCESS;
    } else {
        println!("Generating {} secrets", tasks.len());
    }
    let results = match send_secret_request(tasks).await {
        Ok(results) => results,
        Err(e) => {
            eprintln!("Failed to send secret sync task: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut exit_code = ExitCode::SUCCESS;
    for (result, name) in results
        .into_iter()
        .zip(CONFIG.secret_definitions.0.iter().map(|arg| &arg.name))
    {
        match result {
            Ok(SecretResult::AlreadyValid) => {
                println!("{name} was cached correctly.")
            }
            Ok(SecretResult::Created(secret)) => {
                cache.entry(name.to_string())
                    .and_modify(|v| {
                        println!("{name} was cached locally but did not exist centrally so it was created.");
                        *v = secret.clone()
                    }).or_insert_with(|| {
                        println!("{name} has been created.");
                        secret
                    });
            },
            Ok(SecretResult::AlreadyExisted(secret)) => {
                cache.entry(name.to_string())
                    .and_modify(|v| {
                        println!("{name} was cached but needed to be updated.");
                        *v = secret.clone()
                    }).or_insert_with(|| {
                        println!("{name} already existed but was not cached.");
                        secret
                    });
            }
            Err(e) => {
                exit_code = ExitCode::FAILURE;
                println!("Failed to validate or create secret for {name}: {e}")
            }
        }
    }
    cache
        .write(&CONFIG.cache_path)
        .expect("Failed to write secrets to disk");
    exit_code
}

async fn send_secret_request(
    mut secret_tasks: Vec<SecretRequestType>,
) -> beam_lib::Result<Vec<Result<SecretResult, String>>> {
    wait_for_beam_proxy().await?;
    let mut tasks = Vec::with_capacity(secret_tasks.len());
    // Partition tasks based on task type to send them to the correct app to fulfill the task
    let (oidc, rest) = secret_tasks
        .into_iter()
        .partition(|v| matches!(v.deref(), SecretRequest::OpenIdConnect { .. }));
    secret_tasks = rest;
    if !oidc.is_empty() {
        if let Some(oidc_provider) = &CONFIG.oidc_provider {
            tasks.push(TaskRequest {
                id: MsgId::new(),
                from: APP_ID.clone(),
                to: vec![oidc_provider.clone()],
                body: oidc,
                ttl: "60s".to_string(),
                failure_strategy: beam_lib::FailureStrategy::Discard,
                metadata: ().try_into().unwrap(),
            });
        } else {
            return Err(beam_lib::BeamError::Other("Got OIDC connect tasks but no OIDC provider was configurad".into()));
        }
    }
    assert_eq!(
        secret_tasks.len(),
        0,
        "All secret tasks should be partitioned into their beam tasks"
    );
    futures::future::try_join_all(tasks.into_iter().map(|t| async move {
        BEAM_CLIENT.post_task(&t).await?;
        BEAM_CLIENT.poll_results::<Vec<Result<SecretResult, String>>>(&t.id, &BlockingOptions::from_count(1))
            .await?
            .pop()
            .map(|res| res.body)
            .ok_or(BeamError::Other(
                "Got no result from secret provider".into(),
            ))
        })
    ).map_ok(|v| v.into_iter().flatten().collect()).await
}

async fn wait_for_beam_proxy() -> beam_lib::Result<()> {
    const MAX_RETRIRES: u8 = 10;
    let mut tries = 1;
    loop {
        match reqwest::get(format!("{BEAM_PROXY_URL}/v1/health")).await {
            Ok(res) if res.status() == StatusCode::OK => return Ok(()),
            _ if tries <= MAX_RETRIRES => tries += 1,
            Err(e) => return Err(e.into()),
            Ok(res) => {
                return Err(beam_lib::BeamError::Other(
                    format!("Proxy reachable but failed to start {}", res.status()).into(),
                ))
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
