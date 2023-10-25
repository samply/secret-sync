
use std::{time::Duration, process::ExitCode};

use beam_lib::{AppId, BeamClient, TaskRequest, MsgId, reqwest::{self, StatusCode}, BeamError};
use cache::Cache;
use clap::Parser;
use config::Config;
use once_cell::sync::Lazy;
use shared::{SecretArg, SecretRequestType, SecretResult};

mod config;
mod cache;

pub static CONFIG: Lazy<Config> = Lazy::new(Config::parse);
pub static APP_ID: Lazy<AppId> = Lazy::new(|| AppId::new_unchecked(format!("secret-sync.{}", CONFIG.proxy_id)));
pub static BEAM_PROXY_URL: &str = "http://localhost:8081";

pub static BEAM_CLIENT: Lazy<BeamClient> = Lazy::new(|| {
    BeamClient::new(
        &APP_ID,
        "NotSecret",
        BEAM_PROXY_URL.parse().unwrap(),
    )
});

#[tokio::main]
async fn main() -> ExitCode {
    let mut cache = Cache::open(&CONFIG.cache_path);
    let tasks: Vec<_> = CONFIG.args.iter().map(|SecretArg { name, request }| {
        if let Some(current) = cache.get(name) {
            SecretRequestType::ValidateOrCreate { current: current.clone(), request: request.clone() }
        } else {
            SecretRequestType::Create(request.clone())
        }
    }).collect();
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
    for (result, name) in results.into_iter().zip(CONFIG.args.iter().map(|arg| &arg.name)) {
        match result {
            Ok(SecretResult::AlreadyValid) => {
                println!("{name} was already valid")
            },
            Ok(SecretResult::Created(new_value)) => {
                println!("{name} has been created");
                cache.entry(name.clone()).or_insert(new_value);
            },
            Err(e) => {
                exit_code = ExitCode::FAILURE;
                println!("Failed to validate or create secret for {name}: {e}")
            }
        }
    }
    cache.write(&CONFIG.cache_path).expect("Failed to write secrets to disk");
    exit_code
}

async fn send_secret_request(secret_tasks: Vec<SecretRequestType>) -> beam_lib::Result<Vec<Result<SecretResult, String>>> {
    wait_for_beam_proxy().await?;
    let id = MsgId::new();
    BEAM_CLIENT.post_task(&TaskRequest {
        id,
        from: APP_ID.clone(),
        to: vec![CONFIG.central_beam_id.clone()],
        body: secret_tasks,
        ttl: "60s".to_string(),
        failure_strategy: beam_lib::FailureStrategy::Discard,
        metadata: ().try_into().unwrap(),
    }).await?;

    let results = BEAM_CLIENT
        .poll_results(&id, &beam_lib::BlockingOptions::from_count(1))
        .await?
        .pop()
        .ok_or_else(|| BeamError::Other("Got no result from central site".into()))?
        .body;
    Ok(results)
}

async fn wait_for_beam_proxy() -> beam_lib::Result<()> {
    const MAX_RETRIRES: u8 = 10;
    let mut tries = 1;
    loop {
        match reqwest::get(format!("{BEAM_PROXY_URL}/v1/health")).await {
            Ok(res) if res.status() == StatusCode::OK => return Ok(()),
            _ if tries <= MAX_RETRIRES => tries += 1,
            Err(e) => break Err(e.into()),
            Ok(res) => break Err(beam_lib::BeamError::Other(format!("Proxy reachable but failed to start {}", res.status()).into()))
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
