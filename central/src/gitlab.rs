use reqwest::Client;
use serde_json::Value;
use clap::Parser;
use once_cell::sync::Lazy;
use reqwest::header::{HeaderMap, HeaderValue};
use chrono::{Utc, Duration};
use shared::SecretResult;
use crate::config::GitlabConfig;

pub static CONFIG: Lazy<GitlabConfig> = Lazy::new(GitlabConfig::parse);
pub static CLIENT: Lazy<Client> = Lazy::new(Client::new);

pub async fn create_gitlab_token(token_name: &str) -> Result<SecretResult, String> {
    match fetch_token_id(&CLIENT, &CONFIG, token_name).await {
        Ok(token_id) => {
            match rotate_token(&CLIENT, &CONFIG, token_id).await {
                Ok(new_token) => Ok(SecretResult::Created(new_token)),
                Err(e) => Err(format!("Failed to rotate token: {}", e)),
            }
        },
        Err(e) => Err(format!("Failed to fetch token ID: {}", e)),
    }
}

async fn fetch_token_id(client: &Client, gitlab_config: &GitlabConfig, token_name: &str) -> Result<u32, String> {
    let url = format!("{}/api/v4/personal_access_tokens?search={}", gitlab_config.gitlab_url, token_name);
    let mut headers = HeaderMap::new();
    headers.insert("PRIVATE-TOKEN", HeaderValue::from_str(&gitlab_config.private_token).unwrap());

    let response = client.get(&url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Value>()
        .await
        .map_err(|e| e.to_string())?;

    if let Some(last_token) = response.as_array().and_then(|arr| arr.last()) {
        if let Some(id) = last_token.get("id").and_then(|id| id.as_u64()) {
            Ok(id as u32)
        } else {
            Err("ID not found in the last token".to_string())
        }
    } else {
        Err("No tokens found".to_string())
    }
}

async fn rotate_token(client: &Client, gitlab_config: &GitlabConfig, token_id: u32) -> Result<String, String> {
    let expires_at = Utc::now() + Duration::days(365);
    let expires_at_str = expires_at.format("%Y-%m-%d").to_string();

    let url = format!("{}/api/v4/personal_access_tokens/{}/rotate?expires_at={}", gitlab_config.gitlab_url, token_id, expires_at_str);

    let mut headers = HeaderMap::new();
    headers.insert("PRIVATE-TOKEN", HeaderValue::from_str(&gitlab_config.private_token).unwrap());

    let response = client.post(&url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if response.status().is_success() {
        let response_json: Value = response.json().await.map_err(|e| e.to_string())?;
        if let Some(token) = response_json["token"].as_str() {
            Ok(token.to_string())
        } else {
            Err("Token not found in the response".to_string())
        }
    } else {
        Err(format!("Failed to rotate token: {}", response.status()))
    }
}