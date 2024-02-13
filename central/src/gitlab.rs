use serde_json::Value;
use reqwest::header::{HeaderMap, HeaderValue};
use chrono::{Utc, Duration};
use shared::SecretResult;



pub async fn create_gitlab_token(name: &str) -> Result<SecretResult, String> {
    let private_token = "PRIVATE_TOKEN"; //TODO

    match fetch_token_id(name, private_token).await {
        Ok(token_id) => {
            match rotate_token(private_token, token_id).await {
                Ok(new_token) => Ok(SecretResult::Created(new_token)),
                Err(e) => Err(format!("Failed to rotate token: {}", e)),
            }
        },
        Err(e) => Err(format!("Failed to fetch token ID: {}", e)),
    }
}

async fn fetch_token_id(search_param: &str, private_token: &str) -> Result<u32, String> {
    let client = reqwest::Client::new();
    let url = format!("https://git.verbis.dkfz.de/api/v4/personal_access_tokens?search={}", search_param);
    let mut headers = HeaderMap::new();
    headers.insert("PRIVATE-TOKEN", HeaderValue::from_str(private_token).unwrap());

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

async fn rotate_token(private_token: &str, token_id: u32) -> Result<String, String> {
    let client = reqwest::Client::new();

    let expires_at = Utc::now() + Duration::days(365);
    let expires_at_str = expires_at.format("%Y-%m-%d").to_string();

    let url = format!("https://git.verbis.dkfz.de/api/v4/personal_access_tokens/{}/rotate?expires_at={}", token_id, expires_at_str);

    let mut headers = HeaderMap::new();
    headers.insert("PRIVATE-TOKEN", HeaderValue::from_str(private_token).unwrap());

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