use beam_lib::reqwest::{self, StatusCode, Url};
use reqwest::Client;
use serde_json::json;

use super::AuthentikConfig;

pub async fn create_groups(
    name: &str,
    token: &str,
    conf: &AuthentikConfig,
    CLIENT: &Client,
) -> anyhow::Result<()> {
    let capitalize = |s: &str| {
        let mut chrs = s.chars();
        chrs.next()
            .map(char::to_uppercase)
            .map(Iterator::collect)
            .unwrap_or(String::new())
            + chrs.as_str()
    };
    let name = capitalize(name);
    for group in &conf.authentik_groups_per_bh {
        post_group(&group.replace('#', &name), token, conf).await?;
    }
    Ok(())
}

pub async fn post_group(name: &str, token: &str, conf: &AuthentikConfig) -> anyhow::Result<()> {
    let client = reqwest::Client::new();

    let res = client
        .post(conf.authentik_url.join("api/v3/core/groups/")?)
        .bearer_auth(token)
        .json(&json!({
            "name": name
        }))
        .send()
        .await?;
    match res.status() {
        StatusCode::CREATED => println!("Created group {name}"),
        StatusCode::OK => println!("Created group {name}"),
        StatusCode::BAD_REQUEST => println!("Group {name} already existed"),
        s => anyhow::bail!("Unexpected statuscode {s} while creating group {name}: {:#?}", res.json::<serde_json::Value>().await.unwrap_or_default()),
    }
    Ok(())
}
