use crate::CLIENT;
use beam_lib::reqwest::{self, StatusCode, Url};
use serde_json::json;

use super::AuthentikConfig;


pub async fn create_groups(name: &str, token: &str, conf: &AuthentikConfig) -> anyhow::Result<()> {
    let capitalize = |s: &str| {
        let mut chrs = s.chars();
        chrs.next().map(char::to_uppercase).map(Iterator::collect).unwrap_or(String::new()) + chrs.as_str()
    };
    let name = capitalize(name);
    for group in &conf.authentik_groups_per_bh {
        post_group(&group.replace('#', &name), token, conf).await?;
    }
    Ok(())
}

pub async fn post_group(name: &str, token: &str, conf: &AuthentikConfig) -> anyhow::Result<()> {
    let res = CLIENT
        .post(&format!(
            "{}/api/v3/core/groups/",
            conf.authentik_url
        ))
        .bearer_auth(token)
        .json(&json!({
            "name": name
        }))
        .send()
        .await?;
    match res.status() {
        StatusCode::CREATED => println!("Created group {name}"),
        StatusCode::OK => println!("Created group {name}"),
        StatusCode::CONFLICT => println!("Group {name} already existed"),
        s => anyhow::bail!("Unexpected statuscode {s} while creating group {name}")
    }
    Ok(())
}
