use beam_lib::reqwest::StatusCode;
use serde_json::json;
use tracing::info;

use crate::CLIENT;

use super::AuthentikConfig;

pub async fn create_groups(name: &str, conf: &AuthentikConfig) -> anyhow::Result<()> {
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
        post_group(&group.replace('#', &name), conf).await?;
    }
    Ok(())
}

pub async fn post_group(name: &str, conf: &AuthentikConfig) -> anyhow::Result<()> {
    let res = CLIENT
        .post(conf.authentik_url.join("api/v3/core/groups/")?)
        .bearer_auth(&conf.authentik_service_api_key)
        .json(&json!({
            "name": name
        }))
        .send()
        .await?;
    match res.status() {
        StatusCode::CREATED => info!("Created group {name}"),
        StatusCode::BAD_REQUEST => info!("Group {name} already existed"),
        s => anyhow::bail!(
            "Unexpected statuscode {s} while creating group {name}: {:#?}",
            res.json::<serde_json::Value>().await.unwrap_or_default()
        ),
    }
    Ok(())
}