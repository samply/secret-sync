use crate::auth::authentik::app::get_app_pk;
use crate::CLIENT;
use beam_lib::reqwest::StatusCode;
use serde_json::json;
use tracing::{debug, info};

use super::AuthentikConfig;

pub async fn create_groups(name: &str, conf: &AuthentikConfig) -> anyhow::Result<()> {
    let name = capitalize_name(name);
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

pub async fn group_binding(
    client_id: &str,
    name: &str,
    conf: &AuthentikConfig,
) -> anyhow::Result<()> {
    let name = capitalize_name(name);
    for group in &conf.authentik_groups_per_bh {
        if !check_group_binding(client_id, &group.replace('#', &name), conf).await {
            create_group_binding(client_id, &group.replace('#', &name), conf).await?;    
        }
    }
    if !check_group_binding(client_id, "verbis-all", conf).await {
        create_group_binding(client_id, "verbis-all", conf).await?;
    }
    Ok(())
}

fn capitalize_name(s: &str) -> String {
    let mut chrs = s.chars();
    chrs.next()
        .map(char::to_uppercase)
        .map(Iterator::collect)
        .unwrap_or(String::new())
        + chrs.as_str()
}

pub async fn create_group_binding(
    client_id: &str,
    name: &str,
    conf: &AuthentikConfig,
) -> anyhow::Result<()> {
    let group_id = get_group_id(name, conf)
        .await
        .ok_or_else(|| anyhow::anyhow!("Group {name} not found"))?;
    let app_id = get_app_pk(client_id, conf)
        .await
        .ok_or_else(|| anyhow::anyhow!("Application {client_id} not found"))?;
    let json = json!({
        "group": group_id,
        "target": app_id,
        "order": 0,
        "enable": true
    });
    let res = CLIENT
        .post(conf.authentik_url.join("api/v3/policies/bindings/")?)
        .bearer_auth(&conf.authentik_service_api_key)
        .json(&json)
        .send()
        .await?;
    match res.status() {
        StatusCode::CREATED => info!("Created group binding {name}"),
        s => anyhow::bail!(
            "Unexpected statuscode {s} while creating group binding {name}: {:#?}",
            res.json::<serde_json::Value>().await.unwrap_or_default()
        ),
    }
    Ok(())
}

pub async fn check_group_binding(
    client_id: &str,
    name: &str,
    conf: &AuthentikConfig,
) -> bool {
    let app_id = match get_app_pk(client_id, conf)
        .await {
        Some(app) => app,
        None => return false,
    };
    let query_url = conf
        .authentik_url
        .join("api/v3/policies/bindings/")
        .expect("API Endpoint for policy binding should be present");
    
    let resp = match CLIENT
        .get(query_url)
        .query(&[("target", &app_id)])
        .bearer_auth(&conf.authentik_service_api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return false,
    };
    let target_value: serde_json::Value = match resp.json().await {
        Ok(val) => val,
        Err(_) => return false,
    };
    debug!(
        "Value search key {name} group bindings list: {:?}",
        &target_value
    );
    let results = match target_value["results"].as_array() {
        Some(arr) => arr,
        None => return false,
    };
    let result_names: Vec<String> = results
        .iter()
        .filter_map(|item| item["group_obj"]["name"].as_str().map(|s| s.to_owned()))
        .collect();
    result_names.contains(&name.to_owned())
}

pub async fn get_group_id(name: &str, conf: &AuthentikConfig) -> Option<String> {
    let query_url = conf.authentik_url.join("api/v3/core/groups/").unwrap();
    let target_value: serde_json::Value = CLIENT
        .get(query_url.to_owned())
        .query(&[("name", &name)])
        .bearer_auth(&conf.authentik_service_api_key)
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    debug!("Value search key {name} group: {:?}", &target_value);
    // pk is the id for this result
    Some(target_value["results"][0]["pk"].as_str()?.to_owned())
}
