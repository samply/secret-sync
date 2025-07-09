use beam_lib::reqwest::{self, Response, StatusCode};
use serde_json::{json, Value};
use shared::OIDCConfig;
use std::i64;
use tracing::{debug, info};

use crate::CLIENT;

use super::{client_type, provider::{compare_provider, get_provider_id}, AuthentikConfig};

pub fn generate_app_values(provider: i64, client_id: &str) -> Value {
    json!({
        "name": client_id,
        "slug": client_id,
        "provider": provider,
        "group": client_id.split('-').next().expect("group name does not contain - ")
    })
}

pub async fn generate_app(
    provider: i64,
    client_id: &str,
    conf: &AuthentikConfig,
) -> reqwest::Result<Response> {
    let app_value = generate_app_values(provider, client_id);
    debug!("{:#?}", app_value);
    CLIENT
        .post(
            conf.authentik_url
                .join("api/v3/core/applications/")
                .expect("Error parsing app url"),
        )
        .bearer_auth(&conf.authentik_service_api_key)
        .json(&app_value)
        .send()
        .await
}

pub async fn update_app(
    client_id: &str,
    provider_pk: i64,
    app_name: &str,
    conf: &AuthentikConfig
) -> anyhow::Result<bool> {
    let url = conf.authentik_url.join("api/v3/core/applications/")?
        .join(app_name)?;
    Ok(CLIENT
        .patch(url)
        .bearer_auth(&conf.authentik_service_api_key)
        .json(&generate_app_values(provider_pk, client_id))
        .send()
        .await?
        .status()
        .is_success())
}

pub async fn check_app_result(
    client_id: &str,
    provider_pk: i64,
    conf: &AuthentikConfig
) -> anyhow::Result<bool> {
    let res = generate_app(provider_pk, client_id, conf).await?;
    match res.status() {
        StatusCode::CREATED => {
            info!("Application for {client_id} created.");
            Ok(true)
        }
        StatusCode::BAD_REQUEST => {
            let conflicting_app = get_app(client_id, conf).await?;
            if app_configs_match(
                &conflicting_app,
                &generate_app_values(provider_pk, client_id),
            ) {
                info!("Application {client_id} exists.");
                Ok(true)
            } else {
                info!("Application for {client_id} is updated.");
                update_app(
                    client_id,
                    provider_pk,
                    conflicting_app["name"].as_str().expect("app name has to be present"),
                    conf,
                ).await
            }
        }
        s => anyhow::bail!("Unexpected statuscode {s} while creating authentik client. {res:?}"),
    }
}

pub async fn get_app(
    client_id: &str,
    conf: &AuthentikConfig
) -> reqwest::Result<serde_json::Value> {
    CLIENT
        .get(
            conf.authentik_url
                .join(&format!("api/v3/core/applications/{client_id}/"))
                .expect("Error parsing app url"),
        )
        .bearer_auth(&conf.authentik_service_api_key)
        .send()
        .await?
        .json()
        .await
}

// used only from validate in config
pub async fn compare_app_provider(
    name: &str,
    oidc_client_config: &OIDCConfig,
    secret: &str,
    conf: &AuthentikConfig
) -> anyhow::Result<bool> {
    let client_id = client_type(oidc_client_config, name);
    let provider_pk = get_provider_id(&client_id, conf).await;
    match provider_pk {
        Some(pr_id) => {
            let app_res = get_app(&client_id, conf).await?;
            if app_configs_match(&app_res, &generate_app_values(pr_id, &client_id)) {
                compare_provider(&client_id, oidc_client_config, conf, secret).await
            } else {
                Ok(false)
            }
        }
        None => Ok(false),
    }
}

pub fn app_configs_match(a: &Value, b: &Value) -> bool {
    a.get("name") == b.get("name") && a["group"] == b["group"] && a["provider"] == b["provider"]
}