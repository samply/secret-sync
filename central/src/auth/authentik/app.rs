use beam_lib::reqwest::{self, Response, StatusCode};
use reqwest::{Client, Url};
use serde_json::{json, Value};
use shared::OIDCConfig;
use std::i64;
use tracing::{debug, info};

use crate::CLIENT;

use super::{
    get_uuid,
    provider::{compare_provider, get_provider, get_provider_id, RedirectURIS},
    AuthentikConfig,
};

pub fn generate_app_values(provider: i64, client_id: &str) -> Value {
    json!({
        "name": client_id,
        "slug": client_id,
        "provider": provider,
        "group": client_id.split('-').next().expect("group name does not contain - ")
    })
}

pub async fn generate_application(
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

pub async fn check_app_result(
    client_id: &str,
    provider_pk: i64,
    conf: &AuthentikConfig,
) -> anyhow::Result<bool> {
    let res = generate_application(provider_pk, client_id, conf).await?;
    match res.status() {
        StatusCode::CREATED => {
            info!("Application for {client_id} created.");
            Ok(true)
        }
        StatusCode::BAD_REQUEST => {
            let conflicting_client = get_application(client_id, conf).await?;
            if app_configs_match(
                &conflicting_client,
                &generate_app_values(provider_pk, client_id),
            ) {
                info!("Application {client_id} exists.");
                Ok(true)
            } else {
                info!("Application for {client_id} is updated.");
                Ok(CLIENT
                    .put(
                        conf.authentik_url.join("api/v3/core/applicaions/")?.join(
                            conflicting_client
                                .get("name")
                                .and_then(Value::as_str)
                                .expect("No valid client"),
                        )?,
                    )
                    .bearer_auth(&conf.authentik_service_api_key)
                    .json(&generate_app_values(provider_pk, client_id))
                    .send()
                    .await?
                    .status()
                    .is_success())
            }
        }
        s => anyhow::bail!("Unexpected statuscode {s} while creating authentik client. {res:?}"),
    }
}

pub async fn get_application(
    client_id: &str,
    conf: &AuthentikConfig,
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
    conf: &AuthentikConfig,
) -> anyhow::Result<bool> {
    let client_id = oidc_client_config.client_type(name);
    let provider_pk = get_provider_id(&client_id, conf).await;
    match provider_pk {
        Some(pr_id) => {
            let app_res = get_application(&client_id, conf).await?;
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
