use std::i64;

use anyhow::Context;
use beam_lib::reqwest::{self, Response, StatusCode};
use reqwest::{Client, Url};
use serde_json::{json, Value};
use shared::OIDCConfig;
use tracing::{debug, info};

use crate::auth::config::FlowPropertymapping;

use super::{
    get_uuid,
    provider::{compare_provider, get_provider, get_provider_id, RedirectURIS},
    AuthentikConfig,
};

pub fn generate_app_values(provider: i64, name: &str, oidc_client_config: &OIDCConfig) -> Value {
    let id = format!(
        "{name}-{}",
        if oidc_client_config.is_public {
            "public"
        } else {
            "private"
        }
    );
    json!({
        "name": id,
        "slug": id,
        "provider": provider,
        "group": name
    })
}

pub async fn generate_application(
    provider: i64,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
    token: &str,
    client: &Client,
) -> reqwest::Result<Response> {
    debug!(provider);
    let app_value = generate_app_values(provider, name, oidc_client_config);
    debug!("{:#?}", app_value);
    client
        .post(
            conf.authentik_url
                .join("api/v3/core/applications/")
                .expect("Error parsing app url"),
        )
        .bearer_auth(token)
        .json(&app_value)
        .send()
        .await
}

pub async fn check_app_result(
    token: &str,
    name: &str,
    provider_pk: i64,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
    client: &Client,
) -> anyhow::Result<bool> {
    let res =
        generate_application(provider_pk, name, oidc_client_config, conf, token, client).await?;
    match res.status() {
        StatusCode::CREATED => {
            info!("Application for {name} created.");
            Ok(true)
        }
        StatusCode::BAD_REQUEST => {
            let conflicting_client =
                get_application(name, token, oidc_client_config, conf, client).await?;
            if app_configs_match(
                &conflicting_client,
                &generate_app_values(provider_pk, name, oidc_client_config),
            ) {
                info!("Application {name} exists.");
                Ok(true)
            } else {
                info!("Application for {name} is updated.");
                Ok(client
                    .put(
                        conf.authentik_url.join("api/v3/core/applicaions/")?.join(
                            conflicting_client
                                .get("slug")
                                .and_then(Value::as_str)
                                .expect("No valid client"),
                        )?,
                    )
                    .bearer_auth(token)
                    .json(&generate_app_values(provider_pk, name, oidc_client_config))
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
    name: &str,
    token: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
    client: &Client,
) -> reqwest::Result<serde_json::Value> {
    let id = format!(
        "{name}-{}",
        if oidc_client_config.is_public {
            "public"
        } else {
            "private"
        }
    );
    client
        .get(
            conf.authentik_url
                .join(&format!("api/v3/core/applications/{id}/"))
                .expect("Error parsing app url"),
        )
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await
}

// used only from validate in config
pub async fn compare_app_provider(
    token: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    secret: &str,
    conf: &AuthentikConfig,
    client: &Client,
) -> anyhow::Result<bool> {
    let provider_pk = get_provider_id(name, token, oidc_client_config, conf, client).await;
    match provider_pk {
        Some(pr_id) => {
            let app_res = get_application(name, token, oidc_client_config, conf, client).await?;
            if app_configs_match(
                &app_res,
                &generate_app_values(pr_id, name, oidc_client_config),
            ) {
                return compare_provider(token, name, oidc_client_config, conf, secret, client)
                    .await;
            } else {
                return Ok(false);
            }
        }
        None => Ok(false),
    }
}

pub fn app_configs_match(a: &Value, b: &Value) -> bool {
    a.get("name") == b.get("name")
        && a.get("group") == b.get("group")
        && a.get("provider") == b.get("provider")
}
