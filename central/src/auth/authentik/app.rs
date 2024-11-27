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
    provider::{get_provider, get_provider_id},
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
        StatusCode::CONFLICT => {
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
        Some(res) => {
            let app_res = get_application(name, token, oidc_client_config, conf, client).await?;
            let wanted_client =
                generate_all_validation(name, token, conf, oidc_client_config).await?;
            Ok(app_res.get("client_secret").unwrap() == secret
                && app_configs_match(&app_res, &wanted_client))
        }
        None => Ok(false),
    }
}

pub async fn generate_all_validation(
    name: &str,
    token: &str,
    conf: &AuthentikConfig,
    oidc_client_config: &OIDCConfig,
) -> anyhow::Result<Value> {
    let mapping = FlowPropertymapping::new(conf, token).await?;
    let id = format!(
        "{name}-{}",
        if oidc_client_config.is_public {
            "public"
        } else {
            "private"
        }
    );
    let app_json = json!({
    "name": id,
    "slug": id,
    "provider_obj": {
      "name": id,
        "authorization_flow": mapping.authorization_flow,
        "property_mappings": [
            mapping.property_mapping.get("web-origins"),
            mapping.property_mapping.get("acr"),
            mapping.property_mapping.get("profile"),
            mapping.property_mapping.get("roles"),
            mapping.property_mapping.get("email"),
            mapping.property_mapping.get("microprofile-jwt"),
            mapping.property_mapping.get("groups")
        ],
      "assigned_application_slug": id,
      "assigned_application_name": id,
    },
    "launch_url": oidc_client_config.redirect_urls.first().unwrap(),
    "group": name
      });

    Ok(app_json)
}

pub fn app_configs_match(a: &Value, b: &Value) -> bool {
    let includes_other_json_array = |key, comparator: &dyn Fn(_, _) -> bool| {
        a.get(key)
            .and_then(Value::as_array)
            .is_some_and(|a_values| {
                b.get(key)
                    .and_then(Value::as_array)
                    .is_some_and(|vec| vec.iter().all(|v| comparator(a_values, v)))
            })
    };
    a.get("name") == b.get("name")
        && includes_other_json_array("authorization_flow", &|a_v, v| a_v.contains(v))
        && includes_other_json_array("redirectUris", &|a_v, v| a_v.contains(v))
        && includes_other_json_array("property_mappings", &|a_v, v| {
            a_v.iter().any(|a_v| a_v.get("name") == v.get("name"))
        })
}
