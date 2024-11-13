use crate::auth::authentik::CLIENT;
use beam_lib::reqwest::{self, Response, StatusCode};
use reqwest::Client;
use serde_json::{json, Value};
use shared::OIDCConfig;

use super::AuthentikConfig;

pub fn generate_app_values(provider: &str, name: &str, oidc_client_config: &OIDCConfig) -> Value {
    let id = format!(
        "{name}-{}",
        if oidc_client_config.is_public {
            "public"
        } else {
            "private"
        }
    );
    // Todo noch anpassen
    json!({
        "name": id,
        "slug": id,
        "provider": provider,
        "group": name
    })
}

pub async fn generate_application(
    provider: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
    token: &str,
    client: &Client,
) -> reqwest::Result<Response> {
    client
        .post(&format!("{}/api/v3/core/applications/", conf.authentik_url))
        .bearer_auth(token)
        .json(&generate_app_values(provider, name, oidc_client_config))
        .send()
        .await
}

pub async fn check_app_result(
    token: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
    client: &Client,
) -> anyhow::Result<bool> {
    let res = generate_application(name, name, oidc_client_config, conf, token, client).await?;
    match res.status() {
        StatusCode::OK => {
            println!("Application for {name} created.");
            return Ok(true);
        }
        StatusCode::CONFLICT => {
            let conflicting_client =
                get_application(name, token, oidc_client_config, conf, client).await?;
            if app_configs_match(
                &conflicting_client,
                &generate_app_values(name, name, oidc_client_config),
            ) {
                Ok(true)
            } else {
                Ok(CLIENT
                    .put(&format!(
                        "{}/api/v3/core/applicaions/{}",
                        conf.authentik_url,
                        conflicting_client
                            .get("slug")
                            .and_then(Value::as_str)
                            .expect("We have a valid client")
                    ))
                    .bearer_auth(token)
                    .json(&generate_app_values(name, name, oidc_client_config))
                    .send()
                    .await?
                    .status()
                    .is_success())
            }
        }
        s => anyhow::bail!("Unexpected statuscode {s} while creating keycloak client. {res:?}"),
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
        .get(&format!(
            "{}/api/v3/core/applications/{id}/",
            conf.authentik_url
        ))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await
}

pub async fn compare_applications(
    token: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
    client: &Client,
) -> anyhow::Result<bool> {
    let client = get_application(name, token, oidc_client_config, conf, client).await?;
    let wanted_client = generate_app_values(name, name, oidc_client_config);
    Ok(
        client.get("client_secret") == wanted_client.get("client_ secret")
            && app_configs_match(&client, &wanted_client),
    )
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

