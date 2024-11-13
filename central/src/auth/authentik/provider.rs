use anyhow::Ok;
use reqwest::{Response, StatusCode};
use serde_json::{json, Value};
use shared::{OIDCConfig, SecretResult};

use crate::{auth::config::FlowPropertymapping, get_beamclient, CLIENT};

use super::{get_uuid, AuthentikConfig};

pub async fn generate_provider_values(
    name: &str,
    oidc_client_config: &OIDCConfig,
    secret: &str,
    conf: &AuthentikConfig,
    token: &str,
) -> anyhow::Result<Value> {
    let mapping = FlowPropertymapping::new(conf, token).await?;

    let secret = (!oidc_client_config.is_public).then_some(secret);
    let id = format!(
        "{name}-{}",
        if oidc_client_config.is_public {
            "public"
        } else {
            "private"
        }
    );
    let mut json = json!({
        "name": id,
        "client_id": id,
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
        "redirect_uris": oidc_client_config.redirect_urls,
    });

    if oidc_client_config.is_public {
        json.as_object_mut()
            .unwrap()
            .insert("client_type".to_owned(), "public".into());
    } else {
        json.as_object_mut()
            .unwrap()
            .insert("client_type".to_owned(), "confidential".into());
    }
    if let Some(secret) = secret {
        json.as_object_mut()
            .unwrap()
            .insert("client_secret".to_owned(), secret.into());
    }
    Ok(json)
}

pub async fn get_provider(
    name: &str,
    token: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
) -> reqwest::Result<serde_json::Value> {
    let id = format!(
        "{name}-{}",
        if oidc_client_config.is_public {
            "public"
        } else {
            "private"
        }
    );
    let provider_url = "/api/v3/providers/all/?ordering=name&page=1&page_size=20&search=";
    let pk = get_uuid(&provider_url, conf, token, &id, &get_beamclient())
        .await
        .expect(&format!("Property: {:?}", id));
    CLIENT
        .get(&format!(
            "{}/api/v3/providers/oauth2/{pk}/",
            conf.authentik_url
        ))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await
}

pub async fn compare_provider(
    token: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
    secret: &str,
) -> anyhow::Result<bool> {
    let client = get_provider(name, token, oidc_client_config, conf).await?;
    let wanted_client =
        generate_provider_values(name, oidc_client_config, secret, conf, token).await?;
    Ok(
        client.get("client_secret") == wanted_client.get("client_secret")
            && provider_configs_match(&client, &wanted_client),
    )
}

pub fn provider_configs_match(a: &Value, b: &Value) -> bool {
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

