use anyhow::{Context, Ok};
use reqwest::{Client, Response, StatusCode, Url};
use serde_json::{json, Value};
use shared::{OIDCConfig, SecretResult};
use tracing::debug;

use crate::auth::config::FlowPropertymapping;

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
        "redirect_uris": oidc_client_config.redirect_urls.first().unwrap(),
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
    client: &Client,
) -> anyhow::Result<Value> {
    let id = format!(
        "{name}-{}",
        if oidc_client_config.is_public {
            "public"
        } else {
            "private"
        }
    );
    //let provider_search = "api/v3/providers/all/?ordering=name&page=1&page_size=20&search=";
    let base_url = conf.authentik_url.join("api/v3/providers/all/").unwrap();
    let query_url = Url::parse_with_params(
        base_url.as_str(),
        &[("ordering", "name"), ("page", "1"), ("page_size", "20")],
    )
    .unwrap();

    let pk = get_uuid(&query_url, token, &id, client)
        .await
        .context(format!("Property: {:?}", id))?;
    let mut base_url = conf
        .authentik_url
        .join("api/v3/providers/oauth2/")
        .context("Error parsing provider")?;
    {
        let mut provider_url = base_url.path_segments_mut().unwrap();
        provider_url.push(&pk);
    }
    client
        .get(base_url)
        .bearer_auth(token)
        .send()
        .await
        .context("No Response")?
        .json()
        .await
        .context("No valid json Response")
}

pub async fn compare_provider(
    token: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
    secret: &str,
    client: &Client,
) -> anyhow::Result<bool> {
    let client = get_provider(name, token, oidc_client_config, conf, client).await?;
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