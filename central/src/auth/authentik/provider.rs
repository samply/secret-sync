use anyhow::{Context, Ok};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared::OIDCConfig;
use tracing::debug;

use crate::CLIENT;

use super::{AuthentikConfig, FlowPropertymapping};

#[derive(Debug, Serialize, Deserialize)]
pub struct RedirectURIS {
    pub matching_mode: String,
    pub url: String,
}

pub async fn generate_provider_values(
    client_id: &str,
    oidc_client_config: &OIDCConfig,
    secret: &str,
    conf: &AuthentikConfig,
    token: &str,
) -> anyhow::Result<Value> {
    let mapping = FlowPropertymapping::new(conf, token).await?;

    let secret = (!oidc_client_config.is_public).then_some(secret);
    // only one redirect url is possible
    let mut json = json!({
        "name": client_id,
        "client_id": client_id,
        "authorization_flow": mapping.authorization_flow,
        "invalidation_flow": mapping.invalidation_flow,
        "property_mappings": [
            mapping.property_mapping.get("web-origins"),
            mapping.property_mapping.get("acr"),
            mapping.property_mapping.get("profile"),
            mapping.property_mapping.get("roles"),
            mapping.property_mapping.get("email"),
            mapping.property_mapping.get("microprofile-jwt"),
            mapping.property_mapping.get("groups")
        ]
    });

    if !oidc_client_config.redirect_urls.is_empty() {
        let res_urls: Vec<RedirectURIS> = oidc_client_config
            .redirect_urls
            .iter()
            .map(|url| RedirectURIS {
                matching_mode: "strict".to_owned(),
                url: url.to_owned(),
            })
            .collect();
        json["redirect_uris"] = json!(res_urls);
    }

    json["client_type"] = if oidc_client_config.is_public {
        json!("public")
    } else {
        json!("confidential")
    };
    if let Some(secret) = secret {
        json["client_secret"] = json!(secret);
    }
    Ok(json)
}

pub async fn get_provider_id(
    client_id: &str,
    token: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
) -> Option<i64> {
    //let provider_search = "api/v3/providers/all/?ordering=name&page=1&page_size=20&search=";
    let base_url = conf.authentik_url.join("api/v3/providers/all/").unwrap();
    let query_url = Url::parse_with_params(
        base_url.as_str(),
        &[("ordering", "name"), ("page", "1"), ("page_size", "20")],
    )
    .unwrap();

    let target_value: serde_json::Value = CLIENT
        .get(query_url.to_owned())
        .query(&[("search", &client_id)])
        .bearer_auth(token)
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    debug!("Value search key {client_id}: {:?}", &target_value);
    // pk is the uuid for this result
    target_value
        .as_object()
        .and_then(|o| o.get("results"))
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|o| o.as_object())
        .and_then(|o| o.get("pk"))
        .and_then(|v| v.as_i64())
}

pub async fn get_provider(
    client_id: &str,
    token: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
) -> anyhow::Result<Value> {
    let res = get_provider_id(client_id, token, oidc_client_config, conf).await;
    let pk = res.ok_or_else(|| anyhow::anyhow!("Failed to get a provider id"))?;
    let base_url = conf
        .authentik_url
        .join(&format!("api/v3/providers/oauth2/{pk}/"))
        .context("Error parsing provider")?;
    // TODO: remove debug
    let cli = CLIENT.get(base_url);
    debug!("cli {:?}", cli);

    cli.bearer_auth(token)
        .send()
        .await
        .context("No Response")?
        .json()
        .await
        .context("No valid json Response")
}

pub async fn compare_provider(
    token: &str,
    client_id: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
    secret: &str,
) -> anyhow::Result<bool> {
    let client = get_provider(client_id, token, oidc_client_config, conf).await?;
    let wanted_client =
        generate_provider_values(client_id, oidc_client_config, secret, conf, token).await?;
    debug!("{:#?}", client);
    debug!("{:#?}", wanted_client);
    Ok(provider_configs_match(&client, &wanted_client))
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

    let redirct_url_match = || {
        let a_uris = a.get("redirect_uris").and_then(Value::as_array);
        let b_uris = b.get("redirect_uris").and_then(Value::as_array);
        match (a_uris, b_uris) {
            (Some(a_uris), Some(b_uris)) => {
                a_uris.iter().all(|auri| b_uris.contains(auri))
                    && b_uris.iter().all(|buri| a_uris.contains(buri))
            }
            (None, None) => true,
            _ => false,
        }
    };
    a.get("name") == b.get("name")
        && a.get("client_secret") == b.get("client_secret")
        && a.get("authorization_flow") == b.get("authorization_flow")
        && a.get("invalidation_flow") == b.get("invalidation_flow")
        && includes_other_json_array("property_mappings", &|a_v, v| a_v.contains(v))
        && redirct_url_match()
}
