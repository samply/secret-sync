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
            mapping.property_mapping["web-origins"],
            mapping.property_mapping["acr"],
            mapping.property_mapping["profile"],
            mapping.property_mapping["roles"],
            mapping.property_mapping["email"],
            mapping.property_mapping["microprofile-jwt"],
            mapping.property_mapping["groups"]
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

pub async fn get_provider_id(client_id: &str, token: &str, conf: &AuthentikConfig) -> Option<i64> {
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
    Some(target_value["results"][0]["pk"].as_i64()?.to_owned())
}

pub async fn get_provider(
    client_id: &str,
    token: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
) -> anyhow::Result<Value> {
    let res = get_provider_id(client_id, token, conf).await;
    let pk = res.ok_or_else(|| anyhow::anyhow!("Failed to get a provider id"))?;
    let base_url = conf
        .authentik_url
        .join(&format!("api/v3/providers/oauth2/{pk}/"))
        .context("Error parsing provider")?;
    CLIENT
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
        let a_uris = a["redirect_uris"].as_array();
        let b_uris = b["redirect_uris"].as_array();
        match (a_uris, b_uris) {
            (Some(a_uris), Some(b_uris)) => {
                a_uris.iter().all(|auri| b_uris.contains(auri))
                    && b_uris.iter().all(|buri| a_uris.contains(buri))
            }
            (None, None) => true,
            _ => false,
        }
    };
    a["name"] == b["name"]
        && a["client_secret"] == b["client_secret"]
        && a["authorization_flow"] == b["authorization_flow"]
        && a["invalidation_flow"] == b["invalidation_flow"]
        && includes_other_json_array("property_mappings", &|a_v, v| a_v.contains(v))
        && redirct_url_match()
}
