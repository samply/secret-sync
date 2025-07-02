use anyhow::{Context, Ok};
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
) -> anyhow::Result<Value> {
    let mapping = FlowPropertymapping::new(conf).await?;

    let secret = (!oidc_client_config.is_public).then_some(secret);
    let mut json = json!({
        "name": client_id,
        "client_id": client_id,
        "authorization_flow": mapping.authorization_flow,
        "invalidation_flow": mapping.invalidation_flow,
        "sub_mode": "user_email",
        "property_mappings": mapping.property_mapping,
        "jwt_federation_sources": mapping.federation_mapping,
    });

    if !oidc_client_config.redirect_urls.is_empty() {
        let res_urls: Vec<RedirectURIS> = oidc_client_config
            .redirect_urls
            .iter()
            .map(|url| {
                let (matching_mode, url) = if is_regex_uri(url) {
                    ("regex".to_owned(), url.to_owned())
                } else {
                    ("strict".to_owned(), url.to_owned())
                };
                RedirectURIS {
                    matching_mode,
                    url,
                }
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
    conf: &AuthentikConfig
) -> Option<i64> {
    //let provider_search = "api/v3/providers/all/?name=...";
    let query_url = conf.authentik_url.join("api/v3/providers/oauth2/").unwrap();
    let target_value: serde_json::Value = CLIENT
        .get(query_url.to_owned())
        .query(&[("name", &client_id)])
        .bearer_auth(&conf.authentik_service_api_key)
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    debug!("Value search key {client_id} provider: {:?}", &target_value);
    // pk is the id for this result
    Some(target_value["results"][0]["pk"].as_i64()?.to_owned())
}

pub async fn get_provider(
    client_id: &str,
    conf: &AuthentikConfig,
) -> anyhow::Result<Value> {
    let res = get_provider_id(client_id, conf).await;
    let pk = res.ok_or_else(|| anyhow::anyhow!("Failed to get a provider id"))?;
    let base_url = conf
        .authentik_url
        .join(&format!("api/v3/providers/oauth2/{pk}/"))
        .context("Error parsing provider")?;
    CLIENT
        .get(base_url)
        .bearer_auth(&conf.authentik_service_api_key)
        .send()
        .await
        .context("No Response")?
        .json()
        .await
        .context("No valid json Response")
}

pub async fn compare_provider(
    client_id: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
    secret: &str,
) -> anyhow::Result<bool> {
    let client = get_provider(client_id, conf).await?;
    let wanted_client =
        generate_provider_values(client_id, oidc_client_config, secret, conf).await?;
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

pub async fn patch_provider(
    id: i64,
    federation_id: i64,
    conf: &AuthentikConfig
) -> anyhow::Result<()> {
    //"api/v3/providers/oauth2/70/";
    let query_url = conf.authentik_url.join(&format!("api/v3/providers/oauth2/{}/", id))?;
    let json = json!({
        "jwt_federation_providers": [
                federation_id,
            ],
    });
    let target_value: serde_json::Value = CLIENT
        .patch(query_url.to_owned())
        .bearer_auth(&conf.authentik_service_api_key)
        .json(&json)
        .send()
        .await?
        .json()
        .await?;
    debug!("Value search key {id}: set {federation_id}");
    // contains at the moment one id
    match target_value
        ["jwt_federation_providers"][0].as_i64() {
        Some(_jwt_federation_providers) => {
            Ok(())
        },
        None => { anyhow::bail!("No jwt federation_providers found") },
    }
}

pub async fn check_set_federation_id(
    client_name: &str,
    provider_id: i64,
    conf: &AuthentikConfig,
    oidc_client_config: &OIDCConfig,
) -> anyhow::Result<()> {
    if oidc_client_config.is_public {
        // public
        if let Some(private_id) = get_provider_id(
            &oidc_client_config.flipped_client_type(client_name),
            conf
        ).await {
            debug!("public");
            patch_provider(private_id, provider_id, conf).await
        } else {
            debug!("no jet found for '{}' federation_id", client_name);
            Ok(())
        }
    } else {
        // private
        if let Some(public_id) = get_provider_id(
            &oidc_client_config.flipped_client_type(client_name),
            conf
        ).await {
            debug!("private");
            patch_provider(provider_id, public_id, conf).await
        } else {
            debug!("No provider found for '{}' federation_id", client_name);
            Ok(())
        }
    }
}

fn is_regex_uri(uri: &str) -> bool {
    let regex_chars = ['^', '$', '*'];
    uri.chars().any(|c| regex_chars.contains(&c))
}