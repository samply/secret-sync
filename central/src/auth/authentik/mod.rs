mod app;
mod group;
mod provider;
mod test;

use std::{collections::HashMap, sync::Mutex};

use crate::get_beamclient;
use anyhow::bail;
use app::{app_configs_match, check_app_result, compare_app_provider, get_application};
use beam_lib::reqwest::{self, Url};
use clap::{builder::Str, Parser};
use group::create_groups;
use provider::{
    compare_provider, generate_provider_values, get_provider, get_provider_id,
    provider_configs_match,
};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared::{OIDCConfig, SecretResult};
use tracing::{debug, field::debug, info};

use super::config::FlowPropertymapping;

#[derive(Debug, Parser, Clone)]
pub struct AuthentikConfig {
    /// authentik url
    #[clap(long, env)]
    pub authentik_url: Url,
    #[clap(long, env)]
    pub authentik_id: String,
    #[clap(long, env)]
    pub authentik_secret: String,
    #[clap(long, env, value_parser, value_delimiter = ',', default_values_t = [] as [String; 0])]
    pub authentik_groups_per_bh: Vec<String>,
}

// ctruct is in config
impl FlowPropertymapping {
    async fn new(conf: &AuthentikConfig, token: &str) -> reqwest::Result<Self> {
        static PROPERTY_MAPPING_CACHE: Mutex<Option<FlowPropertymapping>> = Mutex::new(None);
        if let Some(flow) = PROPERTY_MAPPING_CACHE.lock().unwrap().as_ref() {
            return Ok(flow.clone());
        }
        let flow_auth = "authorization_flow";
        let flow_invalidation = "default-provider-invalidation-flow";
        let property_keys = vec![
            "web-origins",
            "acr",
            "profile",
            "roles",
            "email",
            "microprofile-jwt",
            "groups",
        ];
        //let flow_url = "/api/v3/flows/instances/?ordering=slug&page=1&page_size=20&search=";
        let base_url = conf.authentik_url.join("api/v3/flows/instances/").unwrap();
        let flow_url = Url::parse_with_params(
            base_url.as_str(),
            &[("orderung", "slug"), ("page", "1"), ("page_size", "20")],
        )
        .unwrap();

        //let property_url = "/api/v3/propertymappings/all/?managed__isnull=true&ordering=name&page=1&page_size=20&search=";
        let base_url = conf
            .authentik_url
            .join("api/v3/propertymappings/all/")
            .unwrap();
        let query_url = Url::parse_with_params(
            base_url.as_str(),
            &[
                ("managed__isnull", "true"),
                ("ordering", "name"),
                ("page", "1"),
                ("page_size", "20"),
            ],
        )
        .unwrap();

        let property_mapping = get_property_mappings_uuids(&query_url, token, property_keys).await;
        let authorization_flow = get_uuid(&flow_url, token, flow_auth, &get_beamclient())
            .await
            .expect("No default flow present"); // flow uuid
        let invalidation_flow = get_uuid(&flow_url, token, flow_invalidation, &get_beamclient())
            .await
            .expect("No default flow present"); // flow uuid

        let mapping = FlowPropertymapping {
            authorization_flow,
            invalidation_flow,
            property_mapping,
        };
        *PROPERTY_MAPPING_CACHE.lock().unwrap() = Some(mapping.clone());
        Ok(mapping)
    }
}

pub async fn validate_application(
    name: &str,
    oidc_client_config: &OIDCConfig,
    secret: &str,
    conf: &AuthentikConfig,
    client: &Client,
) -> anyhow::Result<bool> {
    let token = get_access_token(conf).await?;
    compare_app_provider(&token, name, oidc_client_config, secret, conf, client).await
}

pub async fn create_app_provider(
    name: &str,
    oidc_client_config: OIDCConfig,
    conf: &AuthentikConfig,
) -> anyhow::Result<SecretResult> {
    let token = get_access_token(conf).await?;
    combine_app_provider(&token, name, &oidc_client_config, conf, &get_beamclient()).await
}

pub async fn combine_app_provider(
    token: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
    client: &Client,
) -> anyhow::Result<SecretResult> {
    let secret = if !oidc_client_config.is_public {
        generate_secret()
    } else {
        String::with_capacity(0)
    };
    let generated_provider =
        generate_provider_values(name, oidc_client_config, &secret, conf, token).await?;
    debug!("Provider Values: {:#?}", generated_provider);
    let provider_res = client
        .post(conf.authentik_url.join("api/v3/providers/oauth2/")?)
        .bearer_auth(token)
        .json(&generated_provider)
        .send()
        .await?;
    // Create groups for this client
    create_groups(name, token, conf, client).await?;
    debug!("Result Provider: {:#?}", provider_res);
    match provider_res.status() {
        StatusCode::CREATED => {
            let res_provider: serde_json::Value = provider_res.json().await?;
            let provider_pk = res_provider.get("pk").and_then(|v| v.as_i64()).unwrap();
            let provider_name = res_provider.get("name").and_then(|v| v.as_str()).unwrap();
            debug!("{:?}", provider_pk);
            info!("Provider for {provider_name} created.");
            if check_app_result(token, name, provider_pk, oidc_client_config, conf, client).await? {
                Ok(SecretResult::Created(secret))
            } else {
                bail!(
                    "Unexpected Conflict {name} while overwriting authentik app. {:?}",
                    get_application(name, token, oidc_client_config, conf, client).await?
                );
            }
        }
        StatusCode::BAD_REQUEST => {
            let conflicting_provider =
                get_provider(name, token, oidc_client_config, conf, client).await?;
            debug!("{:#?}", conflicting_provider);

            let app = conflicting_provider
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap();
            if compare_provider(token, name, oidc_client_config, conf, &secret, client).await? {
                info!("Provider {app} existed.");
                if check_app_result(
                    token,
                    name,
                    conflicting_provider
                        .get("pk")
                        .and_then(|v| v.as_i64())
                        .unwrap(),
                    oidc_client_config,
                    conf,
                    client,
                )
                .await?
                {
                    Ok(SecretResult::AlreadyExisted(
                        conflicting_provider
                            .as_object()
                            .and_then(|o| o.get("client_secret"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned(),
                    ))
                } else {
                    bail!(
                        "Unexpected Conflict {name} while overwriting authentik app. {:?}",
                        get_application(name, token, oidc_client_config, conf, client).await?
                    );
                }
            } else {
                let res = client
                    .patch(conf.authentik_url.join(&format!(
                            "api/v3/providers/oauth2/{}/",
                            get_provider_id(name, token, oidc_client_config, conf, client)
                                .await
                                .unwrap()
                        ))?)
                    .bearer_auth(token)
                    .json(&generated_provider)
                    .send()
                    .await?
                    .status()
                    .is_success()
                    .then_some(SecretResult::AlreadyExisted(secret))
                    .expect("We know the provider already exists so updating should be successful");
                info!("Provider {app} updated");
                if check_app_result(
                    token,
                    name,
                    conflicting_provider
                        .get("pk")
                        .and_then(|v| v.as_i64())
                        .unwrap(),
                    oidc_client_config,
                    conf,
                    client,
                )
                .await?
                {
                    Ok(res)
                } else {
                    bail!(
                        "Unexpected Conflict {name} while overwriting authentik app. {:?}",
                        get_application(name, token, oidc_client_config, conf, client).await?
                    );
                }
            }
        }
        s => bail!(
            "Unexpected statuscode {s} while creating authentik app and provider. {provider_res:?}"
        ),
    }
}

async fn get_uuid(
    target_url: &Url,
    token: &str,
    search_key: &str,
    client: &Client,
) -> Option<String> {
    let target_value: serde_json::Value = client
        .get(target_url.to_owned())
        .query(&[("search", search_key)])
        .bearer_auth(token)
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    debug!("Value search key {search_key}: {:?}", &target_value);
    // pk is the uuid for this result
    target_value
        .as_object()
        .and_then(|o| o.get("results"))
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|o| o.as_object())
        .and_then(|o| o.get("pk"))
        .and_then(Value::as_str)
        .map(|s| s.to_string())
}

async fn get_property_mappings_uuids(
    target_url: &Url,
    token: &str,
    search_key: Vec<&str>,
) -> HashMap<String, String> {
    let mut result: HashMap<String, String> = HashMap::new();
    for key in search_key {
        result.insert(
            key.to_string(),
            get_uuid(target_url, token, key, &get_beamclient())
                .await
                .expect(&format!("Property: {:?}", key)),
        );
    }
    result
}

fn generate_secret() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";
    const PASSWORD_LEN: usize = 30;
    let mut rng = rand::thread_rng();

    (0..PASSWORD_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

async fn get_access_token(conf: &AuthentikConfig) -> reqwest::Result<String> {
    #[derive(Deserialize, Serialize, Debug)]
    struct Token {
        access_token: String,
    }
    get_beamclient()
        .post(
            conf.authentik_url
                .join("application/o/token/")
                .expect("Error parsing token url"),
        )
        .form(&json!({
            "grant_type": "client_credentials",
            "client_id": conf.authentik_id,
            "client_secret": conf.authentik_secret,
            "scope": "openid"
        }))
        .send()
        .await?
        .json::<Token>()
        .await
        .map(|t| t.access_token)
}
