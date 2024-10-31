mod test;
mod group;
mod app;
mod provider;

use std::{collections::HashMap, sync::Mutex};

use crate::CLIENT;
use anyhow::bail;
use app::{app_configs_match, check_app_result, compare_applications, generate_app_values, generate_application, get_application};
use beam_lib::reqwest::{self, Url};
use clap::{builder::Str, Parser};
use group::create_groups;
use provider::{generate_provider_values, get_provider, provider_configs_match};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared::{OIDCConfig, SecretResult};

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
        let flow_key = "authorization_flow";
        let property_keys = vec![
            "web-origins",
            "acr",
            "profile",
            "roles",
            "email",
            "microprofile-jwt",
            "groups"
        ];
        let flow_url = "/api/v3/flows/instances/?ordering=slug&page=1&page_size=20&search=";
        let property_url = "/api/v3/propertymappings/all/?managed__isnull=true&ordering=name&page=1&page_size=20&search=";
        let property_mapping = get_property_mappings_uuids(property_url, conf, token, property_keys).await;
        let authorization_flow = get_uuid(flow_url, conf, token, flow_key).await.expect("No default flow present"); // flow uuid
        let mapping = FlowPropertymapping{
            authorization_flow,
            property_mapping
        };
        *PROPERTY_MAPPING_CACHE.lock().unwrap() = Some(mapping.clone());
        Ok(mapping)
    }
}


pub async fn validate_application(
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
) -> anyhow::Result<bool> {
    let token = get_access_token(conf).await?;
    compare_applications(&token, name, oidc_client_config, conf).await
}

pub async fn create_app_provider(
    name: &str,
    oidc_client_config: OIDCConfig,
    conf: &AuthentikConfig,
) -> anyhow::Result<SecretResult> {
    let token = get_access_token(conf).await?;
    combine_app_provider(&token, name, &oidc_client_config, conf).await
}

pub async fn combine_app_provider(
    token: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
) -> anyhow::Result<SecretResult> {
    let secret = if !oidc_client_config.is_public {
        generate_secret()
    } else {
        String::with_capacity(0)
    };
    let generated_provider = generate_provider_values(name, oidc_client_config, &secret, conf, token)
        .await?;
    let provider_res = CLIENT
    .post(&format!(
        "{}/api/v3/providers/oauth2/",
        conf.authentik_url
    ))
    .bearer_auth(token)
    .json(&generated_provider)
    .send()
    .await?;
    // Create groups for this client
    create_groups(name, token, conf).await?;
    match provider_res.status() {
        StatusCode::CREATED => {
            println!("Client for {name} created.");
            check_app_result(token, name, oidc_client_config, conf).await?;
            Ok(SecretResult::Created(secret))
        }
        StatusCode::CONFLICT => {
            let conflicting_provider = get_provider(name, token, oidc_client_config, conf).await?;
            if provider_configs_match(&conflicting_provider, &generated_provider) {
                check_app_result(token, name, oidc_client_config, conf).await?;
                Ok(SecretResult::AlreadyExisted(conflicting_provider
                    .as_object()
                    .and_then(|o| o.get("client_secret"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned()))
            } else {
                Ok(CLIENT
                    .put(&format!(
                        "{}/api/v3/providers/oauth2/{}",
                        conf.authentik_url,
                        conflicting_provider
                            .get("pk")
                            .and_then(Value::as_str)
                            .expect("We have a valid client")
                    ))
                    .bearer_auth(token)
                    .json(&generated_provider)
                    .send()
                    .await?
                    .status()
                    .is_success()
                    .then_some(SecretResult::AlreadyExisted(secret))
                    .expect("We know the provider already exists so updating should be successful"))
            }
        }
        s => bail!("Unexpected statuscode {s} while creating keycloak client. {provider_res:?}"),
    }
}


async fn get_uuid(target_url: &str, conf: &AuthentikConfig, token: &str, search_key: &str) -> Option<String> {
    println!("{:?}", search_key);
    let target_value: serde_json::Value = CLIENT
    .get(&format!(
        "{}{}{}",
        conf.authentik_url,
        target_url,
        search_key
    ))
    .bearer_auth(token)
    .send()
    .await
    .ok()?
    .json()
    .await
    .ok()?;
    // pk is the uuid for this result
            target_value
            .as_object()
            .and_then(|o| {
                 o.get("results")            
                })
            .and_then(Value::as_array)
            .and_then(|a| {
                a.get(0)
            })
            .and_then(|o| o.as_object())
            .and_then(|o| o.get("pk"))
            .and_then(Value::as_str)
            .map(|s| s.to_string())

        }

async fn get_property_mappings_uuids(target_url: &str, conf: &AuthentikConfig, token: &str, search_key: Vec<&str>) -> HashMap<String, String> {
    let mut result: HashMap<String, String> = HashMap::new();
    for key in search_key {
        result.insert(key.to_string(), get_uuid(target_url, conf, token, key).await.expect(&format!("Property: {:?}", key)));
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
    CLIENT
        .post(&format!(
            "{}/application/o/token/",
            conf.authentik_url
        ))
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
