mod test;
mod group;
pub mod app;

use std::{collections::HashMap, sync::Mutex};

use crate::CLIENT;
use app::generate_app_values;
use beam_lib::reqwest::{self, Url};
use clap::{builder::Str, Parser};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared::OIDCConfig;

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
        let authorization_flow = get_uuid(flow_url, conf, token, flow_key).await; // flow uuid
        let mapping = FlowPropertymapping{
            authorization_flow,
            property_mapping
        };
        *PROPERTY_MAPPING_CACHE.lock().unwrap() = Some(mapping.clone());
        Ok(mapping)
    }
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

async fn get_application(
    name: &str,
    token: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
) -> reqwest::Result<serde_json::Value> {
    let id = format!("{name}-{}", if oidc_client_config.is_public { "public" } else { "private" });
    CLIENT
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

pub async fn validate_application(
    name: &str,
    oidc_client_config: &OIDCConfig,
    secret: &str,
    conf: &AuthentikConfig,
) -> reqwest::Result<bool> {
    let token = get_access_token(conf).await?;
    compare_applications(&token, name, oidc_client_config, conf, secret).await
}

async fn compare_applications(
    token: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
    secret: &str,
) -> Result<bool, reqwest::Error> {
    let client = get_application(name, token, oidc_client_config, conf).await?;
    let wanted_client = generate_app_values(name, name, oidc_client_config, secret);
    Ok(client.get("secret") == wanted_client.get("secret")
        && app_configs_match(&client, &wanted_client))
}

fn app_configs_match(a: &Value, b: &Value) -> bool {
    let includes_other_json_array = |key, comparator: &dyn Fn(_, _) -> bool| a
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(|a_values| b
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|vec| vec.iter().all(|v| comparator(a_values, v)))
        );
    a.get("name") == b.get("name")
        && includes_other_json_array("authorization_flow", &|a_v, v| a_v.contains(v))
        && includes_other_json_array("redirectUris", &|a_v, v| a_v.contains(v))
        && includes_other_json_array("property_mappings", &|a_v, v| a_v.iter().any(|a_v| a_v.get("name") == v.get("name")))
}

async fn get_uuid(target_url: &str, conf: &AuthentikConfig, token: &str, search_key: &str) -> String {
    println!("{:?}", search_key);
    let target_value: reqwest::Result<serde_json::Value> = CLIENT
    .get(&format!(
        "{}{}{}",
        conf.authentik_url,
        target_url,
        search_key
    ))
    .bearer_auth(token)
    .send()
    .await
    .expect("test faild {search_key}" )
    .json()
    .await
    .into();
    println!("{:?}", target_value);

    // pk is the uuid for this result
            target_value
            .expect("flow or propertymapping type is not present")
            .as_object()
            .and_then(|o| {
                let res= o.get("results");
                println!("{:?}", res);
                res
            })
            .and_then(Value::as_array)
            .and_then(|a| {
                let res = a.get(0);
                println!("{:?}", res);
                res
            })
            .and_then(|o| o.as_object())
            .and_then(|o| o.get("pk"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| "default-pk-value")
            .to_string()
        }

async fn get_property_mappings_uuids(target_url: &str, conf: &AuthentikConfig, token: &str, search_key: Vec<&str>) -> HashMap<String, String> {
    let mut result: HashMap<String, String> = HashMap::new();
    for key in search_key {
        result.insert(key.to_string(), get_uuid(target_url, conf, token, key).await);
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

