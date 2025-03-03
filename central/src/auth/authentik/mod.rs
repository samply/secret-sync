mod app;
mod group;
mod provider;
mod test;

use crate::auth::generate_secret;
use std::{collections::HashMap, sync::Mutex};

use crate::CLIENT;
use anyhow::bail;
use app::{check_app_result, compare_app_provider, get_application};
use beam_lib::reqwest::{self, Url};
use clap::Parser;
use group::create_groups;
use provider::{compare_provider, generate_provider_values, get_provider, get_provider_id};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared::{OIDCConfig, SecretResult};
use tracing::{debug, info};

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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FlowPropertymapping {
    pub authorization_flow: String,
    pub invalidation_flow: String,
    pub property_mapping: HashMap<String, String>,
}
impl FlowPropertymapping {
    async fn new(conf: &AuthentikConfig, token: &str) -> reqwest::Result<Self> {
        static PROPERTY_MAPPING_CACHE: Mutex<Option<FlowPropertymapping>> = Mutex::new(None);
        if let Some(flow) = PROPERTY_MAPPING_CACHE.lock().unwrap().as_ref() {
            return Ok(flow.clone());
        }
        let flow_auth = "default-authorization-flow";
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
        let authorization_flow = get_uuid(&flow_url, token, flow_auth)
            .await
            .expect("No default flow present"); // flow uuid
        let invalidation_flow = get_uuid(&flow_url, token, flow_invalidation)
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
) -> anyhow::Result<bool> {
    let token = get_access_token(conf).await?;
    compare_app_provider(&token, name, oidc_client_config, secret, conf).await
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
    let client_id = format!(
        "{name}-{}",
        if oidc_client_config.is_public {
            "public"
        } else {
            "private"
        }
    );

    let secret = if !oidc_client_config.is_public {
        generate_secret()
    } else {
        String::with_capacity(0)
    };
    let generated_provider =
        generate_provider_values(&client_id, oidc_client_config, &secret, conf, token).await?;
    debug!("Provider Values: {:#?}", generated_provider);
    let provider_res = CLIENT
        .post(conf.authentik_url.join("api/v3/providers/oauth2/")?)
        .bearer_auth(token)
        .json(&generated_provider)
        .send()
        .await?;
    // Create groups for this client
    create_groups(name, token, conf).await?;
    debug!("Result Provider: {:#?}", provider_res);
    match provider_res.status() {
        StatusCode::CREATED => {
            let res_provider: serde_json::Value = provider_res.json().await?;
            let provider_pk = res_provider.get("pk").and_then(|v| v.as_i64()).unwrap();
            let provider_name = res_provider.get("name").and_then(|v| v.as_str()).unwrap();
            debug!("{:?}", provider_pk);
            info!("Provider for {provider_name} created.");
            if check_app_result(token, &client_id, provider_pk, conf).await? {
                Ok(SecretResult::Created(secret))
            } else {
                bail!(
                    "Unexpected Conflict {name} while overwriting authentik app. {:?}",
                    get_application(&client_id, token, conf).await?
                );
            }
        }
        StatusCode::BAD_REQUEST => {
            let conflicting_provider =
                get_provider(&client_id, token, oidc_client_config, conf).await?;
            debug!("{:#?}", conflicting_provider);

            let app = conflicting_provider
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap();
            if compare_provider(token, &client_id, oidc_client_config, conf, &secret).await? {
                info!("Provider {app} existed.");
                if check_app_result(
                    token,
                    &client_id,
                    conflicting_provider
                        .get("pk")
                        .and_then(|v| v.as_i64())
                        .expect("pk id not found"),
                    conf,
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
                        get_application(&client_id, token, conf).await?
                    );
                }
            } else {
                let res = CLIENT
                    .patch(conf.authentik_url.join(&format!(
                        "api/v3/providers/oauth2/{}/",
                        get_provider_id(&client_id, token, conf).await.unwrap()
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
                    &client_id,
                    conflicting_provider["pk"]
                        .as_i64()
                        .expect("app id - pk must be present"),
                    conf,
                )
                .await?
                {
                    Ok(res)
                } else {
                    bail!(
                        "Unexpected Conflict {name} while overwriting authentik app. {:?}",
                        get_application(&client_id, token, conf).await?
                    );
                }
            }
        }
        s => bail!(
            "Unexpected statuscode {s} while creating authentik app and provider. {provider_res:?}"
        ),
    }
}

async fn get_uuid(target_url: &Url, token: &str, search_key: &str) -> Option<String> {
    let target_value: serde_json::Value = CLIENT
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
    Some(target_value["results"][0]["pk"].as_str()?.to_owned())
}

async fn get_property_mappings_uuids(
    target_url: &Url,
    token: &str,
    search_key: Vec<&str>,
) -> HashMap<String, String> {
    // TODO: async iter to collect
    let mut result: HashMap<String, String> = HashMap::new();
    for key in search_key {
        result.insert(
            key.to_string(),
            get_uuid(target_url, token, key)
                .await
                .expect(&format!("Property: {:?}", key)),
        );
    }
    result
}

async fn get_access_token(conf: &AuthentikConfig) -> reqwest::Result<String> {
    #[derive(Deserialize, Serialize, Debug)]
    struct Token {
        access_token: String,
    }
    CLIENT
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
