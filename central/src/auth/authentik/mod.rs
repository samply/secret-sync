mod app;
mod group;
mod provider;
#[cfg(test)]
mod test;

use crate::auth::authentik::provider::{
    check_set_federation_id, extract_redirect_obj, generate_provider, get_provider_id,
    update_provider, RedirectURIS,
};
use crate::auth::generate_secret;
use crate::CLIENT;
use anyhow::bail;
use app::{check_app_result, compare_app_provider, get_app};
use beam_lib::reqwest::{self, Url};
use clap::Parser;
use group::create_groups;
use provider::{compare_provider, generate_provider_values, get_provider};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shared::{OIDCConfig, SecretResult};
use std::collections::HashSet;
use std::sync::Mutex;
use tracing::{debug, info};

#[derive(Debug, Parser, Clone)]
pub struct AuthentikConfig {
    /// authentik url
    #[clap(long, env)]
    pub authentik_url: Url,
    // Service Account with api token and all permissions
    #[clap(long, env)]
    pub authentik_service_api_key: String,
    #[clap(long, env, value_parser, value_delimiter = ',', default_values_t = [] as [String; 0])]
    pub authentik_groups_per_bh: Vec<String>,
    #[clap(long, env, value_parser, value_delimiter = ',', default_values_t = [] as [String; 0])]
    pub authentik_property_names: Vec<String>,
    #[clap(long, env, value_parser, value_delimiter = ',', default_values_t = [] as [String; 0])]
    pub authentik_federation_names: Vec<String>,
    #[clap(long, env, default_value = "authentik Self-signed Certificate")]
    pub authentik_crypto_signing_key: String,
    #[clap(long, env, default_value = "Authorize Application")]
    pub authentik_flow_auth: String,
    #[clap(long, env, default_value = "Logged out of application")]
    pub authentik_flow_invalidation: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FlowPropertymapping {
    pub authorization_flow: String,
    pub invalidation_flow: String,
    pub signing_key: String,
    pub property_mapping: Vec<String>,
    pub federation_mapping: Vec<String>,
}
impl FlowPropertymapping {
    async fn new(conf: &AuthentikConfig) -> reqwest::Result<Self> {
        static PROPERTY_MAPPING_CACHE: Mutex<Option<FlowPropertymapping>> = Mutex::new(None);
        if let Some(flow) = PROPERTY_MAPPING_CACHE.lock().unwrap().as_ref() {
            return Ok(flow.clone());
        }
        let flow_auth = &conf.authentik_flow_auth;
        let flow_invalidation = &conf.authentik_flow_invalidation;
        let crypto_signing_key = &conf.authentik_crypto_signing_key;
        let property_keys = &conf.authentik_property_names;
        let jwt_federation_sources = &conf.authentik_federation_names;
        //let flow_url = "/api/v3/flows/instances/?name=...";
        //let property_url = "/api/v3/propertymappings/all/?name=...";
        let flow_url = conf
            .authentik_url
            .join("api/v3/flows/instances/")
            .expect("API endpoint not valid");
        let signing_key_url = conf
            .authentik_url
            .join("api/v3/crypto/certificatekeypairs/")
            .expect("API endpoint not valid");
        let property_url = conf
            .authentik_url
            .join("api/v3/propertymappings/all/")
            .expect("API endpoint not valid");
        let federation_url = conf
            .authentik_url
            .join("api/v3/sources/all/")
            .expect("API endpoint not valid");
        let property_mapping = get_mappings_uuids(&property_url, property_keys, conf).await;
        let federation_mapping =
            get_mappings_uuids(&federation_url, jwt_federation_sources, conf).await;
        let authorization_flow = get_uuid(&flow_url, flow_auth, conf)
            .await
            .expect("No default flow present"); // flow uuid
        let invalidation_flow = get_uuid(&flow_url, flow_invalidation, conf)
            .await
            .expect("No default flow present"); // flow uuid
        let signing_key = get_uuid(&signing_key_url, crypto_signing_key, conf)
            .await
            .expect("No default crypto signing_key"); // crypto signing_key uuid

        let mapping = FlowPropertymapping {
            authorization_flow,
            invalidation_flow,
            signing_key,
            property_mapping,
            federation_mapping,
        };
        *PROPERTY_MAPPING_CACHE.lock().unwrap() = Some(mapping.clone());
        Ok(mapping)
    }
}

pub async fn validate_app(
    name: &str,
    oidc_client_config: &OIDCConfig,
    secret: &str,
    conf: &AuthentikConfig,
) -> anyhow::Result<bool> {
    compare_app_provider(name, oidc_client_config, secret, conf).await
}

pub async fn create_app_provider(
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
) -> anyhow::Result<SecretResult> {
    let client_id = client_type(oidc_client_config, name);
    let secret = if !oidc_client_config.is_public {
        generate_secret()
    } else {
        String::with_capacity(0)
    };
    let generated_provider =
        generate_provider_values(&client_id, oidc_client_config, &secret, conf, None, None).await?;
    debug!("Provider Values: {:#?}", generated_provider);
    let provider_res = generate_provider(&generated_provider, conf).await?;
    // Create groups for this client
    create_groups(name, conf).await?;
    debug!("Result Provider: {:#?}", provider_res);
    match provider_res.status() {
        StatusCode::CREATED => {
            let res_provider: serde_json::Value = provider_res.json().await?;
            let provider_id = res_provider["pk"]
                .as_i64()
                .expect("provider id has to be present");
            let provider_name = res_provider["name"]
                .as_str()
                .expect("provider name has to be present");
            // check and set federation_id
            check_set_federation_id(&name, provider_id, conf, oidc_client_config).await?;
            debug!("{:?}", provider_id);
            info!("Provider for {provider_name} created.");
            if check_app_result(&client_id, provider_id, conf).await? {
                Ok(SecretResult::Created(secret))
            } else {
                bail!(
                    "Unexpected Conflict {name} while overwriting authentik app. {:?}",
                    get_app(&client_id, conf).await?
                );
            }
        }
        StatusCode::BAD_REQUEST => {
            let conflicting_provider = get_provider(&client_id, conf).await?;
            debug!("{:#?}", conflicting_provider);
            let app = conflicting_provider["name"]
                .as_str()
                .expect("app name has to be present");
            if compare_provider(&client_id, name, oidc_client_config, conf, &secret).await? {
                info!("Provider {app} existed.");
                if check_app_result(
                    &client_id,
                    conflicting_provider["pk"]
                        .as_i64()
                        .expect("provider id has to be present"),
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
                        get_app(&client_id, conf).await?
                    );
                }
            } else {
                let current_redirect_uris: Option<HashSet<RedirectURIS>> = conflicting_provider
                    ["redirect_uris"]
                    .as_array()
                    .map(|uris| extract_redirect_obj(&uris));
                let res = update_provider(
                    &generate_provider_values(
                        &client_id,
                        oidc_client_config,
                        &secret,
                        conf,
                        None,
                        current_redirect_uris,
                    )
                    .await?,
                    &client_id,
                    conf,
                )
                .await?
                .status()
                .is_success()
                .then_some(SecretResult::AlreadyExisted(secret))
                .expect("We know the provider already exists so updating should be successful");
                info!("Provider {app} updated");
                if check_app_result(
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
                        get_app(&client_id, conf).await?
                    );
                }
            }
        }
        s => bail!(
            "Unexpected statuscode {s} while creating authentik app and provider. {provider_res:?}"
        ),
    }
}

async fn get_uuid(target_url: &Url, search_name: &str, conf: &AuthentikConfig) -> Option<String> {
    let target_value: serde_json::Value = CLIENT
        .get(target_url.to_owned())
        .query(&[("name", search_name)])
        .bearer_auth(&conf.authentik_service_api_key)
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    debug!("Value search key {search_name}: {:?}", &target_value);
    // pk is the uuid for this result
    Some(target_value["results"][0]["pk"].as_str()?.to_owned())
}

async fn get_mappings_uuids(
    target_url: &Url,
    search_key: &Vec<String>,
    conf: &AuthentikConfig,
) -> Vec<String> {
    // TODO: async iter to collect
    let mut result: Vec<String> = vec![];
    for key in search_key {
        result.push(
            get_uuid(target_url, &key, conf)
                .await
                .expect(&format!("Property: {:?}", key)),
        );
    }
    result
}

pub fn client_type(oidc_config: &OIDCConfig, name: &str) -> String {
    format!(
        "{}-{}",
        name,
        if oidc_config.is_public {
            "public"
        } else {
            "private"
        }
    )
}
//use case federation id
pub fn flipped_client_type(oidc_config: &OIDCConfig, name: &str) -> String {
    format!(
        "{}-{}",
        name,
        if oidc_config.is_public {
            "private"
        } else {
            "public"
        }
    )
}
