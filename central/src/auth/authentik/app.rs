use crate::auth::authentik::CLIENT;
use crate::auth::config::FlowPropertymapping;
use beam_lib::reqwest::{self, Response, StatusCode, Url};
use clap::Parser;
use group::create_groups;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared::{OIDCConfig, SecretResult};

use super::{app_configs_match, generate_secret, get_access_token, get_application, get_property_mappings_uuids, group, AuthentikConfig};

pub async fn create_application(
    name: &str,
    oidc_client_config: OIDCConfig,
    conf: &AuthentikConfig,
) -> reqwest::Result<SecretResult> {
    let token = get_access_token(conf).await?;
    combine_application(&token, name, &oidc_client_config, conf).await
}

pub fn generate_app_values(
    provider: &str, 
    name: &str, 
    oidc_client_config: &OIDCConfig, 
    secret: &str, 
) -> Value 
{
    let secret = (!oidc_client_config.is_public).then_some(secret);
    let id = format!("{name}-{}", if oidc_client_config.is_public { "public" } else { "private" });
// Todo noch anpassen
    let mut json = json!({
        "name": id,
        "slug": id,
        "provider": provider,
        "group": name
    });
    if let Some(secret) = secret {
        json.as_object_mut().unwrap().insert("secret".to_owned(), secret.into());
    }
    json
}

async fn generate_application(
    provider: &str, 
    name: &str, 
    oidc_client_config: &OIDCConfig, 
    secret: &str, 
    conf: &AuthentikConfig, 
    token: &str)
 -> Result<Response, reqwest::Error> 
{
    CLIENT
    .post(&format!(
        "{}/api/v3/core/applications/",
        conf.authentik_url
    ))
    .bearer_auth(token)
    .json(&generate_app_values(provider, name, oidc_client_config, secret))
    .send()
    .await
}

async fn generate_provider(name: &str, oidc_client_config: &OIDCConfig, secret: &str, conf: &AuthentikConfig, token: &str)
-> Result<(), String>
{
    let mapping = FlowPropertymapping::new(conf, token).await.expect("missing flow or property");
    
    let secret = (!oidc_client_config.is_public).then_some(secret);
    let id = format!("{name}-{}", if oidc_client_config.is_public { "public" } else { "private" });
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
        json.as_object_mut().unwrap().insert("client_type".to_owned(), "public".into()); 
    } else {
        json.as_object_mut().unwrap().insert("client_type".to_owned(), "confidential".into());  
    }
    if let Some(secret) = secret {
        json.as_object_mut().unwrap().insert("client_secret".to_owned(), secret.into());
    }
    let res = CLIENT
    .post(&format!(
        "{}/api/v3/providers/oauth2/",
        conf.authentik_url
    ))
    .bearer_auth(token)
    .json(&json)
    .send()
    .await.expect("Authentik not reachable");

    match res.status() {
        StatusCode::CREATED => return Ok(()),
        StatusCode::BAD_REQUEST => return Err(format!("Unexpected statuscode Bad Request while creating authintik provider. {res:?}")),
        s => return Err(format!("Unexpected statuscode {s} while creating authintik provider. {res:?}"))
    }
}

pub async fn combine_application(
    token: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
) -> reqwest::Result<SecretResult> {
    let secret = if !oidc_client_config.is_public {
        generate_secret()
    } else {
        String::with_capacity(0)
    };
    let generated_provider = generate_provider(name, oidc_client_config, &secret, conf, token).await;
    // Todo match if not posible
    // Create groups for this client
    let generated_group = create_groups(name, token, conf).await?;

    let res = generate_application(name, name, oidc_client_config, &secret, conf, token).await?;
    match res.status() {
        StatusCode::OK => {
            println!("Client for {name} created.");
            if !oidc_client_config.is_public {
                let client_id = generate_app_values(name, name, oidc_client_config, &secret)
                    .get("slug")
                    .and_then(Value::as_str)
                    .expect("Always present");
            }
            Ok(SecretResult::Created(secret))
        }
        StatusCode::CONFLICT => {
            let conflicting_client = get_application(name, token, oidc_client_config, conf).await?;
            if app_configs_match(&conflicting_client, &generate_app_values(name, name, oidc_client_config, &secret)) {
                Ok(SecretResult::AlreadyExisted(conflicting_client
                    .as_object()
                    .and_then(|o| o.get("secret"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned()))
            } else {
                Ok(CLIENT
                    .put(&format!(
                        "{}/api/v3/core/applicaions/{}",
                        conf.authentik_url,
                        conflicting_client
                            .get("slug")
                            .and_then(Value::as_str)
                            .expect("We have a valid client")
                    ))
                    .bearer_auth(token)
                    .json(&generate_app_values(name, name, oidc_client_config, &secret))
                    .send()
                    .await?
                    .status()
                    .is_success()
                    .then_some(SecretResult::AlreadyExisted(secret))
                    .expect("We know the client already exists so updating should be successful"))
            }
        }
        s => unreachable!("Unexpected statuscode {s} while creating keycloak client. {res:?}"),
    }
}
