use crate::{auth::keycloak::add_service_account_roles, CLIENT};
use anyhow::bail;
use beam_lib::reqwest::{self, StatusCode, Url};
use clap::Parser;
use serde_json::{json, Value};
use shared::{OIDCConfig, SecretResult};

use super::{create_groups, generate_secret, KeyCloakConfig};

pub async fn get_client(
    name: &str,
    token: &str,
    oidc_client_config: &OIDCConfig,
    conf: &KeyCloakConfig,
) -> reqwest::Result<serde_json::Value> {
    let id = format!(
        "{name}-{}",
        if oidc_client_config.is_public {
            "public"
        } else {
            "private"
        }
    );
    CLIENT
        .get(&format!(
            "{}admin/realms/{}/clients/{id}",
            conf.keycloak_url, conf.keycloak_realm
        ))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await
}

pub async fn compare_clients(
    token: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &KeyCloakConfig,
    secret: &str,
) -> Result<bool, reqwest::Error> {
    let client = get_client(name, token, oidc_client_config, conf).await?;
    let wanted_client = generate_client(name, oidc_client_config, secret);
    Ok(client.get("secret") == wanted_client.get("secret")
        && client_configs_match(&client, &wanted_client))
}

pub fn client_configs_match(a: &Value, b: &Value) -> bool {
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
        && includes_other_json_array("defaultClientScopes", &|a_v, v| a_v.contains(v))
        && includes_other_json_array("redirectUris", &|a_v, v| a_v.contains(v))
        && includes_other_json_array("protocolMappers", &|a_v, v| {
            a_v.iter().any(|a_v| a_v.get("name") == v.get("name"))
        })
}

pub fn generate_client(name: &str, oidc_client_config: &OIDCConfig, secret: &str) -> Value {
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
        "id": id,
        "clientId": id,
        "redirectUris": oidc_client_config.redirect_urls,
        "webOrigins": ["+"], // Will allow all hosts that are named in redirectUris. This is not the same as '*'
        "publicClient": oidc_client_config.is_public,
        "serviceAccountsEnabled": !oidc_client_config.is_public,
        "defaultClientScopes": [
            "web-origins",
            "acr",
            "profile",
            "roles",
            "email",
            "microprofile-jwt",
            "groups"
        ],
        "protocolMappers": [{
            "name": format!("aud-mapper-{name}"),
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "consentRequired": false,
            "config": {
                "included.client.audience": id,
                "id.token.claim": "true",
                "access.token.claim": "true"
            }
        }]
    });
    if let Some(secret) = secret {
        json.as_object_mut()
            .unwrap()
            .insert("secret".to_owned(), secret.into());
    }
    json
}

pub async fn post_client(
    token: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &KeyCloakConfig,
) -> anyhow::Result<SecretResult> {
    let secret = if !oidc_client_config.is_public {
        generate_secret()
    } else {
        String::with_capacity(0)
    };
    let generated_client = generate_client(name, oidc_client_config, &secret);
    let res = CLIENT
        .post(&format!(
            "{}admin/realms/{}/clients",
            conf.keycloak_url, conf.keycloak_realm
        ))
        .bearer_auth(token)
        .json(&generated_client)
        .send()
        .await?;
    // Create groups for this client
    create_groups(name, token, conf).await?;
    match res.status() {
        StatusCode::CREATED => {
            println!("Client for {name} created.");
            if !oidc_client_config.is_public {
                let client_id = generated_client
                    .get("clientId")
                    .and_then(Value::as_str)
                    .expect("Always present");
                add_service_account_roles(token, client_id, conf).await?;
            }
            Ok(SecretResult::Created(secret))
        }
        StatusCode::CONFLICT => {
            let conflicting_client = get_client(name, token, oidc_client_config, conf).await?;
            if client_configs_match(&conflicting_client, &generated_client) {
                Ok(SecretResult::AlreadyExisted(
                    conflicting_client
                        .as_object()
                        .and_then(|o| o.get("secret"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                ))
            } else {
                Ok(CLIENT
                    .put(&format!(
                        "{}admin/realms/{}/clients/{}",
                        conf.keycloak_url,
                        conf.keycloak_realm,
                        conflicting_client
                            .get("clientId")
                            .and_then(Value::as_str)
                            .expect("We have a valid client")
                    ))
                    .bearer_auth(token)
                    .json(&generated_client)
                    .send()
                    .await?
                    .status()
                    .is_success()
                    .then_some(SecretResult::AlreadyExisted(secret))
                    .expect("We know the client already exists so updating should be successful"))
            }
        }
        s => bail!("Unexpected statuscode {s} while creating keycloak client. {res:?}"),
    }
}
