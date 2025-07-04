mod client;

mod test;

use crate::CLIENT;
use anyhow::bail;
use beam_lib::reqwest::{self, StatusCode, Url};
use clap::Parser;
use client::{compare_clients, post_client};
use serde_json::json;
use shared::{OIDCConfig, SecretResult};

#[derive(Debug, Parser, Clone)]
pub struct KeyCloakConfig {
    /// Keycloak url
    #[clap(long, env)]
    pub keycloak_url: Url,
    /// Keycloak client id
    #[clap(long, env)]
    pub keycloak_id: String,
    /// Keycloak client secret
    #[clap(long, env)]
    pub keycloak_secret: String,
    /// Keycloak realm
    #[clap(long, env, default_value = "master")]
    pub keycloak_realm: String,
    /// Keycloak service account roles that should be added to the private keycloak clints
    #[clap(long, env, value_parser, value_delimiter = ',', default_values_t = [] as [String; 0])]
    pub keycloak_service_account_roles: Vec<String>,
    /// Keycloak groups that get auto generated per bridgehead. Must include a '#' which will be replaced by the SITE_ID of the bridgehead
    #[clap(long, env, value_parser, value_delimiter = ',', default_values_t = [] as [String; 0])]
    pub keycloak_groups_per_bh: Vec<String>,
}

pub async fn create_client(
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &KeyCloakConfig,
) -> anyhow::Result<SecretResult> {
    let token = get_access_token(conf).await?;
    post_client(&token, name, &oidc_client_config, conf).await
}

pub async fn validate_client(
    name: &str,
    oidc_client_config: &OIDCConfig,
    secret: &str,
    conf: &KeyCloakConfig,
) -> reqwest::Result<bool> {
    let token = get_access_token(conf).await?;
    compare_clients(&token, name, oidc_client_config, conf, secret).await
}

async fn get_access_token(conf: &KeyCloakConfig) -> reqwest::Result<String> {
    #[derive(serde::Deserialize)]
    struct Token {
        access_token: String,
    }
    CLIENT
        .post(&format!(
            "{}realms/{}/protocol/openid-connect/token",
            conf.keycloak_url, conf.keycloak_realm
        ))
        .form(&json!({
            "client_id": conf.keycloak_id,
            "client_secret":  conf.keycloak_secret,
            "grant_type": "client_credentials"
        }))
        .send()
        .await?
        .json::<Token>()
        .await
        .map(|t| t.access_token)
}

async fn create_groups(name: &str, token: &str, conf: &KeyCloakConfig) -> anyhow::Result<()> {
    let capitalize = |s: &str| {
        let mut chrs = s.chars();
        chrs.next()
            .map(char::to_uppercase)
            .map(Iterator::collect)
            .unwrap_or(String::new())
            + chrs.as_str()
    };
    let name = capitalize(name);
    for group in &conf.keycloak_groups_per_bh {
        post_group(&group.replace('#', &name), token, conf).await?;
    }
    Ok(())
}

async fn post_group(name: &str, token: &str, conf: &KeyCloakConfig) -> anyhow::Result<()> {
    let res = CLIENT
        .post(&format!(
            "{}admin/realms/{}/groups",
            conf.keycloak_url, conf.keycloak_realm
        ))
        .bearer_auth(token)
        .json(&json!({
            "name": name
        }))
        .send()
        .await?;
    match res.status() {
        StatusCode::CREATED => println!("Created group {name}"),
        StatusCode::CONFLICT => println!("Group {name} already existed"),
        s => bail!("Unexpected statuscode {s} while creating group {name}"),
    }
    Ok(())
}

async fn add_service_account_roles(
    token: &str,
    client_id: &str,
    conf: &KeyCloakConfig,
) -> reqwest::Result<()> {
    if conf.keycloak_service_account_roles.is_empty() {
        return Ok(());
    }
    #[derive(serde::Deserialize)]
    struct UserIdExtractor {
        id: String,
    }
    let service_account_id = CLIENT
        .get(&format!(
            "{}admin/realms/{}/clients/{}/service-account-user",
            conf.keycloak_url, conf.keycloak_realm, client_id
        ))
        .bearer_auth(token)
        .send()
        .await?
        .json::<UserIdExtractor>()
        .await?
        .id;
    let roles: Vec<_> = get_realm_permission_roles(token, conf)
        .await?
        .into_iter()
        .filter(|f| conf.keycloak_service_account_roles.contains(&f.name))
        .collect();

    assert_eq!(roles.len(), conf.keycloak_service_account_roles.len(), "Failed to find all required service account roles got {roles:#?} but expected all of these: {:#?}", conf.keycloak_service_account_roles);
    let realm_id = roles[0].container_id.clone();
    CLIENT
        .post(&format!(
            "{}admin/realms/{}/users/{}/role-mappings/clients/{}",
            conf.keycloak_url, conf.keycloak_realm, service_account_id, realm_id
        ))
        .bearer_auth(token)
        .json(&roles)
        .send()
        .await?;

    Ok(())
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ServiceAccountRole {
    id: String,
    #[serde(rename = "containerId", skip_serializing)]
    container_id: String,
    name: String,
}

async fn get_realm_permission_roles(
    token: &str,
    conf: &KeyCloakConfig,
) -> reqwest::Result<Vec<ServiceAccountRole>> {
    #[derive(Debug, serde::Deserialize)]
    struct RealmId {
        id: String,
        #[serde(rename = "clientId")]
        client_id: String,
    }
    let permission_realm = if conf.keycloak_realm == "master" {
        "master-realm"
    } else {
        "realm-management"
    };
    let res = CLIENT
        .get(&format!(
            "{}admin/realms/{}/clients/?q={permission_realm}&search",
            conf.keycloak_url, conf.keycloak_realm
        ))
        .bearer_auth(token)
        .send()
        .await?
        .json::<Vec<RealmId>>()
        .await?;
    let role_client = res
        .into_iter()
        .find(|v| v.client_id.starts_with(permission_realm))
        .expect(&format!("Failed to find realm id for {permission_realm}"));
    CLIENT
        .get(&format!(
            "{}admin/realms/{}/clients/{}/roles",
            conf.keycloak_url, conf.keycloak_realm, role_client.id
        ))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await
}
