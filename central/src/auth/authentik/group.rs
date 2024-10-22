use crate::CLIENT;
use beam_lib::reqwest::{self, StatusCode, Url};
use serde_json::json;

use super::AuthentikConfig;


pub async fn create_groups(name: &str, token: &str, conf: &AuthentikConfig) -> reqwest::Result<()> {
    let capitalize = |s: &str| {
        let mut chrs = s.chars();
        chrs.next().map(char::to_uppercase).map(Iterator::collect).unwrap_or(String::new()) + chrs.as_str()
    };
    let name = capitalize(name);
    for group in &conf.authentik_groups_per_bh {
        post_group(&group.replace('#', &name), token, conf).await?;
    }
    Ok(())
}

pub async fn post_group(name: &str, token: &str, conf: &AuthentikConfig) -> reqwest::Result<()> {
    let res = CLIENT
        .post(&format!(
            "{}/api/v3/core/groups/",
            conf.authentik_url
        ))
        .bearer_auth(token)
        .json(&json!({
            "name": name
        }))
        .send()
        .await?;
    match res.status() {
        StatusCode::CREATED => println!("Created group {name}"),
        StatusCode::OK => println!("Created group {name}"),
        StatusCode::CONFLICT => println!("Group {name} already existed"),
        s => unreachable!("Unexpected statuscode {s} while creating group {name}")
    }
    Ok(())
}
/*
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
    let service_account_id = CLIENT.get(&format!(
            "{}/admin/realms/{}/clients/{}/service-account-user",
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
    CLIENT.post(&format!(
            "{}/admin/realms/{}/users/{}/role-mappings/clients/{}",
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
    name: String
}


async fn get_realm_permission_roles(token: &str, conf: &KeyCloakConfig) -> reqwest::Result<Vec<ServiceAccountRole>> {
    #[derive(Debug, serde::Deserialize)]
    struct RealmId {
        id: String,
        #[serde(rename = "clientId")]
        client_id: String
    }
    let permission_realm = if conf.keycloak_realm == "master" {
        "master-realm"
    } else {
        "realm-management"
    };
    let res = CLIENT.get(&format!(
            "{}/admin/realms/{}/clients/?q={permission_realm}&search",
            conf.keycloak_url, conf.keycloak_realm
        ))
        .bearer_auth(token)
        .send()
        .await?
        .json::<Vec<RealmId>>()
        .await?;
    let role_client = res.into_iter()
        .find(|v| v.client_id.starts_with(permission_realm))
        .expect(&format!("Failed to find realm id for {permission_realm}"));
    CLIENT.get(&format!(
            "{}/admin/realms/{}/clients/{}/roles",
            conf.keycloak_url, conf.keycloak_realm, role_client.id
        ))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await
}
*/