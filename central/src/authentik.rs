use crate::CLIENT;
use beam_lib::reqwest::{self, StatusCode, Url};
use clap::Parser;
use serde_json::{json, Value};
use shared::{OIDCConfig, SecretResult};

#[derive(Debug, Parser, Clone)]
pub struct AuthentikConfig {
    /// authentik url
    #[clap(long, env)]
    pub authentik_url: Url,
    #[clap(long, env)]
    pub authentik_id: String,
    #[clap(long, env)]
    pub authentik_secret: String,
    #[clap(long, env, default_value = "master")]
    pub authentik_realm: String,
    #[clap(long, env, value_parser, value_delimiter = ',', default_values_t = [] as [String; 0])]
    pub authentik_service_account_roles: Vec<String>,
    #[clap(long, env, value_parser, value_delimiter = ',', default_values_t = [] as [String; 0])]
    pub authentik_groups_per_bh: Vec<String>,
}

async fn get_access_token(conf: &AuthentikConfig) -> reqwest::Result<String> {
    #[derive(serde::Deserialize)]
    struct Token {
        access_token: String,
    }
    CLIENT
        .post(&format!(
            "{}/application/o/token",
            conf.authentik_url
        ))
        .form(&json!({
            "grant_type": "client_credentials",
            "client_id": conf.authentik_id,
            "username": "",
            "passord": "",
            "scope": ""
        }))
        .send()
        .await?
        .json::<Token>()
        .await
        .map(|t| t.access_token)
}

#[cfg(test)]
async fn get_access_token_via_admin_login() -> reqwest::Result<String> {
    #[derive(serde::Deserialize)]
    struct Token {
        access_token: String,
    }
    CLIENT
        .post(&format!(
        "{}/application/o/token",
            if cfg!(test) { "http://localhost:9000"} else { "http://keycloak:8080" }
        ))
        .form(&json!({
            "grant_type": "client_credentials",
            "client_id": "MI4DbeyktmjbXJRmUY9tkWvhK7yOzly139EgzhPZ",
            "client_secret": "YGcFnXQMI7HqeDUWClhTkZmPtYj4aB2z3khnoMNpCo8CgTOhUqqOFE56dP2WOJoPGOeqdPsVCrR4yvjnJviYK6dY8WeykDqnzAO1xCLHOsPxefcSAa21qe0ru2bwWBi7",
            "scope": "openid"
        }))
        .send()
        .await?
        .json::<Token>()
        .await
        .map(|t| t.access_token)
}

async fn get_client(
    name: &str,
    token: &str,
    oidc_client_config: &OIDCConfig,
    conf: &KeyCloakConfig,
) -> reqwest::Result<serde_json::Value> {
    let id = format!("{name}-{}", if oidc_client_config.is_public { "public" } else { "private" });
    CLIENT
        .get(&format!(
            "{}/admin/realms/{}/clients/{id}",
            conf.keycloak_url, conf.keycloak_realm
        ))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await
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

async fn compare_clients(
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

fn client_configs_match(a: &Value, b: &Value) -> bool {
    let includes_other_json_array = |key, comparator: &dyn Fn(_, _) -> bool| a
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(|a_values| b
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|vec| vec.iter().all(|v| comparator(a_values, v)))
        );
    
    a.get("name") == b.get("name")
        && includes_other_json_array("defaultClientScopes", &|a_v, v| a_v.contains(v))
        && includes_other_json_array("redirectUris", &|a_v, v| a_v.contains(v))
        && includes_other_json_array("protocolMappers", &|a_v, v| a_v.iter().any(|a_v| a_v.get("name") == v.get("name")))
}

fn generate_client(name: &str, oidc_client_config: &OIDCConfig, secret: &str) -> Value {
    let secret = (!oidc_client_config.is_public).then_some(secret);
    let id = format!("{name}-{}", if oidc_client_config.is_public { "public" } else { "private" });
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
        json.as_object_mut().unwrap().insert("secret".to_owned(), secret.into());
    }
    json
}

#[cfg(test)]
async fn setup_keycloak() -> reqwest::Result<(String, KeyCloakConfig)> {
    let token = get_access_token_via_admin_login().await?;
    let res = CLIENT
        .post("http://localhost:1337/admin/realms/master/client-scopes")
        .bearer_auth(&token)
        .json(&json!({
            "name": "groups",
            "protocol": "openid-connect"
        }))
        .send()
        .await?;
    dbg!(&res.status());
    Ok((
        token,
        KeyCloakConfig {
            keycloak_url: "http://localhost:1337".parse().unwrap(),
            keycloak_id: "unused in tests".into(),
            keycloak_secret: "unused in tests".into(),
            keycloak_realm: "master".into(),
            keycloak_service_account_roles: vec!["query-users".into(), "view-users".into()],
            keycloak_groups_per_bh: vec!["DKTK_CCP_#".into(), "DKTK_CCP_#_Verwalter".into()],
        },
    ))
}

#[ignore = "Requires setting up a keycloak"]
#[tokio::test]
async fn test_create_client() -> reqwest::Result<()> {
    let (token, conf) = setup_keycloak().await?;
    let name = "test";
    // public client
    let client_config = OIDCConfig { is_public: true, redirect_urls: vec!["http://foo/bar".into()] };
    let (SecretResult::Created(pw) | SecretResult::AlreadyExisted(pw)) = dbg!(post_client(&token, name, &client_config, &conf).await?) else {
        panic!("Not created or existed")
    };
    let c = dbg!(get_client(name, &token, &client_config, &conf).await.unwrap());
    assert!(client_configs_match(&c, &generate_client(name, &client_config, &pw)));
    assert!(dbg!(compare_clients(&token, name, &client_config, &conf, &pw).await?));

    // private client
    let client_config = OIDCConfig { is_public: false, redirect_urls: vec!["http://foo/bar".into()] };
    let (SecretResult::Created(pw) | SecretResult::AlreadyExisted(pw)) = dbg!(post_client(&token, name, &client_config, &conf).await?) else {
        panic!("Not created or existed")
    };
    let c = dbg!(get_client(name, &token, &client_config, &conf).await.unwrap());
    assert!(client_configs_match(&c, &generate_client(name, &client_config, &pw)));
    assert!(dbg!(compare_clients(&token, name, &client_config, &conf, &pw).await?));

    Ok(())
}

async fn post_client(
    token: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &KeyCloakConfig,
) -> reqwest::Result<SecretResult> {
    let secret = if !oidc_client_config.is_public {
        generate_secret()
    } else {
        String::with_capacity(0)
    };
    let generated_client = generate_client(name, oidc_client_config, &secret);
    let res = CLIENT
        .post(&format!(
            "{}/admin/realms/{}/clients",
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
                Ok(SecretResult::AlreadyExisted(conflicting_client
                    .as_object()
                    .and_then(|o| o.get("secret"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned()))
            } else {
                Ok(CLIENT
                    .put(&format!(
                        "{}/admin/realms/{}/clients/{}",
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
        s => unreachable!("Unexpected statuscode {s} while creating keycloak client. {res:?}"),
    }
}

async fn create_groups(name: &str, token: &str, conf: &KeyCloakConfig) -> reqwest::Result<()> {
    let capitalize = |s: &str| {
        let mut chrs = s.chars();
        chrs.next().map(char::to_uppercase).map(Iterator::collect).unwrap_or(String::new()) + chrs.as_str()
    };
    let name = capitalize(name);
    for group in &conf.keycloak_groups_per_bh {
        post_group(&group.replace('#', &name), token, conf).await?;
    }
    Ok(())
}

async fn post_group(name: &str, token: &str, conf: &KeyCloakConfig) -> reqwest::Result<()> {
    let res = CLIENT
        .post(&format!(
            "{}/admin/realms/{}/groups",
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
        s => unreachable!("Unexpected statuscode {s} while creating group {name}")
    }
    Ok(())
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

pub async fn create_client(
    name: &str,
    oidc_client_config: OIDCConfig,
    conf: &KeyCloakConfig,
) -> reqwest::Result<SecretResult> {
    let token = get_access_token(conf).await?;
    post_client(&token, name, &oidc_client_config, conf).await
}

#[ignore = "Requires setting up a keycloak"]
#[tokio::test]
async fn service_account_test() -> reqwest::Result<()> {
    let (token, conf) = setup_keycloak().await?;
    create_groups("test", &token, &conf).await?;
    // dbg!(get_realm_permission_roles(&token, &conf).await?);
    // add_service_account_roles(&token, "test-private", &conf).await?;
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
