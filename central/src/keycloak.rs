use crate::CLIENT;
use beam_lib::reqwest::{self, StatusCode, Url};
use clap::Parser;
use serde_json::{json, Value};
use shared::SecretResult;

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
}

async fn get_access_token(conf: &KeyCloakConfig) -> reqwest::Result<String> {
    #[derive(serde::Deserialize)]
    struct Token {
        access_token: String,
    }
    CLIENT
        .post(&format!(
            "{}/realms/{}/protocol/openid-connect/token",
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

#[cfg(test)]
async fn get_access_token_via_admin_login(conf: &KeyCloakConfig) -> reqwest::Result<String> {
    #[derive(serde::Deserialize)]
    struct Token {
        access_token: String,
    }
    CLIENT
        .post(&format!(
            "{}/realms/{}/protocol/openid-connect/token",
            conf.keycloak_url, conf.keycloak_realm
        ))
        .form(&json!({
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin",
            "grant_type": "password"
        }))
        .send()
        .await?
        .json::<Token>()
        .await
        .map(|t| t.access_token)
}

async fn get_client(
    id: &str,
    token: &str,
    conf: &KeyCloakConfig,
) -> reqwest::Result<serde_json::Value> {
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
    id: &str,
    redirect_urls: &[String],
    secret: &str,
    conf: &KeyCloakConfig,
) -> reqwest::Result<bool> {
    let token = get_access_token(conf).await?;
    let client = get_client(id, &token, conf).await?;
    let wanted_client = generate_client(id, redirect_urls, secret);
    Ok(client_configs_match(&client, &wanted_client))
}

fn client_configs_match(a: &Value, b: &Value) -> bool {
    assert_json_diff::assert_json_matches_no_panic(
        &a,
        &b,
        assert_json_diff::Config::new(assert_json_diff::CompareMode::Inclusive)
    )
    .map_err(|e| eprintln!("Clients did not match: {e}"))
    .is_ok()
}

fn generate_client(name: &str, redirect_urls: &[String], secret: &str) -> Value {
    json!({
        "name": name,
        "id": name,
        "clientId": name,
        "redirectUris": redirect_urls,
        "secret": secret,
        "publicClient": false,
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
                "included.client.audience": name,
                "id.token.claim": "true",
                "access.token.claim": "true"
            }
        }]
    })
}

#[tokio::test]
async fn test_create_client() -> reqwest::Result<()> {
    let conf = KeyCloakConfig {
        keycloak_url: "http://localhost:1337".parse().unwrap(),
        keycloak_id: "".to_owned(),
        keycloak_secret: "".to_owned(),
        keycloak_realm: "master".to_owned(),
    };
    let token = get_access_token_via_admin_login(&conf).await?;
    dbg!(post_client(&token, "test", vec!["http://test.bk".into()], &conf).await?);
    dbg!(get_client("test", &token, &conf).await.unwrap());
    Ok(())
}

async fn post_client(
    token: &str,
    name: &str,
    redirect_urls: Vec<String>,
    conf: &KeyCloakConfig,
) -> reqwest::Result<SecretResult> {
    let secret = generate_secret();
    let generated_client = generate_client(name, &redirect_urls, &secret);
    let res = CLIENT
        .post(&format!(
            "{}/admin/realms/{}/clients",
            conf.keycloak_url, conf.keycloak_realm
        ))
        .bearer_auth(token)
        .json(&generated_client)
        .send()
        .await?;
    match res.status() {
        StatusCode::CREATED => Ok(SecretResult::Created(secret)),
        StatusCode::CONFLICT => {
            let conflicting_client = get_client(name, token, conf).await?;
            if client_configs_match(&conflicting_client, &generated_client) {
                Ok(conflicting_client
                    .as_object()
                    .and_then(|o| o.get("secret"))
                    .and_then(|v| v.as_str())
                    .map(|v| SecretResult::AlreadyExisted(v.into()))
                    .expect("These values should have a secret"))
            } else {
                Ok(CLIENT
                    .put(&format!(
                        "{}/admin/realms/{}/clients",
                        conf.keycloak_url, conf.keycloak_realm
                    ))
                    .bearer_auth(token)
                    .json(&generated_client)
                    .send()
                    .await?
                    .status()
                    .is_success()
                    .then_some(secret)
                    .map(SecretResult::Created)
                    .expect("Put should be successfull"))
            }
        }
        s => unreachable!("Unexpected statuscode {s} while creating keycloak client"),
    }
}

fn generate_secret() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%$#@!~";
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
    redirect_urls: Vec<String>,
    conf: &KeyCloakConfig,
) -> reqwest::Result<SecretResult> {
    let token = get_access_token(conf).await?;
    post_client(&token, name, redirect_urls, conf).await
}

///         
/// pw set? validate?
/// pw create but what if it already exists?
///
///
mod asdf {}
