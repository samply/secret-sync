use crate::CLIENT;
use beam_lib::reqwest::{Result, Url, StatusCode};
use clap::Parser;
use serde_json::json;
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

async fn get_access_token(conf: &KeyCloakConfig) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Token {
        access_token: String,
    }
    dbg!(CLIENT
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
            .await?)
        .json::<Token>()
        .await
        .map(|t| t.access_token)
}

#[cfg(test)]
async fn get_access_token_via_admin_login(conf: &KeyCloakConfig) -> Result<String> {
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

#[tokio::test]
async fn test_create_client() -> Result<()> {
    let conf = KeyCloakConfig {
        keycloak_url: "http://localhost:1337".parse().unwrap(),
        keycloak_id: "".to_owned(),
        keycloak_secret: "".to_owned(),
        keycloak_realm: "master".to_owned(),
    };
    let token = get_access_token_via_admin_login(&conf).await?;
    dbg!(post_client(&token, "test", vec!["http://test.bk".into()], &conf).await?);
    Ok(())
}

async fn post_client(
    token: &str,
    name: &str,
    redirect_urls: Vec<String>,
    conf: &KeyCloakConfig,
) -> Result<SecretResult> {
    let secret = generate_secret();
    let res = CLIENT
        .post(&format!(
            "{}/admin/realms/{}/clients",
            conf.keycloak_url, conf.keycloak_realm
        ))
        .bearer_auth(token)
        .json(&json!({
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
        }))
        .send()
        .await?;
    match res.status() {
        StatusCode::CREATED => Ok(SecretResult::Created(secret)),
        StatusCode::CONFLICT => Ok(SecretResult::AlreadyValid),
        s => unreachable!("Unexpected statuscode {s} while creating keycloak client")
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
) -> Result<SecretResult> {
    post_client(&get_access_token(conf).await?, name, redirect_urls, conf).await
}
