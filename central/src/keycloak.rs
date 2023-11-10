use crate::CLIENT;
use beam_lib::reqwest::{self, StatusCode, Url};
use clap::Parser;
use serde_json::{json, Value};
use shared::{SecretResult, OIDCConfig};

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
async fn get_access_token_via_admin_login() -> reqwest::Result<String> {
    #[derive(serde::Deserialize)]
    struct Token {
        access_token: String,
    }
    CLIENT
        .post(&format!(
            "{}/realms/master/protocol/openid-connect/token",
            if cfg!(test) { "http://localhost:1337"} else { "http://keycloak:8080" }
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

async fn compare_clients(token: &str, name: &str, oidc_client_config: &OIDCConfig, conf: &KeyCloakConfig, secret: &str) -> Result<bool, reqwest::Error> {
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
        "publicClient": oidc_client_config.is_public,
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
    Ok((token, KeyCloakConfig { keycloak_url: "http://localhost:1337".parse().unwrap(), keycloak_id: "unused in tests".into(), keycloak_secret: "unused in tests".into(), keycloak_realm: "master".into() }))
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
    match res.status() {
        StatusCode::CREATED => {
            println!("Client for {name} created.");
            Ok(SecretResult::Created(secret))
        },
        StatusCode::CONFLICT => {
            let conflicting_client = get_client(name, token, oidc_client_config, conf).await?;
            if client_configs_match(&conflicting_client, &generated_client) {
                Ok(SecretResult::AlreadyExisted(conflicting_client
                    .as_object()
                    .and_then(|o| o.get("secret"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned()))
            } else {
                Ok(CLIENT
                    .put(&format!(
                        "{}/admin/realms/{}/clients/{}",
                        conf.keycloak_url, conf.keycloak_realm,
                        conflicting_client.get("clientId").and_then(Value::as_str).expect("We have a valid client")
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
    oidc_client_config: OIDCConfig,
    conf: &KeyCloakConfig,
) -> reqwest::Result<SecretResult> {
    let token = get_access_token(conf).await?;
    post_client(&token, name, &oidc_client_config, conf).await
}
