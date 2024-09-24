mod test;
mod group;


use crate::CLIENT;
use beam_lib::reqwest::{self, StatusCode, Url};
use clap::Parser;
use group::create_groups;
use serde::{Deserialize, Serialize};
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
    // !Todo is it needed 
    #[clap(long, env, default_value = "master")]
    pub authentik_tenant: String,
    #[clap(long, env, value_parser, value_delimiter = ',', default_values_t = [] as [String; 0])]
    pub authentik_service_account_roles: Vec<String>,
    #[clap(long, env, value_parser, value_delimiter = ',', default_values_t = [] as [String; 0])]
    pub authentik_groups_per_bh: Vec<String>,
}

async fn get_access_token(conf: &AuthentikConfig) -> reqwest::Result<String> {
    #[derive(Deserialize, Serialize, Debug)]
    struct Token {
        access_token: String,
    }
    CLIENT
        .post(&format!(
            "{}/application/o/token/",
            conf.authentik_url
        ))
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



async fn get_application(
    name: &str,
    token: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
) -> reqwest::Result<serde_json::Value> {
    let id = format!("{name}-{}", if oidc_client_config.is_public { "public" } else { "private" });
    CLIENT
        .get(&format!(
            "{}/api/v3/core/applications/{id}/",
            conf.authentik_url
        ))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await
}

pub async fn validate_application(
    name: &str,
    oidc_client_config: &OIDCConfig,
    secret: &str,
    conf: &AuthentikConfig,
) -> reqwest::Result<bool> {
    let token = get_access_token(conf).await?;
    compare_applications(&token, name, oidc_client_config, conf, secret).await
}

async fn compare_applications(
    token: &str,
    name: &str,
    oidc_client_config: &OIDCConfig,
    conf: &AuthentikConfig,
    secret: &str,
) -> Result<bool, reqwest::Error> {
    let client = get_application(name, token, oidc_client_config, conf).await?;
    let wanted_client = generate_application(name, oidc_client_config, secret);
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

fn generate_application(name: &str, oidc_client_config: &OIDCConfig, secret: &str) -> Value {
    let secret = (!oidc_client_config.is_public).then_some(secret);
    let id = format!("{name}-{}", if oidc_client_config.is_public { "public" } else { "private" });
// Todo noch anpassen
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

async fn post_application(
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
    let generated_app = generate_application(name, oidc_client_config, &secret);
    let res = CLIENT
        .post(&format!(
            "{}/api/v3/core/applications/",
            conf.authentik_url
        ))
        .bearer_auth(token)
        .json(&generated_app)
        .send()
        .await?;
    // Create groups for this client
    create_groups(name, token, conf).await?;
    match res.status() {
        StatusCode::CREATED => {
            println!("Client for {name} created.");
            if !oidc_client_config.is_public {
                let client_id = generated_app
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

pub async fn create_application(
    name: &str,
    oidc_client_config: OIDCConfig,
    conf: &AuthentikConfig,
) -> reqwest::Result<SecretResult> {
    let token = get_access_token(conf).await?;
    post_application(&token, name, &oidc_client_config, conf).await
}
