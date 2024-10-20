mod test;
mod group;
pub mod app;

use crate::CLIENT;
use app::generate_app_values;
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
    let wanted_client = generate_app_values(name, name, oidc_client_config, secret);
    Ok(client.get("secret") == wanted_client.get("secret")
        && app_configs_match(&client, &wanted_client))
}

fn app_configs_match(a: &Value, b: &Value) -> bool {
    let includes_other_json_array = |key, comparator: &dyn Fn(_, _) -> bool| a
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(|a_values| b
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|vec| vec.iter().all(|v| comparator(a_values, v)))
        );
    // Todo! compare values test
    todo!("compare keys must be changed");
    a.get("name") == b.get("name")
        && includes_other_json_array("defaultClientScopes", &|a_v, v| a_v.contains(v))
        && includes_other_json_array("redirectUris", &|a_v, v| a_v.contains(v))
        && includes_other_json_array("protocolMappers", &|a_v, v| a_v.iter().any(|a_v| a_v.get("name") == v.get("name")))
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

