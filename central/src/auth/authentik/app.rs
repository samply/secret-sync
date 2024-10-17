use crate::CLIENT;
use beam_lib::reqwest::{self, StatusCode, Url};
use clap::Parser;
use group::create_groups;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared::{OIDCConfig, SecretResult};

use super::{generate_secret, get_access_token, group, AuthentikConfig};

pub async fn create_application(
    name: &str,
    oidc_client_config: OIDCConfig,
    conf: &AuthentikConfig,
) -> reqwest::Result<SecretResult> {
    let token = get_access_token(conf).await?;
    post_application(&token, name, &oidc_client_config, conf).await
}

async fn generate_application(
    provider: &str, 
    name: &str, 
    oidc_client_config: &OIDCConfig, 
    secret: &str, 
    conf: &AuthentikConfig, 
    token: &str)
-> Result<(), String>
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

    let res = CLIENT
    .post(&format!(
        "{}/api/v3/core/applications/",
        conf.authentik_url
    ))
    .bearer_auth(token)
    .json(&json)
    .send()
    .await
    .expect("Authentik is not reachable");

    match res.status() {
        StatusCode::CREATED => return Ok(()),
        StatusCode::BAD_REQUEST => return Err(format!("Unexpected statuscode Bad Request while creating authintik provider. {res:?}")),
        s => return Err(format!("Unexpected statuscode {s} while creating authintik provider. {res:?}"))
    }
}



async fn generate_provider(name: &str, oidc_client_config: &OIDCConfig, secret: &str, conf: &AuthentikConfig, token: &str)
-> Result<(), String>
{
    let secret = (!oidc_client_config.is_public).then_some(secret);
    let id = format!("{name}-{}", if oidc_client_config.is_public { "public" } else { "private" });
        let mut json = json!({
        "name": id,
        "client_id": id,
        "authorization_flow": "", // flow uuid
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

pub async fn post_application(
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
    //let generated_provider = generate_provider(name, oidc_client_config, &secret, conf, token).await;
    let generated_app = generate_application(name, name, oidc_client_config, &secret, conf, token).await;
    // Create groups for this client
    let generated_group = create_groups(name, token, conf).await?;

}
