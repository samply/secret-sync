use crate::auth::authentik::app::{check_app_result, compare_app_provider, generate_app_values};
use crate::auth::authentik::group::{create_groups, post_group};
use crate::auth::authentik::provider::{generate_provider_values, get_provider, get_provider_id};
use crate::auth::authentik::{
    combine_app_provider, get_application, get_uuid, validate_application, AuthentikConfig,
};
use crate::CLIENT;
use beam_lib::reqwest::{self, Error, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared::{OIDCConfig, SecretResult};

use tracing::debug;
use tracing::field::debug;
#[derive(Deserialize, Serialize, Debug)]
struct Token {
    access_token: String,
}

#[cfg(test)]
pub fn setup_authentik() -> reqwest::Result<(String, AuthentikConfig)> {
    //let token = get_access_token_via_admin_login().await?;
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
    //let token = "";
    // export AUTHENTIK_TOKEN=
    let token = std::env::var("AUTHENTIK_TOKEN").expect("Missing ENV Authentik_Token");
    Ok((
        token,
        AuthentikConfig {
            authentik_url: "http://localhost:9000".parse().unwrap(),
            authentik_id: "unused in tests".into(),
            authentik_secret: "unused in tests".into(),
            authentik_groups_per_bh: vec!["DKTK_CCP_#".into(), "DKTK_CCP_#_Verwalter".into()],
        },
    ))
}

// test is working
#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn get_access_test() {
    let path_url = "http://localhost:9000/application/o/token/";
    let response = CLIENT
        .post(path_url)
        .form(&json!({
            "grant_type": "client_credentials",
            "client_id": "",
            "client_secret": "",
            "scope": "openid"
        }))
        .send()
        .await
        .expect("no response");
    // let raw = response.text().await.expect("no resoponse");
    // dbg!(&raw);

    let t = response
        .json::<Token>()
        .await
        .expect("Token can not be parseed");
    dbg!(&t);
    assert!(!t.access_token.is_empty());
}

#[cfg(test)]
// nicht möglich mit authentik
async fn get_access_token_via_admin_login() -> reqwest::Result<String> {
    CLIENT
        .post(&format!(
            "{}/application/o/token/",
            if cfg!(test) {
                "http://localhost:9000"
            } else {
                "http://authentik:8080"
            }
        ))
        .form(&json!({
            "client_id": "",
            "username": "",
            "password": "",
            "grant_type": ""
        }))
        .send()
        .await?
        .json::<Token>()
        .await
        .map(|t| t.access_token)
}

//#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn test_create_client() -> anyhow::Result<()> {
    let (token, conf) = setup_authentik()?;
    let name = "tree";
    // public client
    let client_config = OIDCConfig {
        is_public: true,
        redirect_urls: vec![
            "http://foo/bar".into(),
            "http://verbis/test".into(),
            "http://dkfz/verbis/test".into(),
        ],
    };
    let (SecretResult::Created(pw) | SecretResult::AlreadyExisted(pw)) =
        dbg!(combine_app_provider(&token, name, &client_config, &conf).await?)
    else {
        panic!("Not created or existed")
    };
    let provider_pk = get_provider(name, &token, &client_config, &conf)
        .await?
        .get("pk")
        .and_then(|v| v.as_i64())
        .unwrap();

    // private client
    let client_config = OIDCConfig {
        is_public: false,
        redirect_urls: vec![
            "http://foo/bar".into(),
            "http://verbis/test".into(),
            "http://dkfz/verbis/test".into(),
        ],
    };
    let (SecretResult::Created(pw) | SecretResult::AlreadyExisted(pw)) =
        dbg!(combine_app_provider(&token, name, &client_config, &conf).await?)
    else {
        panic!("Not created or existed")
    };

    Ok(())
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn group_test() -> anyhow::Result<()> {
    let (token, conf) = setup_authentik()?;
    create_groups("next2", &token, &conf).await
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn test_flow() {
    let (token, conf) = setup_authentik().expect("Cannot setup authentik as test");
    let test_key = "authentication_flow";
    let base_url = conf.authentik_url.join("api/v3/flows/instances/").unwrap();
    let query_url = Url::parse_with_params(
        base_url.as_str(),
        &[("orderung", "slug"), ("page", "1"), ("page_size", "20")],
    )
    .unwrap();
    //let flow_url = "api/v3/flows/instances/?ordering=slug&page=1&page_size=20&search=";
    let res = get_uuid(&query_url, &token, test_key).await;
    debug!(res);
    match res {
        Some(uuid) => {
            debug!("Found flow id: {}", uuid);
            assert!(!uuid.is_empty(), "empty");
        }
        None => {
            debug!("Result flow {} not found", test_key);
        }
    }
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn test_property() {
    let (token, conf) = setup_authentik().expect("Cannot setup authentik as test");
    let test_key = "web-origins";
    let base_url = conf
        .authentik_url
        .join("api/v3/propertymappings/all/")
        .unwrap();
    let query_url = Url::parse_with_params(
        base_url.as_str(),
        &[
            ("managed__isnull", "true"),
            ("ordering", "name"),
            ("page", "1"),
            ("page_size", "20"),
        ],
    )
    .unwrap();
    //let flow_url = "api/v3/propertymappings/all/?managed__isnull=true&ordering=name&page=1&page_size=20&search=";
    let res = get_uuid(&query_url, &token, test_key).await;
    //debug!("Result Property for {test_key}: {:#?}", res);
    debug!("{:?}", query_url);
    debug!("{:?}", res);
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn create_property() {
    let (token, conf) = setup_authentik().expect("Cannot setup authentik as test");
    // let flow_auth = "authorization_flow";
    // let flow_invalidation = "default-provider-invalidation-flow";
    let property_keys = vec![
        "web-origins",
        "acr",
        "profile",
        "roles",
        "email",
        "microprofile-jwt",
        "groups",
    ];
    for key in property_keys {
        let ext = "return{}".to_owned();
        let json_property = json!({
        "name": key,
        "expression": ext
        });
        let property_url = "api/v3/propertymappings/source/oauth/";
        let res = CLIENT
            .post(conf.authentik_url.join(property_url).expect("No valid Url"))
            .bearer_auth(&token)
            .json(&json_property)
            .send()
            .await
            .expect("no response");
        tracing::debug!("Result: {:#?}", res);
    }
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn test_validate_client() -> anyhow::Result<()> {
    let (token, conf) = setup_authentik()?;
    let name = "air";
    // public client
    let client_config = OIDCConfig {
        is_public: true,
        redirect_urls: vec![
            "http://foo/bar".into(),
            "http://verbis/test".into(),
            "http://dkfz/verbis/test".into(),
        ],
    };
    let res = compare_app_provider(&token, name, &client_config, "", &conf).await?;
    debug!("Validate: {res}");
    Ok(())
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn test_patch_provider() -> anyhow::Result<()> {
    let (token, conf) = setup_authentik()?;
    let name = "dark";
    // public client
    let client_config = OIDCConfig {
        is_public: false,
        redirect_urls: vec![
            "http://foo/bar".into(),
            "http://verbis/test".into(),
            "http://dkfz/verbis/test".into(),
        ],
    };
    let pk_id = get_provider_id(name, &token, &conf).await.unwrap();
    let generated_provider =
        generate_provider_values(name, &client_config, "", &conf, &token).await?;
    debug!("{:#?}", generated_provider);

    let res = CLIENT
        .patch(
            conf.authentik_url
                .join(&format!("api/v3/providers/oauth2/{}/", pk_id))?,
        )
        .bearer_auth(&token)
        .json(&generated_provider)
        .send()
        .await?
        .status()
        .is_success()
        .then_some(SecretResult::AlreadyExisted("test".to_owned()))
        .expect("We know the provider already exists so updating should be successful");
    debug!("Updated:  {:#?}", res);
    debug!("Provider {name} updated");
    debug!(
        "App now: {:#?}",
        get_application(name, &token, &conf).await?
    );
    Ok(())
}
