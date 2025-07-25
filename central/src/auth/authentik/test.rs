use crate::auth::authentik::app::{check_app_result, compare_app_provider, generate_app_values};
use crate::auth::authentik::group::{create_groups, post_group};
use crate::auth::authentik::provider::{generate_provider_values, get_provider, get_provider_id};
use crate::auth::authentik::{
    client_type, create_app_provider, get_app, get_uuid, validate_app, AuthentikConfig,
};
use crate::CLIENT;
use beam_lib::reqwest::{self, Error, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared::{OIDCConfig, SecretResult};
use tracing::debug;
use tracing::field::debug;

#[cfg(test)]
pub fn setup_authentik() -> reqwest::Result<AuthentikConfig> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
    let token = "".to_owned();
    Ok(AuthentikConfig {
        authentik_url: "http://localhost:9000".parse().unwrap(),
        authentik_service_api_key: token.clone(),
        authentik_groups_per_bh: vec!["DKTK_CCP_#".into(), "DKTK_CCP_#_Verwalter".into()],
        authentik_property_names: vec![
            "allgroups".into(),
            "authentik default OAuth Mapping: OpenID 'openid'".into(),
            "authentik default OAuth Mapping: OpenID 'profile'".into(),
            "authentik default OAuth Mapping: Proxy outpost".into(),
            "authentik default OAuth Mapping: OpenID 'email'".into(),
        ],
        authentik_federation_names: vec![
            "DKFZ Account".into(),
            "Helmholtz ID".into(),
            "Login with Institutional Account (DFN-AAI)".into(),
            "Local Account".into(),
        ],
        authentik_flow_auth: "Authorize Application".into(),
        authentik_crypto_signing_key: "authentik Self-signed Certificate".into(),
        authentik_flow_invalidation: "Logged out of application".into(),
    })
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn test_create_client() -> anyhow::Result<()> {
    let conf = setup_authentik()?;
    let name = "secondtest";
    // public client
    let client_config = OIDCConfig {
        is_public: true,
        redirect_urls: vec![
            "http://foo/bar".into(),
            "http://verbis/test".into(),
            "http://dkfz/verbis/test".into(),
            "http://dkfz.verbis/*".into(),
            "https://e000-nb000.inet.dkfz-heidelberg.de/opal/*".into(),
            "https://e000-nb000/oauth2-idm/callback".into(),
        ],
    };
    let (SecretResult::Created(pw) | SecretResult::AlreadyExisted(pw)) =
        dbg!(create_app_provider(name, &client_config, &conf).await?)
    else {
        panic!("Not created or existed")
    };

    let provider_pk = get_provider(&client_type(&client_config, name), &conf)
        .await?
        .get("pk")
        .and_then(|v| v.as_i64())
        .unwrap();
    debug!("Provider: {:?}", provider_pk);
    // private client
    let client_config = OIDCConfig {
        is_public: false,
        redirect_urls: vec![
            "http://foo/bar".into(),
            "http://verbis/test".into(),
            "http://dkfz/verbis/test".into(),
            "http://dkfz.verbis/*".into(),
            "https://e000-nb000.inet.dkfz-heidelberg.de/opal/*".into(),
            "https://e000-nb000/oauth2-idm/callback".into(),
        ],
    };
    let (SecretResult::Created(pw) | SecretResult::AlreadyExisted(pw)) =
        dbg!(create_app_provider(name, &client_config, &conf).await?)
    else {
        panic!("Not created or existed")
    };

    Ok(())
}


#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn test_validate_client() -> anyhow::Result<()> {
    let conf = setup_authentik()?;
    let name = "secondtest";
    // public client
    let client_config = OIDCConfig {
        is_public: true,
        redirect_urls: vec![
            "http://foo/bar".into(),
            "http://verbis/test".into(),
            "http://dkfz/verbis/test".into(),
            "http://dkfz.verbis/*".into(),
            "https://e000-nb000.inet.dkfz-heidelberg.de/opal/*".into(),
        ],
    };
    let res = compare_app_provider(name, &client_config, "", &conf).await?;
    debug!("Validate: {res}");
    Ok(())
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn group_test() -> anyhow::Result<()> {
    let conf = setup_authentik()?;
    create_groups("next2", &conf).await
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn test_flow() {
    let conf = setup_authentik().expect("Cannot setup authentik as test");
    let test_key = "authentication_flow";
    let query_url = conf.authentik_url.join("api/v3/flows/instances/").unwrap();
    let res = get_uuid(&query_url, test_key, &conf).await;
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
    let conf = setup_authentik().expect("Cannot setup authentik as test");
    let test_key = "";
    let query_url = conf
        .authentik_url
        .join("api/v3/propertymappings/all/")
        .unwrap();
    let res = get_uuid(&query_url, test_key, &conf).await;
    //debug!("Result Property for {test_key}: {:#?}", res);
    debug!("{:?}", query_url);
    debug!("{:?}", res);
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn create_property() {
    let conf = setup_authentik().expect("Cannot setup authentik as test");
    // let flow_auth = "authorization_flow";
    // let flow_invalidation = "default-provider-invalidation-flow";
    // not used at the moment
    let property_keys = conf.authentik_property_names;
    for key in property_keys {
        let ext = "return{}".to_owned();
        let json_property = json!({
        "name": key,
        "expression": ext
        });
        let property_url = "api/v3/propertymappings/source/oauth/";
        let res = CLIENT
            .post(conf.authentik_url.join(property_url).expect("No valid Url"))
            .bearer_auth(&conf.authentik_service_api_key)
            .json(&json_property)
            .send()
            .await
            .expect("no response");
        tracing::debug!("Result: {:#?}", res);
    }
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn test_patch_provider() -> anyhow::Result<()> {
    let conf = setup_authentik()?;
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
    let pk_id = get_provider_id(name, &conf).await.unwrap();
    let generated_provider = generate_provider_values(name, &client_config, "", &conf, None).await?;
    debug!("{:#?}", generated_provider);

    let res = CLIENT
        .patch(
            conf.authentik_url
                .join(&format!("api/v3/providers/oauth2/{}/", pk_id))?,
        )
        .bearer_auth(&conf.authentik_service_api_key)
        .json(&generated_provider)
        .send()
        .await?
        .status()
        .is_success()
        .then_some(SecretResult::AlreadyExisted("test".to_owned()))
        .expect("We know the provider already exists so updating should be successful");
    debug!("Updated:  {:#?}", res);
    debug!("Provider {name} updated");
    debug!("App now: {:#?}", get_app(name, &conf).await?);
    Ok(())
}


#[derive(Deserialize, Serialize, Debug)]
struct Token {
    access_token: String,
}
// test to verifie created app and provider
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
#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn provider_check() {
    let conf = setup_authentik().expect("Cannot setup authentik as test");
    let name = "Provider for test-david-j Public";
    let provider_pk = get_provider(name, &conf)
        .await
        .expect("Cannot get provider data")
        .get("pk")
        .and_then(|v| v.as_i64())
        .unwrap();
    debug!("Provider: {:?}", provider_pk);
}