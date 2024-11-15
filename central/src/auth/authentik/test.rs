use crate::auth::authentik::app::generate_app_values;
use crate::auth::authentik::group::{create_groups, post_group};
use crate::auth::authentik::{
    app_configs_match, combine_app_provider, compare_applications, get_application, get_uuid,
    AuthentikConfig,
};
use crate::{get_beamclient, CLIENT};
use beam_lib::reqwest::{self, Error, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use shared::{OIDCConfig, SecretResult};

#[derive(Deserialize, Serialize, Debug)]
struct Token {
    access_token: String,
}

#[cfg(test)]
pub async fn setup_authentik() -> reqwest::Result<(String, AuthentikConfig)> {
    //let token = get_access_token_via_admin_login().await?;
    let token = Token {
        access_token: "1xkspjuyWAREk6tKAy4Fw7sIwnKCPfZF0zs6VdHTTIRm6yo2EjTyKAMxQMs2".to_owned(),
    };
    Ok((
        token.access_token,
        AuthentikConfig {
            authentik_url: "http://localhost:9000".parse().unwrap(),
            authentik_id: "unused in tests".into(),
            authentik_secret: "unused in tests".into(),
            authentik_groups_per_bh: vec!["DKTK_CCP_#".into(), "DKTK_CCP_#_Verwalter".into()],
        },
    ))
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn get_access_test() {
    let path_url = "http://localhost:9000/application/o/token/";
    let response = CLIENT
        .post(path_url)
        .form(&json!({
            "grant_type": "client_credentials",
            "client_id": "UtKuQ4Yh7xsPOqI8yRH86azKhEjSmrQMo2MyrvNi",
            "client_secret": "wFfVgSj1w25xpIvpZGad0nLU1NglYUSYMpPyzhbptDPEGlLlaJ0lHStEN0HHuiHMtTlqMtJoMIa2Ye4psz8EBMLdliahsqYatgcmMEYPvTL3BK0bS1YLVzhhXbxgzVgi",
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
            "client_id": "admin-cli",
            "username": "Merlin@frech.com",
            "password": "MErlin",
            "grant_type": "password"
        }))
        .send()
        .await?
        .json::<Token>()
        .await
        .map(|t| t.access_token)
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test(flavor = "multi_thread")]
async fn test_create_client() -> anyhow::Result<()> {
    let (token, conf) = setup_authentik().await?;
    let name = "window";
    // public client
    let client_config = OIDCConfig {
        is_public: true,
        redirect_urls: vec!["http://foo/bar".into()],
    };
    let (SecretResult::Created(pw) | SecretResult::AlreadyExisted(pw)) =
        dbg!(combine_app_provider(&token, name, &client_config, &conf, &get_beamclient()).await?)
    else {
        panic!("Not created or existed")
    };
    let c = dbg!(
        get_application(name, &token, &client_config, &conf, &get_beamclient())
            .await
            .unwrap()
    );
    assert!(app_configs_match(
        &c,
        &generate_app_values(name, name, &client_config)
    ));
    assert!(dbg!(
        compare_applications(&token, name, &client_config, &conf, &get_beamclient()).await?
    ));

    // private client
    let client_config = OIDCConfig {
        is_public: false,
        redirect_urls: vec!["http://foo/bar".into()],
    };
    let (SecretResult::Created(pw) | SecretResult::AlreadyExisted(pw)) =
        dbg!(combine_app_provider(&token, name, &client_config, &conf, &get_beamclient()).await?)
    else {
        panic!("Not created or existed")
    };
    let c = dbg!(
        get_application(name, &token, &client_config, &conf, &get_beamclient())
            .await
            .unwrap()
    );
    assert!(app_configs_match(
        &c,
        &generate_app_values(name, name, &client_config)
    ));
    assert!(dbg!(
        compare_applications(&token, name, &client_config, &conf, &get_beamclient()).await?
    ));

    Ok(())
}

//#[ignore = "Requires setting up a authentik"]
#[tokio::test]
async fn group_test() -> anyhow::Result<()> {
    let (token, conf) = setup_authentik().await?;
    post_group("single", &token, &conf).await
    //create_groups("next1", &token, &conf, &get_beamclient()).await
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test(flavor = "multi_thread")]
async fn test_flow() {
    let (token, conf) = setup_authentik()
        .await
        .expect("Cannot setup authentik as test");
    let test_key = "authorization_flow";
    let flow_url = "/api/v3/flows/instances/?ordering=slug&page=1&page_size=20&search=";
    let res = get_uuid(flow_url, &conf, &token, test_key, &get_beamclient()).await;
    dbg!(&res);
    match res {
        Some(uuid) => {
            println!("Found: {}", uuid);
            assert!(!uuid.is_empty(), "empty");
        }
        None => {
            panic!("Expected {}", test_key);
        }
    }
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test(flavor = "multi_thread")]
async fn test_property() {
    let (token, conf) = setup_authentik()
        .await
        .expect("Cannot setup authentik as test");
    let test_key = "web-origins";
    let flow_url = "/api/v3/propertymappings/all/?managed__isnull=true&ordering=name&page=1&page_size=20&search=";
    let res = get_uuid(flow_url, &conf, &token, test_key, &get_beamclient()).await;
    dbg!(res);
}

#[ignore = "Requires setting up a authentik"]
#[tokio::test(flavor = "multi_thread")]
async fn create_property() {
    let (token, conf) = setup_authentik()
        .await
        .expect("Cannot setup authentik as test");
    let acr = "web-origins".to_owned();
    let ext = "return{}".to_owned();
    let json_property = json!({
    "name": acr,
    "expression": ext
    });
    let propperty_url = "/api/v3/propertymappings/source/oauth/";
    let res = get_beamclient()
        .post(&format!("{}{}", conf.authentik_url, propperty_url))
        .bearer_auth(token)
        .json(&json_property)
        .send()
        .await
        .expect("no response");
    dbg!(res);
}
