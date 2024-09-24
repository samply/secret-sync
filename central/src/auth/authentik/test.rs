use beam_lib::reqwest::{self, Error, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::auth::authentik::AuthentikConfig;
use crate::CLIENT;


#[tokio::test]
async fn get_access_test() {
    let path_url = "http://localhost:9000/application/o/token/";
    #[derive(Deserialize, Serialize, Debug)]
    struct Token {
        access_token: String,
    }
    let response = CLIENT
        .post(path_url)
        .form(&json!({
            "grant_type": "client_credentials",
            "client_id": "MI4DbeyktmjbXJRmUY9tkWvhK7yOzly139EgzhPZ",
            "client_secret": "YGcFnXQMI7HqeDUWClhTkZmPtYj4aB2z3khnoMNpCo8CgTOhUqqOFE56dP2WOJoPGOeqdPsVCrR4yvjnJviYK6dY8WeykDqnzAO1xCLHOsPxefcSAa21qe0ru2bwWBi7",
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
    #[derive(serde::Deserialize)]
    struct Token {
        access_token: String,
    }
    CLIENT
        .post(&format!(
            "{}/application/o/token/",
            if cfg!(test) { "http://localhost:9000"} else { "http://authentik:8080" }
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
/*
#[cfg(test)]
async fn setup_keycloak() -> reqwest::Result<(String, AuthentikConfig)> {
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
        AuthentikConfig {
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

#[ignore = "Requires setting up a keycloak"]
#[tokio::test]
async fn service_account_test() -> reqwest::Result<()> {
    let (token, conf) = setup_keycloak().await?;
    create_groups("test", &token, &conf).await?;
    // dbg!(get_realm_permission_roles(&token, &conf).await?);
    // add_service_account_roles(&token, "test-private", &conf).await?;
    Ok(())
}


    */