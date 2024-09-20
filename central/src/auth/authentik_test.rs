use beam_lib::reqwest::{self, Error, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::CLIENT;


#[tokio::test]
async fn get_access_token() {
    let path_url = "http://localhost:9000/application/o/token";
    #[derive(Deserialize, Serialize, Debug)]
    struct Token {
        access_token: String,
    }
    let response = CLIENT
        .post(path_url)
        .header("Content-Type", "applikation/x-www-form-urlencoded")
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "MI4DbeyktmjbXJRmUY9tkWvhK7yOzly139EgzhPZ"),
            ("client_secret", "YGcFnXQMI7HqeDUWClhTkZmPtYj4aB2z3khnoMNpCo8CgTOhUqqOFE56dP2WOJoPGOeqdPsVCrR4yvjnJviYK6dY8WeykDqnzAO1xCLHOsPxefcSAa21qe0ru2bwWBi7"),
            ("scope", "openid")
        ])
        .send()
        .await
        .expect("no response");

    let t = response
        .json::<Token>()
        .await
        .expect("Token can not be parseed");
    dbg!(&t);
    assert!(!t.access_token.is_empty());
}
