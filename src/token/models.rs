use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    // expired after
    pub exp: i64,
    // valid not before
    pub nbf: i64,
    // issued at
    pub iat: i64,
    // jwt id
    pub jti: String,
    pub name: String,
    pub picture: String,
    pub email: String,
    // space separated list of scopes
    pub oauth_provider: String,
}

impl Claims {
    pub(crate) fn get_user(&self) -> User {
        User {
            id: self.sub.clone(),
            name: self.name.clone(),
            email: self.email.clone(),
            picture: self.picture.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewTokenResponse {
    pub id: i128,
    pub name: String,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub token: String,
    pub oauth_provider: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRequest {
    pub code: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GTokenResponse {
    pub access_token: String,
    pub scope: String,
    pub token_type: String,
    pub expires_in: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub picture: String,
}
