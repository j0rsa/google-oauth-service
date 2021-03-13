extern crate jsonwebtoken as jwt;

use jwt::{decode, encode, Header, Validation};
use uuid::Uuid;
use token::models::Claims;
use crate::token;
use self::jwt::{Algorithm, EncodingKey, DecodingKey};
use crate::token::conf;
use chrono::Utc;
use std::collections::HashSet;
use crate::token::models::User;

fn now() -> i64 {
    Utc::now().timestamp()
}

fn now_plus_days(days: i64) -> i64 {
    now() + (days * 24 * 60 * 60)
}

pub fn generate_user_token(user: &User) -> String {
    generate_user_token_with_secret(user, &conf::env_token_secret())
}

fn generate_user_token_with_secret(user: &User, secret: &String) -> String {
    generate_token_with_secret(
        user.id.clone(),
        user.name.clone(),
        user.email.clone(),
        user.picture.clone(),
        secret,
    )
}

fn generate_token_with_secret(
    sub: String,
    name: String,
    email: String,
    picture: String,
    secret: &String,
) -> String {
    let claims = Claims {
        iss: conf::env_iss(),
        sub,
        iat: now(),
        exp: now_plus_days(conf::env_exp_days()),
        aud: conf::env_aud(),
        nbf: now_plus_days(conf::env_nbf_days()),
        jti: Uuid::new_v4().to_string(),
        name,
        picture,
        email,
        oauth_provider: "google".to_string(),
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
        .expect("Unable to encode claims")
}

pub fn refresh_token(token: &str) -> jsonwebtoken::errors::Result<String> {
    refresh_token_with_secret(token, &conf::env_token_secret())
}

fn refresh_token_with_secret(token: &str, secret: &String) -> jsonwebtoken::errors::Result<String> {
    get_claims_with_secret(token, secret)
        .map(|claims| generate_user_token_with_secret(&claims.get_user(), secret))
}

pub fn get_claims(token: &str) -> jsonwebtoken::errors::Result<Claims> {
    get_claims_with_secret(token, &conf::env_token_secret())
}

fn get_claims_with_secret(token: &str, secret: &String) -> jsonwebtoken::errors::Result<Claims> {
    decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_ref()), &jwt_validation())
        .map(|d| d.claims)
}

fn jwt_validation() -> Validation {
    let aud: HashSet<String> = vec!(conf::env_aud()).into_iter().collect();
    Validation {
        leeway: conf::env_leeway(),

        validate_exp: true,
        validate_nbf: true,

        iss: Some(conf::env_iss()),
        sub: None,
        aud: Some(aud),

        algorithms: vec![Algorithm::HS256],
    }
}

const BEARER_LENGTH: usize = "Bearer ".len();

pub fn get_bearer_token(authorization_header: String) -> Option<String> {
    if authorization_header.starts_with("Bearer") {
        Option::Some(authorization_header[BEARER_LENGTH..].to_string())
    } else {
        Option::None
    }
}

#[cfg(test)]
mod tests {
    use internal::*;

    use crate::token::internal;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_bearer_token() {
        let auth = "Bearer <token>".to_string();
        let resp = get_bearer_token(auth);
        assert_eq!(resp, Option::Some("<token>".to_string()));
    }

    #[test]
    fn test_get_claims() {
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiIiLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiIiwiZXhwIjoxNTgyODQyODUzMzEyLCJuYmYiOjE1ODAyNTA4NTMzMTIsImlhdCI6MTU4MDI1MDg1MzMxMiwianRpIjoiZDEwM2FiM2QtZmM1My00OTM2LThkZjQtM2FkNTdkNmI1YjNmIiwibmFtZSI6IjEyM3Rlc3QifQ.xa57RMHUD3sTnu561IsSedgd-j627GrrKMInQt_zATk";
        let secret = "test".to_string();
        let claims = get_claims_with_secret(&token.to_string(), &secret).unwrap();
        assert_eq!(claims.sub, "1234567890");
    }

    #[test]
    fn test_generate_token_with_secret() {
        let secret = "test".to_string();
        let id = "id1".to_string();
        let name = "123test".to_string();
        let email = "123email".to_string();
        let picture = "some_picture".to_string();
        let token = generate_token_with_secret(id.clone(), name.clone(), email, picture, &secret);
        assert_ne!(token, "");
        let claims = get_claims_with_secret(&token, &secret).unwrap();
        assert_eq!(claims.sub, id);
        assert_eq!(claims.name, name);
        assert_eq!(claims.email, email);
        assert_eq!(claims.picture, picture);
    }

    #[test]
    fn test_refresh_token_with_secret() {
        let secret = "test".to_string();
        let id = "id1".to_string();
        let name = "123test".to_string();
        let email = "123email".to_string();
        let picture = "some_picture".to_string();
        let token = generate_token_with_secret(id.clone(), name.clone(), email, picture, &secret);
        assert_ne!(token, "");
        let claims = get_claims_with_secret(&token, &secret).unwrap();
        sleep(Duration::from_millis(1));
        let refreshed_token = refresh_token_with_secret(&token, &secret).unwrap();
        let refreshed_claims = get_claims_with_secret(&refreshed_token, &secret).unwrap();
        assert_eq!(refreshed_claims.sub, id);
        assert_eq!(refreshed_claims.name, name);
        assert_eq!(refreshed_claims.email, email);
        assert_eq!(claims.picture, picture);
        assert!(refreshed_claims.iat > claims.iat)
    }
}
