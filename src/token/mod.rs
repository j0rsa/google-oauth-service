use actix_web::{HttpRequest, HttpResponse, web, http};

use models::*;
use reqwest::*;
use crate::token::internal::get_claims;
use std::str::FromStr;

mod internal;

pub mod models;
mod conf;

pub async fn redirect_to_login() -> HttpResponse {
    let mut url = Url::parse("https://accounts.google.com/o/oauth2/auth").unwrap();
    url.query_pairs_mut()
        .append_pair("client_id", &conf::g_client_id())
        .append_pair("redirect_uri", &conf::g_code_redirect())
        .append_pair("scope", &conf::g_scope())
        .append_pair("response_type", "code");

    HttpResponse::MovedPermanently()
        .append_header((http::header::LOCATION, url.as_str()))
        .finish()
}
pub async fn get_token_from_json(request: web::Json<TokenRequest>) -> HttpResponse {
    get_token(&request.code).await
}

pub async fn get_token_from_query(request: web::Query<TokenRequest>) -> HttpResponse {
    get_token(&request.code).await
}

pub async fn get_token(code: &String) -> HttpResponse {
    debug!("Getting the token with the code: {}", code);
    let response = match reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&vec![
            ("client_id", conf::g_client_id()),
            ("client_secret", conf::g_client_secret()),
            ("code", code.clone()),
            ("grant_type", "authorization_code".to_string()),
            ("redirect_uri",conf::g_code_redirect()),
        ])
        .send()
        .await {
        Ok(value) => value,
        _ => return HttpResponse::BadRequest().body("Unable to get the access token")
    };

    let token_response = match response.text().await {
        Ok(text) => {
            match serde_json::from_str::<GTokenResponse>(&text) {
                Ok(token_response) => token_response,
                _ => return HttpResponse::InternalServerError().body(format!("Unable to parse access token response: {}", text))
            }
        }
        _ => return HttpResponse::BadRequest().body("Unable to get the access token text")
    };
    debug!("Received an access token {:?}", token_response);
    let user = match user_info(&token_response.access_token).await {
        Ok(value) => value,
        Err(e) => return HttpResponse::BadRequest().body(format!("Unable to get user information {}, token: {}", e, token_response.access_token))
    };
    let token = internal::generate_user_token(&user);
    HttpResponse::Ok().json(user_token_response(&user, &token))
}

fn user_token_response(user: &User, token: &String) -> NewTokenResponse {
    NewTokenResponse {
        id: i128::from_str(&user.id).unwrap(),
        name: user.name.clone(),
        email: Some(user.email.clone()),
        avatar_url: Some(user.picture.clone()),
        token: token.clone(),
        oauth_provider: "Google".to_string(),
    }
}

async fn user_info(token: &String) -> Result<User> {
    reqwest::Client::new()
        .get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json")
        .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
        .send().await?
        .json().await
}

pub async fn refresh(req: HttpRequest) -> HttpResponse {
    let new_token = req.headers().get(http::header::AUTHORIZATION)
        .and_then(|header_value| match header_value.to_str() {
            Ok(v) => Some(v),
            _ => None
        })
        .and_then(|auth| internal::get_bearer_token(auth.to_string()))
        .and_then(|token| match internal::refresh_token(&token) {
            Ok(v) => Some(v),
            _ => None
        });
    match new_token {
        Some(token) => {
            let claims = get_claims(&token).unwrap();
            HttpResponse::Ok().json(user_token_response(&claims.get_user(), &token))
        }
        _ => HttpResponse::Unauthorized().body("unable to refresh token")
    }
}

pub async fn check(req: HttpRequest) -> HttpResponse {
    let header = req.headers().get(http::header::AUTHORIZATION);
    match header {
        Some(header) => {
            let authorization_header_value = header.to_str()
                .expect("Authorization has no string value")
                .to_string();
            check_auth_value(authorization_header_value)
        }
        _ => HttpResponse::Unauthorized().body("No Authorization Header")
    }
}

fn check_auth_value(auth: String) -> HttpResponse {
    let token = internal::get_bearer_token(auth);
    match token {
        Some(bearer) => {
            match internal::get_claims(&bearer) {
                Ok(claims) => {
                    HttpResponse::Ok()
                        .append_header(("X-Auth-Id", claims.email))
                        .append_header(("X-Auth-User", claims.name))
                        .body("")
                }
                Err(e) => HttpResponse::Unauthorized().body(format!("Token is invalid: {}", e.to_string()))
            }
        }
        _ => HttpResponse::Unauthorized().body("No Authorization Bearer Header")
    }
}
