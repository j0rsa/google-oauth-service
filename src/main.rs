#[macro_use]
extern crate log;

use actix_web::{App, HttpServer, web};
use env_logger;
use std::env;

mod health;
mod token;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let address = env::var("BIND_ADDRESS").unwrap_or("0.0.0.0".to_string());
    let port = env::var("BIND_PORT").unwrap_or("8080".to_string());

    HttpServer::new(move ||
        App::new()
            .service(web::resource("/health").route(web::get().to(health::ok)))
            .service(web::resource("/auth/login").route(web::get().to(token::redirect_to_login)))
            .service(web::resource("/auth/token").route(web::post().to(token::get_token_from_json)))
            .service(web::resource("/auth/refresh").route(web::post().to(token::refresh)))
            .service(web::resource("/auth/check").route(web::get().to(token::check)))
            .service(web::resource("/internal/auth/token").route(web::get().to(token::get_token_from_query)))
    )
        .bind(format!("{}:{}", &address, &port))?
        .run()
        .await
}