# Google OAuth Service

This is a simple service to authenticate users via Google OAuth and use it as an authentication middleware in a bundle with Traefik

[Traefik setup](https://doc.traefik.io/traefik/v1.7/configuration/backends/kubernetes/#authentication)

## Flow
[ref](https://developers.google.com/identity/sign-in/web/server-side-flow)
[ref2](https://developers.google.com/identity/protocols/oauth2/native-app)

## Register
1. Go to create an [Oauth credentials client](https://console.developers.google.com/apis/credentials/oauthclient?previousPage=%2Fapis%2Fcredentials)
1. If it is first time - configure OAuth consent screen 
    1. Change the default project if needed
    1. Enter your homepage link, support and dev emails, authorized domains
    1. Choose scopes to request
    1. Choose test users (if required)
1. Go to create an [Oauth credentials client](https://console.developers.google.com/apis/credentials/oauthclient?previousPage=%2Fapis%2Fcredentials)
1. Web client
1. Name it, add authorized redirects and click create

## Endpoints
| Method |     URL         | Description |
| ------:| --------------- | ----------- |
| `GET`  | `/health`       | Healthcheck  which returns Code 200 |
| `GET`  | `/auth/login`   | Redirect to login page with required scopes for provided client id |
| `POST` | `/auth/token`   | Get JWT token by passing user code `{ "code": "<code>"}` after auth on https://accounts.google.com/o/oauth2/auth |
| `POST` | `/internal/auth/token`  | Get JWT token by passing user code in the query after auth on https://accounts.google.com/o/oauth2/auth |
| `GET`  | `/auth/check`   | Checks the token and returns code 200 with Headers: `X-Auth-Id` with user email, `X-Auth-User` with user name |
| `POST` | `/auth/refresh` | Refresh token with a new one by passing the old valid one `{ "token": "eyJhbGciOiJIUz..." }` |

## Environment variables
| Variable | Default value | Description |
| ------| --- | ----------- |
| RUST_LOG | info | defines the log level of app |
| BIND_ADDRESS | 0.0.0.0 | Address of web server to listen connections |
| BIND_PORT | 8080 | Port of web server to listen connections |
| **JWT_SECRET** | -- | JWT HS256 Secret Key |
| JWT_ISS | "" | iss (issuer): Issuer of the JWT |
| JWT_AUD | "" | aud (audience): Recipient for which the JWT is intended |
| JWT_EXP_DAYS | 30 | exp (expiration time): Time in days after which the JWT expires |
| JWT_NBF_DAYS | 0 | nbf (not before time): Time in days before which the JWT must not be accepted for processing |
| JWT_LEEWAY_SEC | 0 | leeway (in seconds) to the `exp`, `iat` and `nbf` validation to  account for clock skew |
| **G_CLIENT_ID** | "" | Google OAuth App client id |
| **G_CLIENT_SECRET** | "" | Google oAuth App client secret | 
| **G_CODE_REDIRECT** | "" | Redirect page after login |
| G_SCOPE | "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email" | Scopes to request ref: https://developers.google.com/identity/protocols/oauth2/scopes |

*Bold variables are required to specify

## Token Claims
```rust
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
```

# Build

## Build release locally
      cargo build --release

## Build release in docker and prepare an image
      docker build -t j0rsa/google-oauth-service .
      docker-compose -f docker/docker-compose.yaml up