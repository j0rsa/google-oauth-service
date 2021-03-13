use std::env;
use std::str::FromStr;

pub fn env_iss() -> String {
    env::var("JWT_ISS").unwrap_or("".to_string())
}

pub fn env_aud() -> String {
    env::var("JWT_AUD").unwrap_or("".to_string())
}

pub fn env_exp_days() -> i64 {
    return match i64::from_str(
        env::var("JWT_EXP_DAYS").unwrap_or("30".to_string()).as_ref()
    ) {
        Ok(v) => v,
        Err(e) => panic!(e)
    };
}

pub fn env_nbf_days() -> i64 {
    return match i64::from_str(
        env::var("JWT_NBF_DAYS").unwrap_or("0".to_string()).as_ref()
    ) {
        Ok(v) => v,
        Err(e) => panic!(e)
    };
}

pub fn env_token_secret() -> String {
    env::var("JWT_SECRET").expect("No token secret found!")
}

pub fn env_leeway() -> u64 {
    return match u64::from_str(
        env::var("JWT_LEEWAY_SEC").unwrap_or("0".to_string()).as_ref()
    ) {
        Ok(v) => v,
        Err(e) => panic!(e)
    };
}

pub fn g_scope() -> String {
    env::var("G_SCOPE").unwrap_or("https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email".to_string())
}

pub fn g_client_id() -> String {
    env::var("G_CLIENT_ID").expect("Google OAuth App client id is required!")
}

pub fn g_client_secret() -> String {
    env::var("G_CLIENT_SECRET").expect("Google OAuth App client secret is required!")
}

pub fn g_code_redirect() -> String {
    env::var("G_CODE_REDIRECT").expect("Google redirect page is required!")
}
