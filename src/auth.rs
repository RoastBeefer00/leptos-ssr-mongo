#[allow(unused)]
use axum::{
    extract::{FromRequestParts, Query, State},
    response::{IntoResponse, Redirect},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::StatusCode;
use leptos::prelude::ServerFnError;
use oauth2::TokenResponse;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl,
};
use serde::Deserialize;
use std::env;
use tower_cookies::{cookie::SameSite, Cookie, Cookies};

use crate::{
    db::{find_or_create_user, get_database},
    models::GoogleUserInfo,
    state::AppState,
};

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v3/userinfo";

pub const SESSION_COOKIE_NAME: &str = "session";
const CSRF_COOKIE_NAME: &str = "csrf_state";
// const OAUTH_SCOPES: [&str; 2] = ["openid", "email"]; // Add "profile" if you need name/picture directly

pub fn setup_cookie(cookie: &mut Cookie) {
    cookie.set_http_only(true);
    cookie.set_path("/");
    cookie.set_secure(false); // Set to true if using HTTPS
    cookie.set_same_site(SameSite::Lax);
}

/// Helper to create the Google OAuth2 client.
pub fn setup_google_oauth_client() -> Result<BasicClient, ServerFnError> {
    let google_client_id = ClientId::new(
        env::var("GOOGLE_CLIENT_ID")
            .map_err(|_| ServerFnError::new("Missing GOOGLE_CLIENT_ID".to_string()))?,
    );
    let google_client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET")
            .map_err(|_| ServerFnError::new("Missing GOOGLE_CLIENT_SECRET".to_string()))?,
    );
    let auth_url = AuthUrl::new(GOOGLE_AUTH_URL.to_string())
        .map_err(|e| ServerFnError::new(format!("Invalid auth URL: {}", e)))?;
    let token_url = TokenUrl::new(GOOGLE_TOKEN_URL.to_string())
        .map_err(|e| ServerFnError::new(format!("Invalid token URL: {}", e)))?;
    let redirect_url = RedirectUrl::new(
        env::var("GOOGLE_REDIRECT_URI")
            .map_err(|_| ServerFnError::new("GOOGLE_REDIRECT_URI".to_string()))?,
    )
    .map_err(|e| ServerFnError::new(format!("Invalid redirect URL: {}", e)))?;

    Ok(BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(redirect_url))
}

/// Axum handler to initiate Google login.
pub async fn google_login_handler(
    State(state): State<AppState>,
    cookies: Cookies, // Use tower-cookies extractor
) -> impl IntoResponse {
    let (authorize_url, csrf_state) = state
        .google_oauth_client
        .authorize_url(CsrfToken::new_random)
        // Add required scopes
        .add_scope(Scope::new("openid".to_string())) // Request OpenID scope
        .add_scope(Scope::new("email".to_string())) // Request email scope
        .add_scope(Scope::new("profile".to_string())) // Request profile scope for name/picture
        .url();

    // Store CSRF token in a secure, HttpOnly cookie
    let csrf_value_b64 = URL_SAFE_NO_PAD.encode(csrf_state.secret());
    let mut csrf_cookie = Cookie::new(CSRF_COOKIE_NAME, csrf_value_b64);
    setup_cookie(&mut csrf_cookie);

    cookies.add(csrf_cookie); // Add the cookie using the Cookies extractor

    Redirect::to(authorize_url.as_str())
}

#[derive(Debug, Deserialize)]
pub struct AuthCallbackParams {
    code: String,
    state: String, // Provided by Google, must match CSRF token
}

/// Axum handler for the Google OAuth callback.
pub async fn google_auth_callback_handler(
    cookies: Cookies,
    Query(params): Query<AuthCallbackParams>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // 1. Verify CSRF Token
    let stored_csrf_b64 = cookies.get(CSRF_COOKIE_NAME).map(|c| c.value().to_string());
    // Remove the CSRF cookie after retrieving it
    let mut cookie = Cookie::from(CSRF_COOKIE_NAME);
    setup_cookie(&mut cookie);
    cookies.remove(cookie);

    let stored_csrf_secret = match stored_csrf_b64 {
        Some(b64) => URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid CSRF token format".to_string(),
                )
                    .into_response()
            })
            .unwrap(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Missing CSRF token cookie".to_string(),
            )
                .into_response()
        }
    };

    if stored_csrf_secret != params.state.as_bytes() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "CSRF token mismatch".to_string(),
        )
            .into_response();
    }

    // 2. Exchange Authorization Code for Access Token
    let token_response = state
        .google_oauth_client
        .exchange_code(AuthorizationCode::new(params.code))
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Token exchange failed: {:?}", e),
            )
                .into_response()
        })
        .unwrap();

    let access_token = token_response.access_token();

    // 3. Fetch User Info from Google
    let client = reqwest::Client::new();
    let user_info_response = client
        .get(GOOGLE_USERINFO_URL)
        .bearer_auth(access_token.secret())
        .send()
        .await
        .unwrap();

    if !user_info_response.status().is_success() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Failed to fetch Google user info: {}",
                user_info_response.status()
            ),
        )
            .into_response();
    }

    let google_user: GoogleUserInfo = user_info_response.json().await.unwrap();

    // 4. Find or Create User in MongoDB
    let db = get_database(&state.db_client).unwrap();
    let user = find_or_create_user(&db, &google_user.sub, &google_user.email, &google_user.name)
        .await
        .unwrap();

    // 5. Create Session (Store User ID in Signed Cookie)
    let user_id_str = user
        .id
        .ok_or_else(|| ServerFnError::new("User ID missing after DB operation".to_string()))
        .unwrap()
        .to_hex(); // Convert ObjectId to hex string for cookie

    let mut session_cookie = Cookie::new(SESSION_COOKIE_NAME, user_id_str);
    setup_cookie(&mut session_cookie);
    session_cookie.set_max_age(tower_cookies::cookie::time::Duration::weeks(2)); // Example: 7 day session

    // Add signed cookie using the private jar derived from Cookies + Key
    cookies.private(&state.cookie_key).add(session_cookie);

    // 6. Redirect to Home Page
    Redirect::to("/").into_response()
}
