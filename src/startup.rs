use axum::{extract::FromRef, routing::get, Extension, Router};
use axum_extra::extract::cookie::Key;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use reqwest::Client;
use shuttle_axum::ShuttleAxum;
use sqlx::PgPool;

use crate::routes::{
    auth::oauth,
    view::{home, landing},
};

#[derive(Clone)]
pub struct JwtSecrets {
    pub access_token: String,
    pub refresh_token: String,
}

// this impl tells `SignedCookieJar` how to access the key from our state
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub ctx: Client,
    // All cookies will be private and encrypted with a Key.
    // This makes it suitable for storing private data.
    pub key: Key,
    pub jwt_secrets: JwtSecrets,
}

fn init_router(state: AppState, oauth_client: BasicClient) -> Router {
    let discord_auth_router = Router::new()
        .route("/authorize", get(oauth::discord_authorize))
        .route("/callback", get(oauth::discord_callback));

    let protected_router = Router::new().route("/", get(oauth::protected));

    let view_router = Router::new()
        .route("/", get(landing))
        .route("/home", get(home));

    Router::new()
        .nest("/api/auth/discord", discord_auth_router)
        .nest("/protected", protected_router)
        .nest("/", view_router)
        .layer(Extension(oauth_client))
        .with_state(state)
}

fn build_oauth_client(client_id: String, client_secret: String) -> BasicClient {
    let redirect_url = "http://localhost:8000/api/auth/discord/callback".to_string();

    let auth_url = AuthUrl::new("https://discord.com/oauth2/authorize".to_string())
        .expect("Invalid discord authorization endpoint URL");
    let token_url = TokenUrl::new("https://discord.com/api/oauth2/token".to_string())
        .expect("Invalid discord token endpoint URL");

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
}

pub struct OauthCredentials {
    pub oauth_id: String,
    pub oauth_secret: String,
}

pub fn run(
    jwt_secrets: JwtSecrets,
    oauth_credentials: OauthCredentials,
    db: PgPool,
) -> ShuttleAxum {
    let ctx = Client::new();

    let state = AppState {
        db,
        ctx,
        key: Key::generate(),
        jwt_secrets,
    };

    let oauth_client =
        build_oauth_client(oauth_credentials.oauth_id, oauth_credentials.oauth_secret);

    let router = init_router(state, oauth_client);

    Ok(router.into())
}
