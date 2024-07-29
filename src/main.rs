use axum::{extract::FromRef, routing::get, Extension, Router};
use axum_extra::extract::cookie::Key;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use reqwest::Client;
use shuttle_runtime::SecretStore;
use sqlx::PgPool;
use view::{home, landing};

pub mod errors;
pub mod oauth;
pub mod view;

#[derive(Clone)]
pub struct JwtSecrets {
    access_token: String,
    refresh_token: String,
}

#[derive(Clone)]
pub struct AppState {
    db: PgPool,
    ctx: Client,
    key: Key,
    jwt_secrets: JwtSecrets,
}

// this impl tells `SignedCookieJar` how to access the key from our state
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

#[shuttle_runtime::main]
async fn main(
    #[shuttle_shared_db::Postgres] db: PgPool,
    #[shuttle_runtime::Secrets] secrets: SecretStore,
) -> shuttle_axum::ShuttleAxum {
    sqlx::migrate!()
        .run(&db)
        .await
        .expect("Failed to run migrations");

    let oauth_id = secrets.get("DISCORD_OAUTH_CLIENT_ID").unwrap();
    let oauth_secret = secrets.get("DISCORD_OAUTH_CLIENT_SECRET").unwrap();
    let access_token_secret = secrets.get("ACCESS_TOKEN_SECRET").unwrap();
    let refresh_token_secret = secrets.get("REFRESH_TOKEN_SECRET").unwrap();
    let jwt_secrets = JwtSecrets {
        access_token: access_token_secret,
        refresh_token: refresh_token_secret,
    };

    let ctx = Client::new();

    let state = AppState {
        db,
        ctx,
        key: Key::generate(),
        jwt_secrets,
    };

    let oauth_client = build_oauth_client(oauth_id.clone(), oauth_secret);

    let router = init_router(state, oauth_client);

    Ok(router.into())
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
