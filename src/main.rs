use rust_axum_auth::startup::{run, AppSecrets, OauthCredentials};
use shuttle_runtime::SecretStore;
use sqlx::PgPool;

#[shuttle_runtime::main]
async fn main(
    #[shuttle_shared_db::Postgres] db: PgPool,
    #[shuttle_runtime::Secrets] secrets: SecretStore,
) -> shuttle_axum::ShuttleAxum {
    sqlx::migrate!()
        .run(&db)
        .await
        .expect("Failed to run migrations");

    let is_prod = option_env!("SHUTTLE").is_some();
    if is_prod {
        println!("Running on Shuttle");
    } else {
        println!("Not running on Shuttle or SHUTTLE env var not set");
    }

    let cookie_key = secrets.get("COOKIE_KEY").unwrap();
    let key_bytes: Vec<u8> = cookie_key.into_bytes();
    let app_secrets = AppSecrets {
        access_token: secrets.get("ACCESS_TOKEN_SECRET").unwrap(),
        refresh_token: secrets.get("REFRESH_TOKEN_SECRET").unwrap(),
        cookie_key: key_bytes,
    };
    let oauth_credentials = OauthCredentials {
        oauth_id: secrets.get("DISCORD_OAUTH_CLIENT_ID").unwrap(),
        oauth_secret: secrets.get("DISCORD_OAUTH_CLIENT_SECRET").unwrap(),
    };
    run(app_secrets, oauth_credentials, db, is_prod)
}
