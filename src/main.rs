use rust_axum_auth::startup::{run, JwtSecrets, OauthCredentials};
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

    if option_env!("SHUTTLE") == Some("true") {
        println!("Running on Shuttle");
    } else {
        println!("Not running on Shuttle or SHUTTLE env var not set");
    }
    let jwt_secrets = JwtSecrets {
        access_token: secrets.get("ACCESS_TOKEN_SECRET").unwrap(),
        refresh_token: secrets.get("REFRESH_TOKEN_SECRET").unwrap(),
    };
    let oauth_credentials = OauthCredentials {
        oauth_id: secrets.get("DISCORD_OAUTH_CLIENT_ID").unwrap(),
        oauth_secret: secrets.get("DISCORD_OAUTH_CLIENT_SECRET").unwrap(),
    };
    run(jwt_secrets, oauth_credentials, db)
}
