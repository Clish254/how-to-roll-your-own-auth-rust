use std::time::SystemTime;

use axum::{
    extract::{FromRequest, FromRequestParts, Query, Request, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthorizationCode, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse,
};
use time::Duration as TimeDuration;

use crate::errors::ApiError;
use crate::startup::AppState;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct DiscordCallbackRequest {
    code: String,
    state: String,
}

pub async fn discord_authorize(
    jar: PrivateCookieJar,
    Extension(oauth_client): Extension<BasicClient>,
) -> Result<impl IntoResponse, ApiError> {
    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_string()))
        .add_scope(Scope::new("email".to_string())) // enables /users/@me to return an email
        .set_pkce_challenge(pkce_challenge)
        .url();

    let csrf_cookie = Cookie::build(("csrf_token", csrf_token.secret().to_string()))
        .same_site(SameSite::None)
        //.secure(true)
        .http_only(true)
        .max_age(TimeDuration::seconds(120));
    let pkce_cookie = Cookie::build(("pkce_verifier", pkce_verifier.secret().to_string()))
        .same_site(SameSite::None)
        //.secure(true)
        .http_only(true)
        .max_age(TimeDuration::seconds(120));

    Ok((
        jar.add(csrf_cookie).add(pkce_cookie),
        Redirect::to(auth_url.as_str()),
    ))
}

pub async fn discord_callback(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(query): Query<DiscordCallbackRequest>,
    Extension(oauth_client): Extension<BasicClient>,
) -> Result<impl IntoResponse, ApiError> {
    // Retrieve the CSRF token and PKCE verifier from the cookies
    let csrf_cookie = jar
        .get("csrf_token")
        .map(|cookie| cookie.value().to_owned());
    let pkce_cookie = jar
        .get("pkce_verifier")
        .map(|cookie| cookie.value().to_owned());

    if csrf_cookie.is_none() {
        return Err(ApiError::InvalidCsrf);
    }
    if csrf_cookie.unwrap() != query.state {
        return Err(ApiError::InvalidCsrf);
    }
    if pkce_cookie.is_none() {
        return Err(ApiError::InvalidPkce);
    }
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code))
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_cookie.unwrap()))
        .request_async(async_http_client)
        .await?;

    let profile = state
        .ctx
        .get("https://discord.com/api/users/@me")
        .bearer_auth(token.access_token().secret().to_owned())
        .send()
        .await?;

    let profile = profile.json::<DiscordUserProfile>().await?;

    let access_token: String;
    let refresh_token: String;

    let user = sqlx::query_as::<_, User>(
        "
         SELECT id, email, discord_id, created_at, last_updated
         FROM users
         WHERE discord_id = $1",
    )
    .bind(profile.id.clone())
    .fetch_optional(&state.db)
    .await?;
    match user {
        Some(user) => {
            let (a_token, r_token) =
                generate_access_and_refresh_token(user.id.to_string().clone(), state.clone())?;
            access_token = a_token;
            refresh_token = r_token;
        }
        None => {
            let user = sqlx::query_as::<_, User>(
                "
                INSERT INTO users (email, discord_id)
                VALUES ($1, $2)
                RETURNING id, email, discord_id, created_at, last_updated
            ",
            )
            .bind(profile.email.clone())
            .bind(profile.id.clone())
            .fetch_one(&state.db)
            .await?;
            let (a_token, r_token) =
                generate_access_and_refresh_token(user.id.to_string().clone(), state.clone())?;
            access_token = a_token;
            refresh_token = r_token;
        }
    };

    let access_token_cookie = Cookie::build(("access_token", access_token))
        .same_site(SameSite::Strict)
        .path("/")
        //.secure(true)
        .http_only(true)
        .max_age(TimeDuration::seconds(900));

    let refresh_token_cookie = Cookie::build(("refresh_token", refresh_token))
        .same_site(SameSite::Strict)
        .path("/")
        //.secure(true)
        .http_only(true)
        .max_age(TimeDuration::seconds(2_592_000));

    Ok((
        jar.add(access_token_cookie).add(refresh_token_cookie),
        Redirect::to("/home"),
    ))
}

#[derive(Deserialize, Debug, Clone)]
struct DiscordUserProfile {
    id: String,
    email: String,
}

#[derive(Deserialize, Clone)]
pub struct AuthenticatedUser {
    pub id: i32,
}

#[derive(Serialize, Deserialize, sqlx::FromRow, Debug)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub discord_id: String,
    pub created_at: Option<DateTime<Utc>>,
    pub last_updated: Option<DateTime<Utc>>,
}

#[axum::async_trait]
impl FromRequest<AppState> for AuthenticatedUser {
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let state = state.to_owned();
        let (mut parts, _body) = req.into_parts();
        let cookiejar: PrivateCookieJar =
            PrivateCookieJar::from_request_parts(&mut parts, &state).await?;

        let Some(access_token_cookie) = cookiejar
            .get("access_token")
            .map(|cookie| cookie.value().to_owned())
        else {
            return Err(ApiError::Unauthorized);
        };

        let token_data = decode::<Claims>(
            &access_token_cookie,
            &Keys::new(&state.jwt_secrets.access_token.into_bytes()).decoding,
            &Validation::default(),
        )
        .map_err(|_| ApiError::Unauthorized)?;

        let user_id = token_data
            .claims
            .sub
            .parse::<i32>()
            .map_err(|_| ApiError::UserIdParseError)?;
        Ok(Self { id: user_id })
    }
}

pub async fn protected(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    let user = sqlx::query_as::<_, User>(
        r#"
                SELECT id, email, discord_id, created_at, last_updated
                FROM users
                WHERE id = $1
            "#,
    )
    .bind(authenticated_user.id)
    .fetch_one(&state.db)
    .await?;
    Ok((StatusCode::OK, Json(user)))
}

#[derive(Clone)]
pub struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

// the JWT claim
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub fn generate_access_and_refresh_token(
    user_id: String,
    app_state: AppState,
) -> Result<(String, String), ApiError> {
    // add 15 minutes to current unix epoch time as expiry date/time
    let access_token_exp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 900;

    let access_token_claims = Claims {
        sub: user_id.clone(),
        // Mandatory expiry time as UTC timestamp - takes unix epoch
        exp: usize::try_from(access_token_exp).unwrap(),
    };
    // Create the access token
    let access_token = encode(
        &Header::default(),
        &access_token_claims,
        &Keys::new(&app_state.jwt_secrets.access_token.into_bytes()).encoding,
    )
    .map_err(|_| ApiError::TokenCreation)?;

    // add 30 days to current unix epoch time as expiry date/time
    let refresh_token_exp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 2_592_000;

    let refresh_token_claims = Claims {
        sub: user_id,
        // Mandatory expiry time as UTC timestamp - takes unix epoch
        exp: usize::try_from(refresh_token_exp).unwrap(),
    };
    // Create the refresh token
    let refresh_token = encode(
        &Header::default(),
        &refresh_token_claims,
        &Keys::new(&app_state.jwt_secrets.refresh_token.into_bytes()).encoding,
    )
    .map_err(|_| ApiError::TokenCreation)?;
    Ok((access_token, refresh_token))
}
