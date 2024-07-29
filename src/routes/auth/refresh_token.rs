use axum::{
    extract::{FromRequest, FromRequestParts, Request, State},
    response::IntoResponse,
    Json,
};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use jsonwebtoken::{decode, Validation};
use time::Duration as TimeDuration;

use crate::errors::ApiError;
use crate::startup::AppState;
use serde::{Deserialize, Serialize};

use super::oauth::{generate_access_and_refresh_token, Keys, RefreshTokenClaims, User};

pub async fn refresh_tokens(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    authenticated_user: RefreshUser,
) -> Result<impl IntoResponse, ApiError> {
    let (access_token, refresh_token) =
        generate_access_and_refresh_token(authenticated_user.id, state.clone()).await?;
    let access_token_cookie = Cookie::build(("access_token", access_token.clone()))
        .same_site(SameSite::Strict)
        .path("/")
        //.secure(true)
        .http_only(true)
        .max_age(TimeDuration::seconds(900));

    let refresh_token_cookie = Cookie::build(("refresh_token", refresh_token.clone()))
        .same_site(SameSite::Strict)
        .path("/")
        //.secure(true)
        .http_only(true)
        .max_age(TimeDuration::seconds(2_592_000));

    let tokens = TokensResponse {
        access_token,
        refresh_token,
    };
    Ok((
        jar.add(access_token_cookie).add(refresh_token_cookie),
        Json(tokens),
    ))
}

#[derive(Deserialize, Serialize, Debug)]
pub struct TokensResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Deserialize, Clone)]
pub struct RefreshUser {
    pub id: i32,
}

#[axum::async_trait]
impl FromRequest<AppState> for RefreshUser {
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let state = state.to_owned();
        let (mut parts, _body) = req.into_parts();
        let cookiejar: PrivateCookieJar =
            PrivateCookieJar::from_request_parts(&mut parts, &state).await?;

        let Some(refresh_token_cookie) = cookiejar
            .get("refresh_token")
            .map(|cookie| cookie.value().to_owned())
        else {
            return Err(ApiError::Unauthorized);
        };

        let token_data = decode::<RefreshTokenClaims>(
            &refresh_token_cookie,
            &Keys::new(&state.jwt_secrets.refresh_token.into_bytes()).decoding,
            &Validation::default(),
        )
        .map_err(|_| ApiError::Unauthorized)?;

        let user_id = token_data.claims.sub;
        let user = sqlx::query_as::<_, User>(
            "
         SELECT id, email, discord_id, created_at, last_updated
         FROM users
         WHERE discord_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;

        match user {
            Some(user) => {
                if user.refresh_token_version != token_data.claims.refresh_token_version {
                    return Err(ApiError::Unauthorized);
                }
            }
            None => {
                return Err(ApiError::Unauthorized);
            }
        };
        Ok(Self { id: user_id })
    }
}
