use axum::{
    extract::State,
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    PrivateCookieJar,
};
use time::{Duration, OffsetDateTime};

use crate::{errors::ApiError, startup::AppState};

use super::oauth::{AuthenticatedUser, User};

pub async fn logout(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    authenticated_user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    // we increment the refresh_token_version to invalidate existing ones
    let _user = sqlx::query_as::<_, User>(
        "
        UPDATE users
        SET refresh_token_version = refresh_token_version + 1
        WHERE id = ($1)
        RETURNING id, email, discord_id, refresh_token_version, created_at, last_updated
        ",
    )
    .bind(authenticated_user.id)
    .fetch_one(&state.db)
    .await?;

    let expired_access_token_cookie = Cookie::build(("access_token", ""))
        .same_site(SameSite::Strict)
        .path("/")
        .secure(state.is_prod)
        .http_only(true)
        .expires(OffsetDateTime::now_utc() - Duration::days(1));

    let expired_refresh_token_cookie = Cookie::build(("refresh_token", ""))
        .same_site(SameSite::Strict)
        .path("/")
        .secure(state.is_prod)
        .http_only(true)
        .expires(OffsetDateTime::now_utc() - Duration::days(1));

    // we set cookies with past expiration dates,
    // which should ensure they're removed on the client side.
    Ok((
        jar.remove("access_token")
            .add(expired_access_token_cookie)
            .remove("refresh_token")
            .add(expired_refresh_token_cookie),
        Redirect::to("/"),
    ))
}
