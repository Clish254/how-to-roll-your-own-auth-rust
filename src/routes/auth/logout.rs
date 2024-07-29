use axum::{
    extract::State,
    response::{IntoResponse, Redirect},
};

use crate::{errors::ApiError, startup::AppState};

use super::oauth::{AuthenticatedUser, User};

pub async fn logout(
    State(state): State<AppState>,
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

    Ok(Redirect::to("/"))
}
