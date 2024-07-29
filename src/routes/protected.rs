use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use crate::{errors::ApiError, startup::AppState};

use super::auth::oauth::{AuthenticatedUser, User};

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
