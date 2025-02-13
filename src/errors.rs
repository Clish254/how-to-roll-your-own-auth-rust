use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("SQL error: {0}")]
    SQL(#[from] sqlx::Error),
    #[error("HTTP request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("OAuth token error: {0}")]
    TokenError(
        #[from]
        oauth2::RequestTokenError<
            oauth2::reqwest::Error<reqwest::Error>,
            oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
        >,
    ),
    #[error("You're not authorized!")]
    Unauthorized,
    #[error("Attempted to get a non-none value but found none")]
    OptionError,
    #[error("Attempted to parse a number to an integer but errored out: {0}")]
    ParseIntError(#[from] std::num::TryFromIntError),
    #[error("Attempted to parse user_id to number but errored out")]
    UserIdParseError,
    #[error("Encountered an error trying to convert an infallible value: {0}")]
    FromRequestPartsError(#[from] std::convert::Infallible),
    #[error("Error creating access tokens")]
    TokenCreation,
    #[error("Missing or invalid csrf token")]
    InvalidCsrf,
    #[error("Missing or invalid pkce verifier")]
    InvalidPkce,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let response = match self {
            Self::SQL(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::Request(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::TokenError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized!".to_string()),
            Self::OptionError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Attempted to get a non-none value but found none".to_string(),
            ),
            Self::ParseIntError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::FromRequestPartsError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::TokenCreation => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error creating access tokens".to_string(),
            ),
            Self::InvalidCsrf => (
                StatusCode::BAD_REQUEST,
                "Missing or invalid csrf token".to_string(),
            ),
            Self::InvalidPkce => (
                StatusCode::BAD_REQUEST,
                "Missing or invalid pkce verifier".to_string(),
            ),
            Self::UserIdParseError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Attempted to parse user_id to number but errored out".to_string(),
            ),
        };

        response.into_response()
    }
}
