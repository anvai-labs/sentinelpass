//! Relay error types.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Relay server error types mapped to HTTP status codes.
#[derive(Debug)]
#[allow(dead_code)]
pub enum RelayError {
    /// 410: the endpoint's protocol generation was retired (v1 sync).
    Gone(String),
    Database(String),
    Auth(String),
    NotFound(String),
    Conflict(String),
    RateLimited,
    PayloadTooLarge,
    BadRequest(String),
    Internal(String),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gone(m) => write!(f, "Gone: {}", m),
            Self::Database(e) => write!(f, "Database error: {}", e),
            Self::Auth(e) => write!(f, "Auth error: {}", e),
            Self::NotFound(e) => write!(f, "Not found: {}", e),
            Self::Conflict(e) => write!(f, "Conflict: {}", e),
            Self::RateLimited => write!(f, "Rate limited"),
            Self::PayloadTooLarge => write!(f, "Payload too large"),
            Self::BadRequest(e) => write!(f, "Bad request: {}", e),
            Self::Internal(e) => write!(f, "Internal error: {}", e),
        }
    }
}

impl std::error::Error for RelayError {}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Gone(m) => (StatusCode::GONE, m.clone()),
            Self::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::Auth(e) => (StatusCode::UNAUTHORIZED, e.clone()),
            Self::NotFound(e) => (StatusCode::NOT_FOUND, e.clone()),
            Self::Conflict(e) => (StatusCode::CONFLICT, e.clone()),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()),
            Self::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Payload too large".to_string(),
            ),
            Self::BadRequest(e) => (StatusCode::BAD_REQUEST, e.clone()),
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        let body = serde_json::json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}

impl From<rusqlite::Error> for RelayError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e.to_string())
    }
}
