//! API errors: static messages only (no echo of request content).
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    #[error("bad request")]
    BadRequest,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("gone")]
    Gone,
    #[error("payload too large")]
    TooLarge,
    #[error("rate limited")]
    RateLimited,
    #[error("queue full")]
    QueueFull,
    #[error("overloaded")]
    Overloaded,
    #[error("internal error")]
    Internal,
}

impl ApiError {
    pub fn status(self) -> StatusCode {
        match self {
            ApiError::BadRequest => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Conflict => StatusCode::CONFLICT,
            ApiError::Gone => StatusCode::GONE,
            ApiError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::RateLimited | ApiError::QueueFull => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Overloaded => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = format!("{{\"error\":\"{}\"}}", self);
        (self.status(), [("content-type", "application/json"), ("cache-control", "no-store")], body).into_response()
    }
}
