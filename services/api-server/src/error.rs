use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub request_id: String,
}

impl ApiError {
    pub fn new(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            request_id: request_id.into(),
        }
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>, request_id: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message, request_id)
    }

    pub fn unauthorized(request_id: &str) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "authentication is required",
            request_id,
        )
    }

    pub fn forbidden(code: &'static str, message: impl Into<String>, request_id: &str) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message, request_id)
    }

    pub fn not_found(code: &'static str, message: impl Into<String>, request_id: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, code, message, request_id)
    }

    pub fn conflict(code: &'static str, message: impl Into<String>, request_id: &str) -> Self {
        Self::new(StatusCode::CONFLICT, code, message, request_id)
    }

    pub fn internal(request_id: &str) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "the request could not be completed",
            request_id,
        )
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
    request_id: &'a str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            code: self.code,
            message: &self.message,
            request_id: &self.request_id,
        };
        (self.status, Json(body)).into_response()
    }
}
