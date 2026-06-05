use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[derive(Debug, thiserror::Error)]
pub enum MpcError {
    #[error("malformed request: {0}")]
    BadRequest(String),
    #[error("authorization failed: {0}")]
    Forbidden(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid request binding: {0}")]
    Unprocessable(String),
    #[error("backend unavailable: {0}")]
    Unavailable(String),
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}

impl MpcError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Forbidden(_) => "forbidden",
            Self::NotFound(_) => "not_found",
            Self::Conflict(_) => "conflict",
            Self::Unprocessable(_) => "unprocessable",
            Self::Unavailable(_) => "unavailable",
        }
    }
}

impl From<codec::CodecError> for MpcError {
    fn from(error: codec::CodecError) -> Self {
        match error {
            codec::CodecError::BadRequest(message) => Self::BadRequest(message),
            codec::CodecError::Unprocessable(message) => Self::Unprocessable(message),
        }
    }
}

impl From<crypto::CryptoError> for MpcError {
    fn from(error: crypto::CryptoError) -> Self {
        match error {
            crypto::CryptoError::BadRequest(message) => Self::BadRequest(message),
            crypto::CryptoError::Unprocessable(message) => Self::Unprocessable(message),
        }
    }
}

impl IntoResponse for MpcError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = ErrorResponse {
            code: self.code().to_string(),
            message: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body, http::StatusCode, response::IntoResponse};

    #[test]
    fn status_code_maps_domain_errors() {
        assert_eq!(
            MpcError::BadRequest("bad json".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            MpcError::Forbidden("reader".to_string()).status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            MpcError::NotFound("key".to_string()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            MpcError::Conflict("reader exists".to_string()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            MpcError::Unprocessable("binding".to_string()).status_code(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            MpcError::Unavailable("backend".to_string()).status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn code_maps_domain_errors() {
        assert_eq!(
            MpcError::BadRequest("bad json".to_string()).code(),
            "bad_request"
        );
        assert_eq!(
            MpcError::Forbidden("reader".to_string()).code(),
            "forbidden"
        );
        assert_eq!(MpcError::NotFound("key".to_string()).code(), "not_found");
        assert_eq!(
            MpcError::Conflict("reader exists".to_string()).code(),
            "conflict"
        );
        assert_eq!(
            MpcError::Unprocessable("binding".to_string()).code(),
            "unprocessable"
        );
        assert_eq!(
            MpcError::Unavailable("backend".to_string()).code(),
            "unavailable"
        );
    }

    #[tokio::test]
    async fn error_response_uses_status_code_and_json_body() {
        let response = MpcError::Unprocessable("request id mismatch".to_string()).into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(
            body,
            serde_json::json!({
                "code": "unprocessable",
                "message": "invalid request binding: request id mismatch",
            })
        );
    }
}
