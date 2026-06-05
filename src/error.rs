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
}

impl IntoResponse for MpcError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = match status.as_u16() {
            400 => "bad_request",
            403 => "forbidden",
            404 => "not_found",
            409 => "conflict",
            422 => "unprocessable",
            503 => "unavailable",
            _ => "error",
        };
        let body = ErrorResponse {
            code: code.to_string(),
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
