use crate::error::MpcError;
use crate::state::AppState;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use types::{
    PutReaderRequest, PutReaderResponse, ReaderId, ToEnclaveRequest, ToEnclaveResponse,
    ToReaderRequest, ToReaderResponse,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/config", get(get_config_handler))
        .route("/v1/readers/{reader_id}", put(put_reader_handler))
        .route("/v1/operations/to-enclave", post(to_enclave_handler))
        .route("/v1/operations/to-reader", post(to_reader_handler))
        .with_state(state)
}

async fn get_config_handler(State(state): State<AppState>) -> Json<types::MpcConfigResponse> {
    Json(crate::service::get_config(&state))
}

async fn put_reader_handler(
    State(state): State<AppState>,
    Path(reader_id): Path<String>,
    MpcJson(request): MpcJson<PutReaderRequest>,
) -> Result<Json<PutReaderResponse>, MpcError> {
    let reader_id = parse_reader_id(&reader_id)?;
    crate::service::put_reader(&state, reader_id, request).map(Json)
}

async fn to_enclave_handler(
    State(state): State<AppState>,
    MpcJson(request): MpcJson<ToEnclaveRequest>,
) -> Result<Json<ToEnclaveResponse>, MpcError> {
    crate::service::to_enclave(&state, request).map(Json)
}

async fn to_reader_handler(
    State(state): State<AppState>,
    MpcJson(request): MpcJson<ToReaderRequest>,
) -> Result<Json<ToReaderResponse>, MpcError> {
    crate::service::to_reader(&state, request).map(Json)
}

struct MpcJson<T>(T);

impl<S, T> FromRequest<S> for MpcJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = MpcError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection| MpcError::BadRequest(rejection.body_text()))
    }
}

fn parse_reader_id(value: &str) -> Result<ReaderId, MpcError> {
    serde_json::from_value(serde_json::Value::String(value.to_string()))
        .map_err(|error| MpcError::BadRequest(format!("invalid reader_id path parameter: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::reader_id;
    use crate::state::AppState;
    use axum::body::{self, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use types::X25519PublicKey;

    #[tokio::test]
    async fn get_config_returns_json() {
        let app = router(AppState::local_deterministic_for_tests());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn put_reader_rejects_mismatched_path_id() {
        let app = router(AppState::local_deterministic_for_tests());
        let body = serde_json::json!({
            "reader_pubkey": "0x0808080808080808080808080808080808080808080808080808080808080808"
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/readers/0x1111111111111111111111111111111111111111111111111111111111111111")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn put_reader_registers_reader() {
        let reader_pubkey = X25519PublicKey([8; 32]);
        let expected_reader_id = reader_id(reader_pubkey);
        let path_reader_id = serde_json::to_value(expected_reader_id)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let app = router(AppState::local_deterministic_for_tests());
        let body = serde_json::json!({
            "reader_pubkey": "0x0808080808080808080808080808080808080808080808080808080808080808"
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/readers/{path_reader_id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "reader_id": path_reader_id,
            })
        );
    }

    #[tokio::test]
    async fn malformed_json_returns_bad_request_error_response() {
        let app = router(AppState::local_deterministic_for_tests());
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/readers/0x1111111111111111111111111111111111111111111111111111111111111111")
                    .header("content-type", "application/json")
                    .body(Body::from("{"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["code"], "bad_request");
    }
}
