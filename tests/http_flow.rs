use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, Response, StatusCode};
use codec::{Aad, AadKind, PlaintextCodec, SystemHandleAadV1, SystemInputAadV1};
use mpc::api::router;
use mpc::attestation::LocalAttestationVerifier;
use mpc::crypto::{
    HpkeKeypair, open_enclave_ciphertext_for_tests, open_reader_ciphertext_for_tests, reader_id,
    seal_system_ciphertext,
};
use mpc::state::AppState;
use serde::de::DeserializeOwned;
use tower::ServiceExt;
use types::*;

fn json_request<T: serde::Serialize>(
    method: Method,
    uri: impl AsRef<str>,
    body: &T,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri.as_ref())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

async fn read_json<T: DeserializeOwned>(response: Response<Body>) -> T {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn assert_error(response: Response<Body>, expected_status: StatusCode, expected_code: &str) {
    assert_eq!(response.status(), expected_status);
    let body: serde_json::Value = read_json(response).await;
    assert_eq!(body["code"], expected_code);
    assert!(body["message"].is_string());
}

async fn send(app: &Router, request: Request<Body>) -> Response<Body> {
    app.clone().oneshot(request).await.unwrap()
}

fn reader_id_path(id: ReaderId) -> String {
    serde_json::to_value(id)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

async fn register_reader(app: &Router, reader: &HpkeKeypair) -> ReaderId {
    let id = reader_id(reader.public_key);
    let response = send(
        app,
        json_request(
            Method::PUT,
            format!("/v1/readers/{}", reader_id_path(id)),
            &PutReaderRequest {
                reader_pubkey: reader.public_key,
            },
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: PutReaderResponse = read_json(response).await;
    assert_eq!(body.reader_id, id);
    id
}

fn system_handle_ciphertext(
    state: &AppState,
    handle_id: HandleId,
    plaintext_value: [u8; 32],
) -> (SystemCiphertextV1, Vec<u8>) {
    let aad = SystemHandleAadV1 {
        version: 1,
        kind: AadKind::SystemHandle,
        chain_id: state.config().chain_id,
        domain_id: state.config().domain_id,
        handle_id,
        type_tag: "suint256".to_string(),
        key_id: state.config().key_id,
    };
    let plaintext = PlaintextCodec::encode_suint256(plaintext_value).unwrap();
    let ciphertext = seal_system_ciphertext(
        &state.config().hpke_public_key,
        state.config().key_id,
        &Aad::SystemHandle(aad),
        &plaintext,
    )
    .unwrap();

    (ciphertext, plaintext)
}

fn system_input_ciphertext(
    state: &AppState,
    plaintext_value: [u8; 32],
) -> (SystemCiphertextV1, Vec<u8>) {
    let aad = SystemInputAadV1 {
        version: 1,
        kind: AadKind::SystemInput,
        chain_id: state.config().chain_id,
        domain_id: state.config().domain_id,
        contract: Address([0x55; 20]),
        type_tag: "suint256".to_string(),
        key_id: state.config().key_id,
    };
    let plaintext = PlaintextCodec::encode_suint256(plaintext_value).unwrap();
    let ciphertext = seal_system_ciphertext(
        &state.config().hpke_public_key,
        state.config().key_id,
        &Aad::SystemInput(aad),
        &plaintext,
    )
    .unwrap();

    (ciphertext, plaintext)
}

#[tokio::test]
async fn full_reader_flow_through_http() {
    let state = AppState::local_deterministic_for_tests();
    let app = router(state.clone());

    let response = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/v1/config")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let config: MpcConfigResponse = read_json(response).await;
    assert_eq!(config, state.config_response());

    let reader = HpkeKeypair::from_seed_for_tests([10; 32]);
    let reader_id = register_reader(&app, &reader).await;
    let handle_id = HandleId([0x44; 32]);
    let (system_ciphertext, plaintext) = system_handle_ciphertext(&state, handle_id, [0x99; 32]);

    let response = send(
        &app,
        json_request(
            Method::POST,
            "/v1/operations/to-reader",
            &ToReaderRequest {
                request_id: RequestId([0x66; 32]),
                chain_id: state.config().chain_id,
                handle_id,
                reader_id,
                system_ciphertext,
            },
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: ToReaderResponse = read_json(response).await;
    assert_eq!(
        open_reader_ciphertext_for_tests(&reader, &body.ciphertext).unwrap(),
        plaintext
    );
}

#[tokio::test]
async fn full_enclave_flow_through_http() {
    let state = AppState::local_deterministic_for_tests();
    let app = router(state.clone());
    let enclave = HpkeKeypair::from_seed_for_tests([11; 32]);
    let measurement = state.config().approved_enclave_measurement;
    let handle_id = HandleId([0x44; 32]);
    let (system_ciphertext, plaintext) = system_input_ciphertext(&state, [0xaa; 32]);

    let response = send(
        &app,
        json_request(
            Method::POST,
            "/v1/operations/to-enclave",
            &ToEnclaveRequest {
                request_id: RequestId([0x77; 32]),
                chain_id: state.config().chain_id,
                handle_id,
                enclave_pubkey: enclave.public_key,
                measurement,
                attestation: LocalAttestationVerifier::attestation_for_tests(
                    enclave.public_key,
                    measurement,
                ),
                system_ciphertext,
            },
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: ToEnclaveResponse = read_json(response).await;
    assert_eq!(
        open_enclave_ciphertext_for_tests(&enclave, &body.ciphertext).unwrap(),
        plaintext
    );
}

#[tokio::test]
async fn malformed_json_body_on_reader_registration_returns_bad_request() {
    let state = AppState::local_deterministic_for_tests();
    let app = router(state);
    let reader_id = ReaderId([0x11; 32]);
    let response = send(
        &app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/readers/{}", reader_id_path(reader_id)))
            .header("content-type", "application/json")
            .body(Body::from("{"))
            .unwrap(),
    )
    .await;

    assert_error(response, StatusCode::BAD_REQUEST, "bad_request").await;
}

#[tokio::test]
async fn unknown_reader_on_to_reader_returns_not_found() {
    let state = AppState::local_deterministic_for_tests();
    let app = router(state.clone());
    let handle_id = HandleId([0x44; 32]);
    let (system_ciphertext, _) = system_handle_ciphertext(&state, handle_id, [0x99; 32]);

    let response = send(
        &app,
        json_request(
            Method::POST,
            "/v1/operations/to-reader",
            &ToReaderRequest {
                request_id: RequestId([0x66; 32]),
                chain_id: state.config().chain_id,
                handle_id,
                reader_id: ReaderId([0x88; 32]),
                system_ciphertext,
            },
        ),
    )
    .await;

    assert_error(response, StatusCode::NOT_FOUND, "not_found").await;
}

#[tokio::test]
async fn reader_id_mismatch_on_registration_returns_conflict() {
    let state = AppState::local_deterministic_for_tests();
    let app = router(state);
    let reader = HpkeKeypair::from_seed_for_tests([10; 32]);
    let mismatched_reader_id = ReaderId([0x11; 32]);

    let response = send(
        &app,
        json_request(
            Method::PUT,
            format!("/v1/readers/{}", reader_id_path(mismatched_reader_id)),
            &PutReaderRequest {
                reader_pubkey: reader.public_key,
            },
        ),
    )
    .await;

    assert_error(response, StatusCode::CONFLICT, "conflict").await;
}

#[tokio::test]
async fn wrong_handle_id_on_to_reader_returns_unprocessable() {
    let state = AppState::local_deterministic_for_tests();
    let app = router(state.clone());
    let reader = HpkeKeypair::from_seed_for_tests([10; 32]);
    let reader_id = register_reader(&app, &reader).await;
    let handle_id = HandleId([0x44; 32]);
    let (system_ciphertext, _) = system_handle_ciphertext(&state, handle_id, [0x99; 32]);

    let response = send(
        &app,
        json_request(
            Method::POST,
            "/v1/operations/to-reader",
            &ToReaderRequest {
                request_id: RequestId([0x66; 32]),
                chain_id: state.config().chain_id,
                handle_id: HandleId([0x45; 32]),
                reader_id,
                system_ciphertext,
            },
        ),
    )
    .await;

    assert_error(response, StatusCode::UNPROCESSABLE_ENTITY, "unprocessable").await;
}

#[tokio::test]
async fn malformed_system_aad_on_to_reader_returns_bad_request() {
    let state = AppState::local_deterministic_for_tests();
    let app = router(state.clone());
    let reader = HpkeKeypair::from_seed_for_tests([10; 32]);
    let reader_id = register_reader(&app, &reader).await;
    let handle_id = HandleId([0x44; 32]);
    let (mut system_ciphertext, _) = system_handle_ciphertext(&state, handle_id, [0x99; 32]);
    system_ciphertext.aad = PayloadBytes(vec![0xff]);

    let response = send(
        &app,
        json_request(
            Method::POST,
            "/v1/operations/to-reader",
            &ToReaderRequest {
                request_id: RequestId([0x66; 32]),
                chain_id: state.config().chain_id,
                handle_id,
                reader_id,
                system_ciphertext,
            },
        ),
    )
    .await;

    assert_error(response, StatusCode::BAD_REQUEST, "bad_request").await;
}

#[tokio::test]
async fn wrong_enclave_measurement_on_to_enclave_returns_forbidden() {
    let state = AppState::local_deterministic_for_tests();
    let app = router(state.clone());
    let enclave = HpkeKeypair::from_seed_for_tests([11; 32]);
    let wrong_measurement = EnclaveMeasurement([0x34; 32]);
    let handle_id = HandleId([0x44; 32]);
    let (system_ciphertext, _) = system_handle_ciphertext(&state, handle_id, [0xaa; 32]);

    let response = send(
        &app,
        json_request(
            Method::POST,
            "/v1/operations/to-enclave",
            &ToEnclaveRequest {
                request_id: RequestId([0x77; 32]),
                chain_id: state.config().chain_id,
                handle_id,
                enclave_pubkey: enclave.public_key,
                measurement: wrong_measurement,
                attestation: LocalAttestationVerifier::attestation_for_tests(
                    enclave.public_key,
                    wrong_measurement,
                ),
                system_ciphertext,
            },
        ),
    )
    .await;

    assert_error(response, StatusCode::FORBIDDEN, "forbidden").await;
}
