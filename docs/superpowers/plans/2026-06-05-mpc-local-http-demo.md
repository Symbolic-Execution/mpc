# MPC Local HTTP Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local Rust MPC HTTP service that matches the approved MPC spec, uses real cryptography, and proves `SystemCiphertextV1` can be transformed to reader and enclave ciphertexts through HTTP.

**Architecture:** Implement a library crate with focused modules for types, AAD encoding, crypto, attestation, state, service logic, and Axum routes. Keep runtime state in memory, keep attestation behind a trait, and drive all behavior through unit and HTTP integration tests.

**Tech Stack:** Rust 2024, Axum 0.8, Tokio 1, Serde, Ciborium 0.2, HPKE 0.13, AES-GCM 0.10, SHA3 Keccak-256, base64url, hex, thiserror, tower.

---

## File Structure

- Create `src/lib.rs`: module declarations and public test helper exports.
- Modify `src/main.rs`: parse simple runtime config, build app state, and run Axum server.
- Modify `Cargo.toml`: add runtime, crypto, encoding, testing, and error dependencies.
- Create `src/types.rs`: fixed-size byte newtypes, serde helpers, enums, ciphertext envelopes, request/response DTOs.
- Create `src/error.rs`: `MpcError`, `ErrorResponse`, HTTP status mapping.
- Create `src/aad.rs`: canonical CBOR fixed-array AAD encoding/decoding and source AAD enum.
- Create `src/crypto.rs`: Keccak helpers, HPKE open/seal, system ciphertext open/seal helpers, plaintext encoding helpers.
- Create `src/attestation.rs`: `AttestationVerifier` trait and deterministic local verifier.
- Create `src/state.rs`: `MpcConfig`, in-memory reader registry, app state constructor.
- Create `src/service.rs`: endpoint orchestration and validation order.
- Create `src/api.rs`: Axum router and handler functions.
- Create `tests/http_flow.rs`: end-to-end HTTP tests for config, readers, transforms, and error cases.

## Dependency Baseline

Use these `Cargo.toml` dependencies:

```toml
[dependencies]
aes-gcm = "0.10.3"
async-trait = "0.1"
axum = "0.8.4"
base64 = "0.22.1"
ciborium = "0.2.2"
hex = "0.4"
hpke = { version = "0.13.0", features = ["std", "x25519"] }
rand = "0.8"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha3 = "0.10"
thiserror = "2"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net", "signal"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[dev-dependencies]
tower = { version = "0.5", features = ["util"] }
```

---

### Task 1: Crate Dependencies And Module Skeleton

**Files:**
- Modify: `Cargo.toml`
- Create: `src/lib.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Add dependencies**

Replace the empty `[dependencies]` section with the dependency baseline above.

- [ ] **Step 2: Create the library module skeleton**

Create `src/lib.rs`:

```rust
pub mod aad;
pub mod api;
pub mod attestation;
pub mod crypto;
pub mod error;
pub mod service;
pub mod state;
pub mod types;
```

- [ ] **Step 3: Replace the hello-world binary with a minimal async entrypoint**

Change `src/main.rs` to compile against modules that later tasks will fill:

```rust
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let addr: SocketAddr = std::env::var("MPC_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_string())
        .parse()
        .expect("MPC_BIND_ADDR must be a socket address");

    let state = mpc::state::AppState::local_ephemeral();
    let app = mpc::api::router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind MPC HTTP listener");

    tracing::info!(%addr, "starting MPC HTTP service");
    axum::serve(listener, app)
        .await
        .expect("run MPC HTTP service");
}
```

- [ ] **Step 4: Run check and record expected missing modules**

Run: `cargo check`

Expected: FAIL with unresolved module files such as `file not found for module 'aad'`.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/lib.rs src/main.rs
git commit -m "chore: add MPC crate skeleton"
```

---

### Task 1.5: Compile Scaffold For Declared Modules

**Files:**
- Create: `src/aad.rs`
- Create: `src/api.rs`
- Create: `src/attestation.rs`
- Create: `src/crypto.rs`
- Create: `src/error.rs`
- Create: `src/service.rs`
- Create: `src/state.rs`
- Create: `src/types.rs`

This task repairs the execution baseline after Task 1. `src/lib.rs` declares
all planned modules and `src/main.rs` references `api::router` and
`state::AppState`, so the crate needs minimal module files before later TDD
tasks can compile and run targeted tests.

- [ ] **Step 1: Add empty future modules**

Create empty files:

```text
src/aad.rs
src/attestation.rs
src/crypto.rs
src/error.rs
src/service.rs
src/types.rs
```

- [ ] **Step 2: Add minimal state scaffold**

Create `src/state.rs`:

```rust
#[derive(Clone, Debug, Default)]
pub struct AppState;

impl AppState {
    pub fn local_ephemeral() -> Self {
        Self
    }
}
```

- [ ] **Step 3: Add minimal API scaffold**

Create `src/api.rs`:

```rust
pub fn router(_state: crate::state::AppState) -> axum::Router {
    axum::Router::new()
}
```

- [ ] **Step 4: Run compile check**

Run: `cargo check --locked`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/plans/2026-06-05-mpc-local-http-demo.md src/aad.rs src/api.rs src/attestation.rs src/crypto.rs src/error.rs src/service.rs src/state.rs src/types.rs
git commit -m "chore: add compile scaffold for MPC modules"
```

---

### Task 2: Fixed Bytes, Serde, DTOs, And Errors

**Files:**
- Modify: `src/types.rs`
- Modify: `src/error.rs`
- Test: unit tests inside `src/types.rs` and `src/error.rs`

- [ ] **Step 1: Write fixed-byte serde tests**

Add tests in `src/types.rs` for `0x`-prefixed hex control-plane bytes and base64url payload bytes:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes32_json_uses_lowercase_0x_hex() {
        let value = Bytes32([0xab; 32]);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(
            json,
            "\"0xabababababababababababababababababababababababababababababababab\""
        );
        let decoded: Bytes32 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn payload_bytes_json_use_base64url_without_padding() {
        let value = PayloadBytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, "\"3q2-7w\"");
        let decoded: PayloadBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, value);
    }
}
```

- [ ] **Step 2: Implement fixed-size newtypes and payload serde**

Define these public types in `src/types.rs`:

```rust
pub type Address = FixedBytes<20>;
pub type Bytes32 = FixedBytes<32>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

pub type DomainId = Bytes32;
pub type KeyId = Bytes32;
pub type RequestId = Bytes32;
pub type ReaderId = Bytes32;
pub type HandleId = Bytes32;
pub type EnclaveMeasurement = Bytes32;
pub type AttestationDigest = Bytes32;
pub type X25519PublicKey = FixedBytes<32>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadBytes(pub Vec<u8>);
```

Implement `Serialize` and `Deserialize` for `FixedBytes<N>` as lowercase `0x`
hex with exact byte length. Implement `Serialize` and `Deserialize` for
`PayloadBytes` and `Attestation` as base64url without padding.

- [ ] **Step 3: Add API enums, ciphertext envelopes, and DTOs**

In `src/types.rs`, define the spec DTOs:

```rust
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ReaderKeyAlgorithm {
    X25519,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum CiphertextSuite {
    HpkeX25519HkdfSha256Aes256Gcm,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct MpcConfigResponse {
    pub version: u16,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub key_id: KeyId,
    pub hpke_public_key: X25519PublicKey,
    pub reader_key_algorithm: ReaderKeyAlgorithm,
    pub ciphertext_suite: CiphertextSuite,
    pub approved_enclave_measurement: EnclaveMeasurement,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PutReaderRequest {
    pub reader_pubkey: X25519PublicKey,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PutReaderResponse {
    pub reader_id: ReaderId,
}
```

Also define `SystemCiphertextV1`, `EnclaveCiphertextV1`, `ReaderCiphertextV1`,
`ToEnclaveRequest`, `ToEnclaveResponse`, `ToReaderRequest`, and
`ToReaderResponse` with field names matching `../spec/mpc/mpc-api.md`.
Use `PayloadBytes` for `enc`, `wrapped_key`, `ciphertext`, and `aad`.

- [ ] **Step 4: Implement domain errors**

Create `src/error.rs`:

```rust
use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};

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
```

- [ ] **Step 5: Run tests**

Run: `cargo test bytes32_json_uses_lowercase_0x_hex payload_bytes_json_use_base64url_without_padding`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/types.rs src/error.rs
git commit -m "feat: add MPC API types and errors"
```

---

### Task 3: Canonical CBOR AAD Encoding

**Files:**
- Create: `src/aad.rs`
- Modify: `src/types.rs` if constructors are needed
- Test: unit tests inside `src/aad.rs`

- [ ] **Step 1: Write AAD round-trip tests**

Add tests for each AAD variant:

```rust
#[test]
fn system_handle_aad_round_trips_as_fixed_array() {
    let aad = SystemHandleAadV1 {
        version: 1,
        chain_id: 31337,
        domain_id: Bytes32([0x11; 32]),
        handle_id: Bytes32([0x22; 32]),
        type_tag: "suint256".to_string(),
        key_id: Bytes32([0x33; 32]),
    };

    let encoded = encode_aad(&Aad::SystemHandle(aad.clone())).unwrap();
    assert_eq!(encoded[0], 0x87);
    let decoded = decode_source_aad(&encoded).unwrap();
    assert_eq!(decoded, SourceAad::SystemHandle(aad));
}
```

Repeat with:

- `SystemInputAadV1`, expecting first byte `0x87`
- `EnclaveAadV1`, expecting first byte `0x89`
- `ReaderAadV1`, expecting first byte `0x89`

- [ ] **Step 2: Implement AAD types and kind parsing**

Create `src/aad.rs` with:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AadKind {
    SystemInput = 1,
    SystemHandle = 2,
    Enclave = 3,
    Reader = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemInputAadV1 {
    pub version: u8,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub contract: Address,
    pub type_tag: String,
    pub key_id: KeyId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemHandleAadV1 {
    pub version: u8,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub handle_id: HandleId,
    pub type_tag: String,
    pub key_id: KeyId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnclaveAadV1 {
    pub version: u8,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub request_id: RequestId,
    pub handle_id: HandleId,
    pub type_tag: String,
    pub attestation_digest: AttestationDigest,
    pub key_id: KeyId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderAadV1 {
    pub version: u8,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub request_id: RequestId,
    pub handle_id: HandleId,
    pub reader_id: ReaderId,
    pub type_tag: String,
    pub key_id: KeyId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Aad {
    SystemInput(SystemInputAadV1),
    SystemHandle(SystemHandleAadV1),
    Enclave(EnclaveAadV1),
    Reader(ReaderAadV1),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceAad {
    SystemInput(SystemInputAadV1),
    SystemHandle(SystemHandleAadV1),
}
```

Do not encode structs as maps.

- [ ] **Step 3: Implement canonical array encode/decode**

Implement these functions:

```rust
pub fn encode_aad(aad: &Aad) -> Result<Vec<u8>, MpcError>;
pub fn decode_source_aad(bytes: &[u8]) -> Result<SourceAad, MpcError>;
pub fn decode_reader_aad(bytes: &[u8]) -> Result<ReaderAadV1, MpcError>;
pub fn decode_enclave_aad(bytes: &[u8]) -> Result<EnclaveAadV1, MpcError>;
```

Use `ciborium::value::Value` arrays and reject:

- map-encoded AAD
- unsupported `version`
- unsupported `kind`
- wrong array length
- wrong byte-string lengths
- non-text `type_tag`

- [ ] **Step 4: Run AAD tests**

Run: `cargo test aad::`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aad.rs src/types.rs
git commit -m "feat: add canonical AAD encoding"
```

---

### Task 4: Crypto Core And Local Ciphertext Helpers

**Files:**
- Create: `src/crypto.rs`
- Modify: `src/lib.rs` if test helper exports are needed
- Test: unit tests inside `src/crypto.rs`

- [ ] **Step 1: Write crypto behavior tests**

Add tests:

```rust
#[test]
fn reader_id_is_keccak256_of_public_key() {
    let public_key = X25519PublicKey([0x42; 32]);
    let id = reader_id(public_key);
    assert_eq!(id.0.len(), 32);
    assert_ne!(id, Bytes32([0x42; 32]));
}

#[test]
fn system_ciphertext_opens_with_mpc_key() {
    let keypair = HpkeKeypair::from_seed_for_tests([7u8; 32]);
    let aad = Aad::SystemHandle(SystemHandleAadV1 {
        version: 1,
        chain_id: 31337,
        domain_id: Bytes32([1; 32]),
        handle_id: Bytes32([2; 32]),
        type_tag: "suint256".to_string(),
        key_id: Bytes32([3; 32]),
    });
    let plaintext = encode_plaintext_suint256([9u8; 32]).unwrap();
    let ciphertext = seal_system_ciphertext(&keypair.public_key, Bytes32([3; 32]), &aad, &plaintext).unwrap();
    let opened = open_system_ciphertext(&keypair, &ciphertext).unwrap();
    assert_eq!(opened.plaintext, plaintext);
}
```

- [ ] **Step 2: Implement hash helpers**

In `src/crypto.rs`, implement:

```rust
pub fn keccak256(bytes: &[u8]) -> [u8; 32];
pub fn reader_id(reader_pubkey: X25519PublicKey) -> ReaderId;
pub fn attestation_digest(attestation: &Attestation) -> AttestationDigest;
```

Use `sha3::{Digest, Keccak256}`.

- [ ] **Step 3: Implement HPKE keypair and seal/open wrappers**

Define:

```rust
pub struct HpkeKeypair {
    pub public_key: X25519PublicKey,
    secret_key: hpke::kem::PrivateKey<hpke::kem::X25519HkdfSha256>,
}

pub struct OpenedSystemCiphertext {
    pub source_aad: SourceAad,
    pub plaintext: Vec<u8>,
}
```

Implement:

```rust
impl HpkeKeypair {
    pub fn generate() -> Self;
    pub fn from_seed_for_tests(seed: [u8; 32]) -> Self;
}

pub fn hpke_seal(recipient: X25519PublicKey, aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), MpcError>;
pub fn hpke_open(keypair: &HpkeKeypair, enc: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, MpcError>;
```

Use `hpke::OpModeS::Base`, `hpke::OpModeR::Base`, `hpke::Kem as X25519HkdfSha256`,
`hpke::Kdf as HkdfSha256`, and `hpke::Aead as AesGcm256`.

- [ ] **Step 4: Implement system ciphertext open/seal**

Implement:

```rust
pub fn seal_system_ciphertext(
    mpc_public_key: &X25519PublicKey,
    key_id: KeyId,
    aad: &Aad,
    plaintext: &[u8],
) -> Result<SystemCiphertextV1, MpcError>;

pub fn open_system_ciphertext(
    keypair: &HpkeKeypair,
    ciphertext: &SystemCiphertextV1,
) -> Result<OpenedSystemCiphertext, MpcError>;
```

`seal_system_ciphertext` must:

- encode AAD with `encode_aad`
- generate a random 32-byte data encryption key
- generate a random 12-byte AES-GCM nonce
- AES-GCM encrypt plaintext with encoded AAD as AEAD AAD
- HPKE-seal the data encryption key to the MPC public key with encoded AAD
- place HPKE `enc` in `enc`, wrapped DEK in `wrapped_key`, AES nonce in
  `nonce`, encrypted payload in `ciphertext`, and encoded AAD in `aad`

`open_system_ciphertext` must:

- HPKE-open `wrapped_key` with `enc` and encoded AAD
- AES-GCM decrypt the payload with encoded AAD
- parse the source AAD with `decode_source_aad`

- [ ] **Step 5: Implement recipient ciphertext helpers**

Implement:

```rust
pub fn seal_reader_ciphertext(
    reader_pubkey: X25519PublicKey,
    key_id: KeyId,
    aad: ReaderAadV1,
    plaintext: &[u8],
) -> Result<ReaderCiphertextV1, MpcError>;

pub fn seal_enclave_ciphertext(
    enclave_pubkey: X25519PublicKey,
    key_id: KeyId,
    aad: EnclaveAadV1,
    plaintext: &[u8],
) -> Result<EnclaveCiphertextV1, MpcError>;

pub fn open_reader_ciphertext_for_tests(
    reader_keypair: &HpkeKeypair,
    ciphertext: &ReaderCiphertextV1,
) -> Result<Vec<u8>, MpcError>;

pub fn open_enclave_ciphertext_for_tests(
    enclave_keypair: &HpkeKeypair,
    ciphertext: &EnclaveCiphertextV1,
) -> Result<Vec<u8>, MpcError>;
```

- [ ] **Step 6: Run crypto tests**

Run: `cargo test crypto::`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/crypto.rs src/lib.rs
git commit -m "feat: add MPC crypto core"
```

---

### Task 5: State And Deterministic Local Attestation

**Files:**
- Create: `src/state.rs`
- Create: `src/attestation.rs`
- Test: unit tests inside both files

- [ ] **Step 1: Write state and attestation tests**

Add tests:

```rust
#[test]
fn reader_registration_is_idempotent() {
    let state = AppState::local_deterministic_for_tests();
    let pubkey = X25519PublicKey([8; 32]);
    let id = reader_id(pubkey);
    state.register_reader(id, pubkey).unwrap();
    state.register_reader(id, pubkey).unwrap();
    assert_eq!(state.reader_pubkey(id).unwrap(), pubkey);
}

#[test]
fn local_attestation_binds_pubkey_and_measurement() {
    let verifier = LocalAttestationVerifier;
    let pubkey = X25519PublicKey([1; 32]);
    let measurement = Bytes32([2; 32]);
    let attestation = LocalAttestationVerifier::attestation_for_tests(pubkey, measurement);
    verifier.verify(pubkey, measurement, &attestation).unwrap();
}
```

- [ ] **Step 2: Implement attestation verifier**

Create `src/attestation.rs`:

```rust
pub trait AttestationVerifier: Send + Sync {
    fn verify(
        &self,
        enclave_pubkey: X25519PublicKey,
        measurement: EnclaveMeasurement,
        attestation: &Attestation,
    ) -> Result<(), MpcError>;
}

#[derive(Clone, Debug, Default)]
pub struct LocalAttestationVerifier;
```

For the local format, define `attestation.0` as:

```text
keccak256("mpc-local-attestation-v1" || enclave_pubkey || measurement)
```

Expose `LocalAttestationVerifier::attestation_for_tests`.

- [ ] **Step 3: Implement app state**

Create `src/state.rs` with:

```rust
#[derive(Clone)]
pub struct AppState {
    inner: std::sync::Arc<AppStateInner>,
}

pub struct AppStateInner {
    pub config: MpcConfig,
    pub keypair: HpkeKeypair,
    pub readers: std::sync::RwLock<std::collections::HashMap<ReaderId, X25519PublicKey>>,
    pub attestation_verifier: std::sync::Arc<dyn AttestationVerifier>,
}

#[derive(Clone, Debug)]
pub struct MpcConfig {
    pub version: u16,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub key_id: KeyId,
    pub hpke_public_key: X25519PublicKey,
    pub approved_enclave_measurement: EnclaveMeasurement,
}
```

Implement:

```rust
impl AppState {
    pub fn local_ephemeral() -> Self;
    pub fn local_deterministic_for_tests() -> Self;
    pub fn config_response(&self) -> MpcConfigResponse;
    pub fn register_reader(&self, reader_id: ReaderId, pubkey: X25519PublicKey) -> Result<(), MpcError>;
    pub fn reader_pubkey(&self, reader_id: ReaderId) -> Result<X25519PublicKey, MpcError>;
    pub fn keypair(&self) -> &HpkeKeypair;
    pub fn config(&self) -> &MpcConfig;
    pub fn verify_attestation(&self, pubkey: X25519PublicKey, measurement: EnclaveMeasurement, attestation: &Attestation) -> Result<(), MpcError>;
}
```

`register_reader` must return `MpcError::Conflict("reader_id does not match reader_pubkey")`
when `reader_id != reader_id(pubkey)`.

- [ ] **Step 4: Run tests**

Run: `cargo test state:: attestation::`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/state.rs src/attestation.rs
git commit -m "feat: add MPC state and local attestation"
```

---

### Task 6: Service-Layer Transform Validation

**Files:**
- Create: `src/service.rs`
- Test: unit tests inside `src/service.rs`

- [ ] **Step 1: Write service tests for reader transform**

Add a passing transform test:

```rust
#[test]
fn to_reader_reencrypts_handle_bound_system_ciphertext() {
    let state = AppState::local_deterministic_for_tests();
    let reader = HpkeKeypair::from_seed_for_tests([10; 32]);
    let reader_id = reader_id(reader.public_key);
    state.register_reader(reader_id, reader.public_key).unwrap();

    let aad = Aad::SystemHandle(SystemHandleAadV1 {
        version: 1,
        chain_id: state.config().chain_id,
        domain_id: state.config().domain_id,
        handle_id: Bytes32([0x44; 32]),
        type_tag: "suint256".to_string(),
        key_id: state.config().key_id,
    });
    let plaintext = encode_plaintext_suint256([0x99; 32]).unwrap();
    let system_ciphertext = seal_system_ciphertext(&state.config().hpke_public_key, state.config().key_id, &aad, &plaintext).unwrap();

    let response = to_reader(&state, ToReaderRequest {
        request_id: Bytes32([0x55; 32]),
        chain_id: state.config().chain_id,
        handle_id: Bytes32([0x44; 32]),
        reader_id,
        system_ciphertext,
    }).unwrap();

    let opened = open_reader_ciphertext_for_tests(&reader, &response.ciphertext).unwrap();
    assert_eq!(opened, plaintext);
}
```

Add a failure test where `request.handle_id` differs from source AAD and assert
`matches!(err, MpcError::Unprocessable(_))`.

- [ ] **Step 2: Write service tests for enclave transform**

Add a passing enclave transform test using
`LocalAttestationVerifier::attestation_for_tests`, plus a failure test with the
wrong measurement that asserts `MpcError::Forbidden`.

- [ ] **Step 3: Implement service functions**

Create `src/service.rs`:

```rust
pub fn get_config(state: &AppState) -> MpcConfigResponse;
pub fn put_reader(state: &AppState, reader_id: ReaderId, request: PutReaderRequest) -> Result<PutReaderResponse, MpcError>;
pub fn to_reader(state: &AppState, request: ToReaderRequest) -> Result<ToReaderResponse, MpcError>;
pub fn to_enclave(state: &AppState, request: ToEnclaveRequest) -> Result<ToEnclaveResponse, MpcError>;
```

Implement validation in the order from `docs/superpowers/specs/2026-06-05-mpc-local-http-demo-design.md`.

For `to_reader`, reject:

- unknown reader as `MpcError::NotFound`
- inactive `system_ciphertext.key_id` as `MpcError::NotFound`
- non-`SystemHandleAadV1` source AAD as `MpcError::Unprocessable`
- chain or handle mismatch as `MpcError::Unprocessable`

For `to_enclave`, reject:

- inactive key id as `MpcError::NotFound`
- invalid local attestation as `MpcError::Unprocessable`
- measurement not equal to approved measurement as `MpcError::Forbidden`
- chain mismatch as `MpcError::Unprocessable`
- handle mismatch for handle-bound source AAD as `MpcError::Unprocessable`

- [ ] **Step 4: Run service tests**

Run: `cargo test service::`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/service.rs
git commit -m "feat: add MPC transform service"
```

---

### Task 7: Axum HTTP API

**Files:**
- Create: `src/api.rs`
- Modify: `src/main.rs` if compile fixes are needed
- Test: unit tests inside `src/api.rs`

- [ ] **Step 1: Write HTTP route smoke tests**

Add tests using `tower::ServiceExt`:

```rust
#[tokio::test]
async fn get_config_returns_json() {
    let app = router(AppState::local_deterministic_for_tests());
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/config")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn put_reader_rejects_mismatched_path_id() {
    let app = router(AppState::local_deterministic_for_tests());
    let body = serde_json::json!({ "reader_pubkey": "0x0808080808080808080808080808080808080808080808080808080808080808" });
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("PUT")
                .uri("/v1/readers/0x1111111111111111111111111111111111111111111111111111111111111111")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
}
```

- [ ] **Step 2: Implement router and handlers**

Create `src/api.rs`:

```rust
pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/v1/config", axum::routing::get(get_config_handler))
        .route("/v1/readers/{reader_id}", axum::routing::put(put_reader_handler))
        .route("/v1/operations/to-enclave", axum::routing::post(to_enclave_handler))
        .route("/v1/operations/to-reader", axum::routing::post(to_reader_handler))
        .with_state(state)
}
```

Handlers should call service functions and return `Result<Json<T>, MpcError>`.
Use `Path<ReaderId>` for path decoding.

- [ ] **Step 3: Run API tests**

Run: `cargo test api::`

Expected: PASS.

- [ ] **Step 4: Run binary check**

Run: `cargo check --bins`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/api.rs src/main.rs
git commit -m "feat: expose MPC HTTP API"
```

---

### Task 8: End-To-End HTTP Flow And Failure Tests

**Files:**
- Create: `tests/http_flow.rs`
- Modify: `src/lib.rs` if test helpers need public exports

- [ ] **Step 1: Write full reader flow integration test**

Create `tests/http_flow.rs` with a test that:

1. builds `AppState::local_deterministic_for_tests()`
2. starts `api::router(state.clone())` in memory
3. gets `/v1/config`
4. creates a deterministic reader keypair
5. registers the reader
6. constructs a `SystemHandleAadV1`
7. seals a `SystemCiphertextV1` with the config public key
8. posts `/v1/operations/to-reader`
9. opens returned `ReaderCiphertextV1` with the reader keypair
10. asserts plaintext equality

Use this assertion shape:

```rust
assert_eq!(response.status(), StatusCode::OK);
let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
let decoded: ToReaderResponse = serde_json::from_slice(&body).unwrap();
let opened = open_reader_ciphertext_for_tests(&reader, &decoded.ciphertext).unwrap();
assert_eq!(opened, plaintext);
```

- [ ] **Step 2: Write full enclave flow integration test**

In the same file, add a test that:

1. creates deterministic enclave keypair
2. uses approved measurement from test state
3. creates `LocalAttestationVerifier::attestation_for_tests`
4. posts `/v1/operations/to-enclave`
5. opens returned `EnclaveCiphertextV1`
6. asserts plaintext equality

- [ ] **Step 3: Write representative failure tests**

Add one test per status:

- `400`: malformed JSON body on `PUT /v1/readers/{reader_id}`
- `404`: unknown reader id on `POST /v1/operations/to-reader`
- `409`: reader id mismatch on registration
- `422`: wrong handle id on `POST /v1/operations/to-reader`
- `403`: wrong enclave measurement on `POST /v1/operations/to-enclave`

Each test must assert both HTTP status and JSON `ErrorResponse.code`.

- [ ] **Step 4: Run integration tests**

Run: `cargo test --test http_flow`

Expected: PASS.

- [ ] **Step 5: Run full verification**

Run:

```bash
cargo fmt --check
cargo test
cargo check --bins
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add tests/http_flow.rs src/lib.rs
git commit -m "test: prove MPC HTTP transform flows"
```

---

### Task 9: Runtime Smoke Test And Final Documentation Check

**Files:**
- Modify: `README.md` if it exists; otherwise create `README.md`

- [ ] **Step 1: Add local run instructions**

Create or update `README.md` with this content:

````markdown
# MPC

Local Rust implementation of the MPC HTTP API.

## Run

```bash
cargo run
```

The service binds to `127.0.0.1:3000` by default. Override with:

```bash
MPC_BIND_ADDR=127.0.0.1:3001 cargo run
```

## Test

```bash
cargo test
```
````

- [ ] **Step 2: Start the service briefly**

Run: `MPC_BIND_ADDR=127.0.0.1:3001 cargo run`

Expected: log line includes `starting MPC HTTP service`.

Stop the process with `Ctrl-C`.

- [ ] **Step 3: Run final verification**

Run:

```bash
cargo fmt --check
cargo test
cargo check --bins
git status --short
```

Expected:

- formatting check passes
- tests pass
- binary check passes
- only intentional README changes are uncommitted

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: add MPC local run instructions"
```

---

## Self-Review Checklist

- Spec coverage: Tasks cover dependencies, module boundaries, fixed-byte JSON,
  base64url payloads, canonical CBOR AAD, real HPKE/AES-GCM/Keccak, in-memory
  state, reader registration, reader transform, enclave transform, local
  attestation, Axum endpoints, structured errors, integration tests, and
  `cargo run`.
- Scope check: The plan excludes durable storage, threshold protocols,
  production attestation, TLS, coordinator auth, and key rotation.
- Type consistency: The plan consistently uses `Bytes32` aliases for fixed
  identifiers, `PayloadBytes` for JSON base64url binary payload fields,
  `HpkeKeypair` for local recipient keys, and `AppState` for shared service
  state.
