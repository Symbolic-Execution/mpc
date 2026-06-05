# MPC Local HTTP Demo Design

## Purpose

Build the first Rust implementation of the `MPC` service as a local,
spec-matching HTTP demo with real cryptography from day one.

The demo proves the core boundary described in `../spec/mpc`: callers can fetch
public configuration, register reader keys, and transform `SystemCiphertextV1`
payloads into reader- or enclave-targeted ciphertexts without exposing
plaintext or private key material through the API.

## Scope

The first implementation exposes these endpoints:

- `GET /v1/config`
- `PUT /v1/readers/{reader_id}`
- `POST /v1/operations/to-enclave`
- `POST /v1/operations/to-reader`

It uses real cryptography for:

- HPKE with X25519, HKDF-SHA256, and AES-256-GCM for recipient encryption
- AES-256-GCM for the inner system ciphertext payload
- Keccak-256 for `reader_id` and `attestation_digest`
- canonical CBOR for plaintext and AAD payloads

State is in memory for this milestone:

- one active MPC keypair and `key_id`
- public configuration
- approved enclave measurement
- registered reader public keys

The implementation does not attempt production threshold custody yet. Key
custody is modeled behind a service boundary so a later threshold/MPC backend
can replace the local single-node implementation without changing HTTP
handlers or ciphertext envelope code.

Out of scope:

- distributed threshold protocols
- durable storage
- production enclave attestation formats
- coordinator authentication or public user authorization
- TLS deployment
- multiple active keys or production key rotation
- production readiness

## Architecture

The crate should be structured as a small library plus an HTTP adapter.

- `api`: Axum routes, JSON request and response DTOs, and HTTP error mapping.
- `types`: fixed-size IDs, public keys, ciphertext envelopes, and serde helpers.
- `aad`: canonical CBOR AAD encoding, decoding, and binding validation.
- `crypto`: HPKE, AES-GCM, Keccak helpers, and local test encryption helpers.
- `service`: request authorization flow and transformation orchestration.
- `state`: in-memory config, active key, and reader registry.
- `attestation`: verifier trait plus a deterministic local verifier.
- `demo/tests`: end-to-end tests that exercise the HTTP API.

Each unit has one clear responsibility. HTTP handlers parse and serialize API
data, the service layer owns validation order and domain errors, and crypto/AAD
modules own byte-level compatibility.

## Endpoint Behavior

### `GET /v1/config`

Returns the active public configuration generated at startup or loaded from
local config:

- `version`
- `chain_id`
- `domain_id`
- `key_id`
- MPC HPKE public key
- reader key algorithm
- ciphertext suite
- approved enclave measurement

### `PUT /v1/readers/{reader_id}`

Registers a reader X25519 public key.

The service derives `keccak256(reader_pubkey)` and compares it to the path
`reader_id`. If they match, it stores the reader key in memory and returns the
derived `reader_id`.

Registering the same `(reader_id, reader_pubkey)` pair again is idempotent.
A mismatched path returns `409`.

### `POST /v1/operations/to-reader`

Transforms `SystemCiphertextV1` into `ReaderCiphertextV1`.

The service:

1. parses and validates the request body
2. resolves the registered reader public key
3. verifies `system_ciphertext.key_id` is active
4. opens the incoming system ciphertext with local MPC key material
5. parses `system_ciphertext.aad` as `SystemHandleAadV1`
6. verifies `request.chain_id == aad.chain_id`
7. verifies `request.handle_id == aad.handle_id`
8. constructs `ReaderAadV1` from the request and source AAD
9. HPKE-encrypts the plaintext to the reader key
10. returns `ReaderCiphertextV1`

### `POST /v1/operations/to-enclave`

Transforms `SystemCiphertextV1` into `EnclaveCiphertextV1`.

The service:

1. parses and validates the request body
2. verifies `system_ciphertext.key_id` is active
3. opens the incoming system ciphertext with local MPC key material
4. parses `system_ciphertext.aad` as `SystemInputAadV1` or
   `SystemHandleAadV1`
5. verifies `request.chain_id == aad.chain_id`
6. if source AAD is handle-bound, verifies `request.handle_id == aad.handle_id`
7. asks the attestation verifier whether the attestation binds
   `enclave_pubkey` to `measurement`
8. verifies `measurement` matches the approved enclave measurement
9. constructs `EnclaveAadV1` from the request and source AAD
10. HPKE-encrypts the plaintext to the enclave key
11. returns `EnclaveCiphertextV1`

Transform endpoints return ciphertext only. No raw data encryption keys,
plaintext, or private key material are exposed through the API.

## Encoding

Encoding follows `../spec/mpc/mpc-api.md`.

HTTP endpoints use JSON for identifiers and control-plane fields.
Cryptographic payloads use canonical CBOR. When CBOR payloads are carried
inside JSON, they are encoded as base64url strings.

AAD is the canonical CBOR encoding of a fixed-length array. It is never encoded
as a map. The supported AAD variants are:

- `SystemInputAadV1`
- `SystemHandleAadV1`
- `EnclaveAadV1`
- `ReaderAadV1`

The implementation must preserve the exact element order and byte widths
defined in the MPC API spec.

Typed IDs and fixed-size public keys are JSON strings. Because the MPC spec only
explicitly requires base64url for CBOR payloads carried inside JSON,
fixed-size control-plane byte fields use lowercase `0x`-prefixed hex strings in
this implementation.

## Attestation

Attestation verification is represented by a trait.

The first implementation provides a deterministic local verifier that checks a
test-format binding over `(enclave_pubkey, measurement)`. This verifier is
non-production and exists only so the HTTP demo can exercise the authorization
path end to end.

The service layer depends only on the verifier trait. A production verifier can
replace the local verifier without changing route handlers, request DTOs, AAD
construction, or ciphertext transformation logic.

## Error Handling

The API returns:

```rust
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}
```

HTTP status mapping:

- `400`: malformed JSON, invalid encoding, wrong byte lengths, or undecodable
  AAD
- `403`: authorization failures, such as unapproved enclave measurement
- `404`: unknown reader id or inactive/unknown key id
- `409`: reader id mismatch
- `422`: invalid attestation, ciphertext binding mismatch, or undecryptable
  ciphertext
- `503`: unavailable backend abstractions

The local in-memory demo should rarely emit `503`, but the error category stays
in the domain model because the production service will have backend
dependencies.

## Testing

The first milestone is complete when `cargo test` proves the following:

- `GET /v1/config` returns stable suite and config fields.
- reader registration derives and validates `reader_id`.
- duplicate reader registration is idempotent.
- all AAD variants round-trip through canonical CBOR fixed arrays.
- a sample `SystemCiphertextV1` encrypts with the service public key.
- `to-reader` transforms that ciphertext to a registered reader.
- the reader can decrypt `ReaderCiphertextV1` and recover the original
  plaintext.
- `to-enclave` transforms that ciphertext to an approved enclave key.
- the enclave key can decrypt `EnclaveCiphertextV1` and recover the original
  plaintext.
- binding failures reject wrong `chain_id`, wrong `handle_id`, wrong `key_id`,
  wrong measurement, and bad attestation.
- malformed byte payloads return structured `ErrorResponse`.

## Configuration

Runtime configuration is simple and explicit:

- `chain_id`
- `domain_id`
- `approved_enclave_measurement`
- bind address

By default, the local service generates ephemeral key material on startup.
Tests use deterministic configuration and fixed test key material so generated
ciphertexts can be opened and binding behavior can be asserted reliably.

## Milestones

1. Library foundations: typed IDs, byte-string serde, canonical CBOR AAD,
   ciphertext envelopes, `reader_id`, and `attestation_digest`.
2. Crypto core: generate or load local MPC HPKE keypair, encrypt/decrypt
   `SystemCiphertextV1`, and encrypt derived reader/enclave ciphertexts.
3. Service layer: validate requests in the spec order where practical, resolve
   readers, verify key IDs, construct derived AADs, and return typed errors.
4. HTTP adapter: Axum server exposing the four MPC endpoints and returning
   `ErrorResponse`.
5. Local demo tests: exercise reader registration, system ciphertext creation,
   reader transform/decrypt, enclave transform/decrypt, and representative
   failure cases.

## Success Criteria

The first project definition is successful when:

- `cargo test` passes.
- `cargo run` starts the HTTP service.
- an integration test proves a value encrypted as `SystemCiphertextV1` can be
  transformed to a registered reader and decrypted with that reader's secret
  key.
- an integration test proves the same system ciphertext can be transformed to
  an approved enclave key and decrypted with that enclave secret key.
