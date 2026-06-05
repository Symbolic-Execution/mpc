# MPC

Local Rust implementation of the MPC HTTP API.

This is a local demo, not production threshold custody.

## Workspace

- `types`: shared wire types, ciphertext envelopes, fixed-byte serde, and API DTOs.
- `codec`: canonical CBOR AAD encoding/decoding and typed plaintext encoding.
- `crypto`: HPKE, AES-GCM, Keccak helpers, keypair ownership, and ciphertext transforms.
- `service`: MPC service state, local attestation policy, Axum API, and binary runtime.

Future coordinator, coprocessor, or client work should depend on the shared
crates directly when it needs wire types, byte codecs, or crypto fixtures.

## Run

```bash
cargo run -p mpc
```

The service binds to `127.0.0.1:3000` by default. Override with:

```bash
MPC_BIND_ADDR=127.0.0.1:3001 cargo run -p mpc
```

## Test

```bash
cargo test --workspace
```
