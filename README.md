# MPC

Local Rust implementation of the MPC HTTP API.

This is a local demo, not production threshold custody.

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
