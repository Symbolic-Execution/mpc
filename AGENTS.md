# MPC Agent Instructions

## Project Overview

This repo implements the `MPC` HTTP API used by the Coordinator and the
coprocessor for public config, reader registration, and ciphertext
transformations.

The sibling spec repo is the current source of truth. Before changing
behavior, read:

- `../spec/README.md`
- `../spec/mpc/mpc-api.md`
- `../spec/coordinator/coordinator-api.md`
- `../spec/coprocessor/README.md`

## Coding Style

Use the same Rust architecture style established in `coprocessor`:

- Prefer deep modules with small interfaces and concentrated invariants.
- Keep `main.rs` thin: environment parsing and process startup only.
- Put transport wiring in `api`, domain behavior in `service`, and stable data
  shapes in `types`.
- Use seams only where behavior genuinely varies.
- Keep tests focused on public behavior through `lib.rs` modules and HTTP flows.

## Structure

- Root crate exposes modules through `lib.rs`.
- Runtime/process configuration belongs in `config.rs`.
- HTTP entrypoints belong in `api.rs`.
- State/configuration owned by the running service belongs in `state.rs`.

## Security And Privacy

- Never log plaintexts, DEKs, reader private keys, or decrypted payloads.
- Treat AAD and key ids as part of the security contract, not decorative
  metadata.
- Keep malformed, forbidden, not-found, and unavailable errors distinct.
