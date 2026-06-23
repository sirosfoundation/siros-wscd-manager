# siros-wscd-manager

[![CI](https://github.com/sirosfoundation/siros-wscd-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/siros-wscd-manager/actions/workflows/ci.yml)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](LICENSE)

Pluggable WSCD (Wallet Secure Cryptographic Device) manager for the SIROS EUDI wallet.

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│  Mobile SDK (Kotlin/Swift via UniFFI)                │
│  ┌──────────────────────────────────────────┐       │
│  │         WscdManager                       │       │
│  │  ┌──────────┬──────────┬──────────┐      │       │
│  │  │ SoftkeyP │ R2psP    │ FIDO2P   │      │       │
│  │  │ (JWE)    │ (HSM)    │ (rawSign)│      │       │
│  │  └──────────┴──────────┴──────────┘      │       │
│  └──────────────────────────────────────────┘       │
│        ▲             ▲             ▲                 │
│   AuthCallback  ProgressCallback  Ctap2Transport    │
│   (PIN/WebAuthn)  (UI spinners)   (BLE/NFC relay)   │
└─────────────────────────────────────────────────────┘
```

### Plugins

| Plugin | Backend | Auth | Status |
| ------ | ------- | ---- | ------ |
| `softkey` | Software P-256/Ed25519 container (host must JWE-encrypt before persisting) | None | ✅ Implemented |
| `r2ps` | Remote PKCS#11 HSM via R2PS | OPAQUE / WebAuthn | ✅ Implemented (feature-gated) |
| `fido2` | Yubico previewSign (CTAP2 rawSign) | FIDO2 | ✅ Implemented |

### Key Features

- **Plugin resolution**: per-key binding → per-operation default → global default
- **Auth callbacks**: PIN entry (OPAQUE), WebAuthn assertion — host provides UI
- **Progress callbacks**: async state pushed to SDK for spinner/progress UI
- **Key migration**: move keys between plugins, with re-enrollment signaling
- **Lifecycle API**: explicit register/activate/rotate/destroy operations for
    plugin-bound trust contexts
- **Zeroize**: private key material zeroized on drop

## Lifecycle API

The manager now exposes a lifecycle surface in addition to key operations,
so plugin registration and teardown are explicit and testable.

Lifecycle operations:

- `register_lifecycle` - establish registration bindings for a context
- `activate_lifecycle` - authenticate/activate a registered context
- `rotate_lifecycle` - rotate bound registration material
- `destroy_lifecycle` - destroy local bindings and optionally attempt remote revoke
- `lifecycle_status` - inspect current lifecycle state per context

Key lifecycle concepts:

- `FactorKind`: `Opaque`, `WebAuthn`, `RawSign`
- `LifecycleState`: `Uninitialized`, `Registered`, `Active`, `Suspended`, `Destroyed`
- `DestroyMode`: `LocalOnly`, `RemoteRevokeIfSupported`, `Strict`

### Current lifecycle support

- `r2ps`: lifecycle implemented (register = OPAQUE/WebAuthn, activate = OPAQUE/WebAuthn auth, rotate = re-registration, destroy = local + optional remote revoke by `DestroyMode`)
- `fido2` (`preview_sign`): lifecycle implemented for `RawSign` (register/rotate provision bound keys, activate marks context active, destroy performs local key-binding teardown)
- `softkey`: lifecycle not implemented (returns `Unsupported`)

## Usage

```rust
use siros_wscd_manager::*;
use siros_wscd_manager::plugins::softkey::SoftkeyPlugin;
use std::sync::Arc;

let mut manager = WscdManager::new(WscdConfig::default());
manager.register_plugin(Arc::new(SoftkeyPlugin::new()));

// Generate and sign (requires AuthCallback + ProgressCallback impls)
let key = manager.generate_key(Algorithm::ES256, &auth, &progress).await?;
let sig = manager.sign(&key.kid, b"data", Algorithm::ES256, &auth, &progress).await?;
```

## Building

```bash
cargo build                          # default (softkey only)
cargo build --features plugin-r2ps   # with R2PS support
cargo test
```

## Development

```bash
cargo fmt --all -- --check           # check formatting
cargo clippy --all-features -- -D warnings  # lint
cargo test                           # run tests
cargo test --features plugin-r2ps    # test with R2PS plugin
```

## Crate Structure

```text
src/
├── lib.rs           # Public re-exports
├── error.rs         # WscdError enum
├── types.rs         # Key/lifecycle domain types and operation results
├── traits.rs        # WscdPlugin trait (+ lifecycle defaults)
├── callbacks.rs     # AuthCallback, ProgressCallback, Ctap2Transport traits
├── config.rs        # WscdConfig, R2psConfig
├── manager.rs       # WscdManager (key and lifecycle routing)
└── plugins/
    ├── mod.rs
    ├── softkey.rs   # SoftkeyPlugin (JWE container, P-256 ECDSA)
    └── r2ps.rs      # R2psPlugin (remote PKCS#11 HSM via R2PS protocol)
    └── preview_sign.rs  # PreviewSignPlugin (FIDO2 rawSign / Yubico previewSign)
```

## Features

| Feature | Default | Description |
| ------- | :-----: | ----------- |
| `plugin-softkey` | ✅ | Software key store (JWE-encrypted P-256 container) |
| `plugin-r2ps` | | Remote PKCS#11 HSM signing via [r2ps-client](https://github.com/sirosfoundation/r2ps-client) |
| `plugin-fido2` | | Yubico previewSign / CTAP2 rawSign |

## License

BSD-2-Clause
