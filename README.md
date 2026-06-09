# siros-wscd-manager

Pluggable WSCD (Wallet Secure Cryptographic Device) manager for the SIROS EUDI wallet.

## Architecture

```
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
|--------|---------|------|--------|
| `softkey` | JWE-encrypted container | None | ✅ Implemented |
| `r2ps` | Remote PKCS#11 HSM via R2PS | OPAQUE / WebAuthn | Planned |
| `fido2` | Yubico previewSign (CTAP2 rawSign) | FIDO2 | Planned |

### Key Features

- **Plugin resolution**: per-key binding → per-operation default → global default
- **Auth callbacks**: PIN entry (OPAQUE), WebAuthn assertion — host provides UI
- **Progress callbacks**: async state pushed to SDK for spinner/progress UI
- **Key migration**: move keys between plugins, with re-enrollment signaling
- **Zeroize**: private key material zeroized on drop

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

## License

BSD-2-Clause
