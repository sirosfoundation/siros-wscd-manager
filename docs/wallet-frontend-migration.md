# Migrating wallet-frontend onto siros-wscd-manager

- Version: 1.0
- Date: 2026-08-30
- Status: **Single source of truth.** One open decision (D1), see §2.

## Scope and standing

This document governs two strands of work that were planned separately,
drifted apart, and turned out to gate each other:

1. **The WASM migration** — replacing `wallet-frontend`'s WebCrypto-only key
   management with `siros-wscd-manager` compiled to WASM, so every wallet
   client shares one key-management implementation.
2. **The `privatedata-spec` update** —
   [privatedata-spec#1](https://github.com/sirosfoundation/privatedata-spec/pull/1),
   which introduces `S.extensions`, the normative mechanism for
   client-defined state in the shared container.

They are here together because strand 2 gates strand 1 and neither document
said so. Everything the native SDKs now write into the container — WSCD key
metadata, OID4VCI refresh tokens, blind BBS holder state — travels through a
mechanism that is not yet published, into a client that cannot yet carry it.

### What this supersedes

| Superseded | Disposition |
|---|---|
| `wallet-frontend#183` — `docs/wsca-migration-spec.md` v0.4 | **Closed.** Its content is this document; nothing was dropped. |
| `siros-wscd-manager#66` Part A (overview, decisions, sequencing) | Superseded by §1–§3 and §16 here. Part B's task graph stays in the issue. |
| `privatedata-spec` `docs/ROLLOUT-PLAN.md` | Reduced to a pointer here. Its content is §3 and §16. |

Anything that contradicts this document is out of date, including the three
rows above.

## 1. The rule everything is built on

> **At every moment, a client that has not yet learned a data kind must be
> able to carry it faithfully.**

Not "a client running an old build" — a client that does not *understand* a
data kind. The native SDKs have a negligible deployed base and can change
freely, so version skew between them is not the hazard. What remains is a
client asked to hold state it has never modelled: `wallet-frontend` carrying
`S.extensions`, or any future client meeting a namespace registered after it
shipped.

Break it and the failure is not degraded behaviour. It is a destroyed
credential, and it surfaces on whichever client touches the container
*last*, not on the one that caused it.

### 1.1 Status, verified 2026-08-30

| Repo | Where it stands |
|---|---|
| `privatedata-spec` | `SPEC.md` v2.1 §6.1 `S.extensions` + §6.2 deprecations exist **only in PR #1**. `origin/main` has no mention of `wscdCredentials` and no extension mechanism at all. PR open, `CHANGES_REQUESTED` outstanding since 2026-08-28. |
| `siros-wscd-manager` | WASM module built, browser-tested in CI, published as `@sirosfoundation/wscd-manager-wasm` 0.8.0. FIDO2 ships but is unreachable from JS (§16, W-1). `kid` allocation fixed in #67. |
| `siros-sdk-kotlin` | Implements `S.extensions` (`ExtensionStore`, `BbsHolderStateVault`). Writes `org.siros.bbs`. |
| `siros-sdk-swift` | Mirror not started — `siros-sdk-swift#119`. |
| `wallet-frontend` | Still V3, still WebCrypto. Cannot carry unmodelled content across a merge (§14.2). No WASM dependency. |

### 1.2 Two namespaces are already live

| Namespace | Written by | Cost of losing it |
|---|---|---|
| `org.siros.wscd` | native SDKs (was `S.wscdCredentials`) | an enrolled authenticator becomes unaddressable |
| `org.siros.bbs` | `siros-sdk-kotlin`, today | **the credential is destroyed** |

`org.siros.bbs` holds a blind BBS credential's secret prover blind. It
cannot be reconstructed: a client that drops it does not degrade the
credential, it makes it permanently unpresentable.

This is why §1's rule is a correctness requirement rather than a courtesy,
and why the cheapest work in this plan (§16 Stage 0) is also the most
urgent.

## 2. Decisions

> **Agreed direction, 2026-08-31** (@leifj and @smncd, on this PR and
> `privatedata-spec#1`). This supersedes **D2** below and fixes the order in
> §16:
>
> 1. Stop `wallet-frontend` silently dropping `S.extensions`.
> 2. Migrate `wallet-frontend` onto `siros-wscd-manager`, and make
>    `org.siros.wscd` work across platforms — web and Kotlin first, Swift
>    after.
> 3. Move to **Automerge across all platforms**.
> 4. Implement the review extension in `wallet-frontend`.
> 5. Implement BBS in `wallet-frontend`.
>
> Meanwhile the native SDKs keep implementing BBS, and **when (3) reaches
> them the BBS data is expected to ride along** — see §18 for what that
> requires and why it already holds.

One question is still open: **D1**, which blocks §16 Stage 3.

### D1 — Where does the WASM module run?

This document and the architecture documentation currently specify
**different execution contexts**, and the difference is not cosmetic:

- **This document**: in-page. `wallet-frontend` takes the
  `@sirosfoundation/wscd-manager-wasm` dependency and calls `WscdManagerJs`
  from its own JavaScript.
- **`docs/docs/wallet/architecture/wsca-wscd.md`**: inside the
  `wallet-companion` browser extension's background service worker, which the
  page reaches over extension messaging.

The choice changes the security properties (see §12.1), the capability set,
the API shape (an extension boundary is async and serialised; an in-page call
is not), and who can use the feature at all — the extension model means no
hardware-backed keys for users who have not installed the companion.

**This must be resolved first.** Until it is, §2's architecture diagram
should be read as describing the in-page option only.

### D2 — Does the V3 → V4 blob split happen at all? — **decided: no**

> **Decided by the agreed direction above: Automerge is the destination, so
> there is no standalone V3 → V4 split.** V4's key separation survives only
> as a *layout* choice inside whatever the Automerge conversion produces —
> document in one JWE, keys in another — not as a migration of its own.
> §6, §8, §10, §11 and §13 remain accurate as a description of that layout;
> they are no longer a plan.
>
> The reasoning that got here, kept because it is the reason the answer is
> "no" rather than "later":
> `privatedata-spec`'s `docs/ROLLOUT-PLAN.md` §5.1 reaches this from the
> other direction. If the Automerge alternative
> (`docs/SPEC-ALTERNATIVE-AUTOMERGE.md`) is ever adopted, its conversion is
> itself a one-time, non-derivable, per-account migration — two clients
> converting the same container independently produce documents that
> *duplicate* rather than reconcile. Doing V3→V4 first would mean two
> dangerous one-time conversions per account instead of one. This
> document's key separation survives either way as a **layout** choice:
> document in one JWE, keys in another. So D2's answer is not "no" but
> "not on its own schedule".
>
> This does not block anything below. Stage 3 already runs on V3
> indefinitely (§14.4).

§7.2 already concludes that splitting the *backend API* buys nothing, because
credential data dominates the blob while the softkey container is a few
hundred bytes. §14.4 says the V3-compatible integration "can run indefinitely".

If D1 resolves to in-page, §12.1's isolation rationale does not apply (see
the correction there), and V4's remaining benefits are narrow: metadata-only
key events, plus a cross-platform key portability that §8.4 explicitly
declares a non-goal for state. Stage 5 is the most expensive and highest-risk
part of this plan — IndexedDB migration, event rewriting, cross-client
compatibility, and a normative `privatedata-spec` bump. It should be decided
deliberately rather than treated as implied by Stage 3.

## 3. Overview

This specification defines how to migrate `wallet-frontend` from its
monolithic private data blob (where key material and credential data are
co-mingled in a single JWE) to an architecture where:

1. **Key management** is handled by `siros-wscd-manager` compiled to WASM,
    providing the same `WscdPlugin` interface used by the native SDKs
    (Kotlin/Swift).
2. **Credential and wallet state** remain in an event-sourced encrypted
    container (the private data blob), but with key material removed.
3. The two concerns have **independent storage, encryption, and sync
    lifecycles**.

### 3.1 Goals

- Single source of truth for key management logic across all platforms
  (native + web) via the Rust `siros-wscd-manager` crate.
- Credential data and key material stored in separate encrypted containers
  with independent sync and conflict resolution.
- The softkey WASM module produces the **same container format** as the
  native SDKs, enabling cross-platform key portability.
- Existing PRF-derived encryption chain is preserved for both containers.
- Backwards-compatible migration from `WalletStateV3`.

### 3.2 Non-Goals

- Changes to the WebAuthn PRF or password-based key derivation chain itself.
- Changes to the JWE envelope format (`A256GCMKW` / `A256GCM`).

## 4. Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  wallet-frontend                                                 │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  KeystoreAdapter (TypeScript)                              │  │
│  │                                                            │  │
│  │  Protocol-level operations (unchanged signatures):         │  │
│  │  • generateOpenid4vciProofs()                              │  │
│  │  • signJwtPresentation()                                   │  │
│  │  • generateDeviceResponse()                                │  │
│  │  • generateDeviceResponseForDCAPI()                        │  │
│  │  • generateDeviceResponseWithProximity()                   │  │
│  │                                                            │  │
│  │  Delegates raw crypto to WscdManager (WASM).               │  │
│  │  Delegates credential lookup to WalletState (TS).          │  │
│  └────────────┬──────────────────────────────────┬────────────┘  │
│               │                                  │               │
│     generateKey / sign              credential lookup by kid     │
│     listKeys / deleteKey                                         │
│     exportPublicKey                                              │
│     securityProperties                                           │
│               │                                  │               │
│  ┌────────────▼──────────┐     ┌─────────────────▼────────────┐  │
│  │  siros-wscd-manager   │     │  WalletStateV4 Container     │  │
│  │  (WASM module)        │     │  (TypeScript, event-sourced) │  │
│  │                       │     │                              │  │
│  │  WscdManager          │     │  credentials[]               │  │
│  │   ├─ SoftkeyPlugin    │     │  presentations[]             │  │
│  │   │  (p256, ed25519)  │     │  settings                    │  │
│  │   ├─ R2PS Plugin      │     │                              │  │
│  │   │  (OPAQUE/FIDO2    │     │                              │  │
│  │   │   via JS callback)│     │                              │  │
│  │   └─ FIDO2 Plugin     │     │                              │  │
│  │      (rawSign via     │     │                              │  │
│  │       WebAuthn API)   │     │                              │  │
│  │                       │     │  credentialIssuanceSessions[] │  │
│  │  export_container()   │     │                              │  │
│  │  → cleartext JSON     │     │  NO keypairs[]               │  │
│  └────────────┬──────────┘     └──────────────────┬───────────┘  │
│               │                                   │              │
│  ┌────────────▼───────────────────────────────────▼───────────┐  │
│  │  Encryption Layer (TypeScript, existing code)              │  │
│  │                                                            │  │
│  │  PRF → HKDF → prfKey → ECDH → mainKey → JWE               │  │
│  │                                                            │  │
│  │  Produces TWO independent JWE containers:                  │  │
│  │    1. keyContainerJwe   (softkey JSON from WASM)           │  │
│  │    2. stateContainerJwe (WalletStateV4 JSON)               │  │
│  │                                                            │  │
│  │  Same mainKey encrypts both. Same PRF keys unlock it.      │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              │                                   │
│                    ┌─────────▼─────────┐                         │
│                    │  Storage Layer    │                          │
│                    │                   │                          │
│                    │  IndexedDB:       │                          │
│                    │   store: keys     │                          │
│                    │   store: state    │                          │
│                    │                   │                          │
│                    │  Backend sync:    │                          │
│                    │   POST /private-data?type=keys               │
│                    │   POST /private-data?type=state              │
│                    └───────────────────┘                          │
└──────────────────────────────────────────────────────────────────┘
```

## 5. WASM Compilation of siros-wscd-manager

### 5.1 Feature Flags

A new Cargo feature `wasm` is added to `siros-wscd-manager/Cargo.toml`:

```toml
[features]
default = ["plugin-softkey"]
wasm = ["plugin-softkey", "getrandom/js", "web-time"]

[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }
web-time = "1"
wasm-bindgen = "0.2"
wasm-bindgen-futures = "0.4"
js-sys = "0.3"
serde-wasm-bindgen = "0.6"
```

### 5.2 Conditional Compilation

The following items are gated behind `#[cfg(not(target_arch = "wasm32"))]`:

| Item | Reason |
|------|--------|
| `uniffi::setup_scaffolding!()` in `lib.rs` | UniFFI is native-only C FFI |
| Entire `ffi.rs` module | UniFFI bindings |
| `build.rs` UniFFI codegen | Build script |
| `tokio` features `rt`, `rt-multi-thread` | No thread runtime on WASM |
| `crate-type = ["cdylib", "staticlib"]` | WASM needs `cdylib` only |
| `josekit` / `openssl` dependencies | C library, not used by softkey |

The following items require platform-conditional implementations:

| Item | Native | WASM |
|------|--------|------|
| `std::time::SystemTime::now()` | As-is | Replace with `web_time::SystemTime` |
| `async_trait` bounds | `#[async_trait]` (requires `Send + Sync`) | `#[async_trait(?Send)]` |
| `OsRng` | Uses OS entropy | Uses `crypto.getRandomValues` via `getrandom/js` |

### 5.3 WASM Bindings

A new module `src/wasm.rs` (gated behind `#[cfg(target_arch = "wasm32")]`)
exposes the WASM API via `wasm-bindgen`:

```rust
#[wasm_bindgen]
pub struct WasmWscdManager { /* wraps WscdManager */ }

#[wasm_bindgen]
impl WasmWscdManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self;

    /// Initialize with a softkey plugin, optionally loading an existing
    /// container (cleartext JSON bytes from a decrypted JWE).
    pub fn register_softkey(&self, container: Option<Vec<u8>>) -> Result<(), JsValue>;

    /// Register the FIDO2 plugin with a JS callback for WebAuthn rawSign.
    /// The callback implements the Ctap2Transport trait by calling the
    /// WebAuthn API's `navigator.credentials.get()` with the `previewSign`
    /// extension.
    pub fn register_fido2(&self, transport: JsValue) -> Result<(), JsValue>;

    /// Register the R2PS plugin with HTTP transport and auth callbacks.
    /// `http_transport`: JS callback for fetch()-based HTTP requests.
    /// `auth_callback`: JS callback for OPAQUE PIN or WebAuthn assertion.
    pub fn register_r2ps(
        &self,
        config: JsValue,
        http_transport: JsValue,
        auth_callback: JsValue,
    ) -> Result<(), JsValue>;

    /// Generate a new key. Returns JSON: { kid, publicKeyJwk }.
    pub async fn generate_key(&self, algorithm: &str) -> Result<JsValue, JsValue>;

    /// Sign data. Returns the raw signature bytes.
    pub async fn sign(&self, kid: &str, data: &[u8], algorithm: &str)
        -> Result<Vec<u8>, JsValue>;

    /// List all keys. Returns JSON array of KeyInfo.
    pub fn list_keys(&self) -> Result<JsValue, JsValue>;

    /// Delete a key.
    pub async fn delete_key(&self, kid: &str) -> Result<(), JsValue>;

    /// Export a key's public JWK. Returns JSON.
    pub fn export_public_key(&self, kid: &str) -> Result<JsValue, JsValue>;

    /// Get security properties for a key. Returns JSON.
    pub fn security_properties(&self, kid: &str) -> Result<JsValue, JsValue>;

    /// Export the softkey container as cleartext JSON bytes.
    /// The caller MUST encrypt this (JWE) before persisting.
    pub fn export_container(&self) -> Result<Vec<u8>, JsValue>;
}
```

### 5.4 FIDO2 Plugin via WebAuthn rawSign

The FIDO2 `previewSign` (rawSign) extension is supported by YubiKey
firmware ≥ 5.8. In the browser, the plugin delegates CTAP2 operations
through the WebAuthn API:

```typescript
// JS implementation of Ctap2Transport for FIDO2 plugin
const fido2Transport = {
  async rawSign(challenge: Uint8Array, rpId: string,
                allowCredentials: object[]): Promise<Uint8Array> {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId,
        allowCredentials,
        extensions: { previewSign: { data: challenge } },
      },
    });
    return new Uint8Array(
      assertion.getClientExtensionResults().previewSign.signature
    );
  },
};
```

The WASM FIDO2 plugin wraps this JS callback via `wasm-bindgen`, calling
back into JavaScript for each signing operation. The WebAuthn API handles
BLE/NFC/USB transport to the authenticator transparently.

Security properties: `{ key_storage: "hardware", amr: ["hwk", "rawsign"] }`.

### 5.5 R2PS Plugin via fetch()

The R2PS plugin communicates with a remote PKCS#11 HSM over HTTPS. In the
browser context:

- **HTTP transport**: Implemented as a JS callback wrapping `fetch()`. The
  WASM R2PS plugin calls back into JavaScript for each HTTP round-trip to
  the R2PS service.
- **OPAQUE authentication**: The OPAQUE PAKE (RFC 9807) protocol runs
  inside the WASM module (pure Rust `opaque-ke` crate, WASM-compatible).
  The PIN is collected via the `AuthCallback` which crosses the WASM
  boundary to a JS-side PIN prompt.
- **WebAuthn authentication**: For R2PS instances configured with FIDO2
  auth, the `AuthCallback` triggers `navigator.credentials.get()` in
  JavaScript and returns the assertion to the WASM module.

This means R2PS remote HSM signing is fully available to browser-based
wallets, providing `{ key_storage: "remote_hsm", certification: "high" }`
security properties — the same level as the native SDKs.

**Additional WASM dependencies for R2PS**:

```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
# Only needed when plugin-r2ps feature is enabled
opaque-ke = { version = "3", optional = true }
```

The `r2ps-client` crate itself needs a `wasm` feature that replaces
`tokio::task::block_in_place` with `wasm-bindgen-futures` and uses the
JS HTTP callback instead of `reqwest`.

### 5.6 Build and Packaging

The WASM module is built with `wasm-pack`:

```sh
cd siros-wscd-manager
wasm-pack build --target web --features wasm --no-default-features
```

Output: `pkg/siros_wscd_manager.js` + `siros_wscd_manager_bg.wasm`

Published as `@sirosfoundation/wscd-manager-wasm` on **npmjs.com** (public
registry). This makes the package available to any web wallet
implementation without GitHub Packages authentication.

### 5.7 TypeScript Wrapper

A thin TypeScript wrapper (`wscd-manager.ts`) provides typed access:

```typescript
import init, { WasmWscdManager } from '@sirosfoundation/wscd-manager-wasm';

export interface GeneratedKey {
  kid: string;
  publicKeyJwk: JWK;
}

export interface KeyInfo {
  kid: string;
  algorithm: 'ES256' | 'EdDSA';
  plugin_id: string;
  created_at: number;
}

export interface SecurityProperties {
  key_storage: 'software' | 'hardware' | 'remote_hsm' | 'trusted_execution';
  user_authentication: string[];
  certification: 'none' | 'baseline' | 'substantial' | 'high';
  amr: string[];
}

export interface R2psConfig {
  serviceUrl: string;
  clientId: string;
}

export class WscdManager {
  private inner: WasmWscdManager;

  static async create(container?: Uint8Array): Promise<WscdManager>;

  /** Register the softkey (software) plugin. */
  registerSoftkey(container?: Uint8Array): void;

  /** Register the FIDO2 rawSign plugin (requires YubiKey ≥ 5.8). */
  registerFido2(transport: Fido2Transport): void;

  /** Register the R2PS remote HSM plugin. */
  registerR2ps(config: R2psConfig, authCallback: AuthCallback): void;

  async generateKey(algorithm: 'ES256' | 'EdDSA'): Promise<GeneratedKey>;
  async sign(kid: string, data: Uint8Array, algorithm: 'ES256' | 'EdDSA'): Promise<Uint8Array>;
  listKeys(): KeyInfo[];
  async deleteKey(kid: string): Promise<void>;
  exportPublicKey(kid: string): JWK;
  securityProperties(kid: string): SecurityProperties;
  exportContainer(): Uint8Array;
}
```

## 6. Private Data Blob Split

### 6.1 Current State (Schema V3)

A single JWE contains everything:

```
EncryptedContainer {
  mainKey, prfKeys, jwe → WalletStateContainer {
    S: {
      schemaVersion: 3,
      keypairs: [{ kid, keypair: { kid, did, alg, publicKey, privateKey } }],
      credentials: [{ credentialId, format, data, kid, ... }],
      presentations: [{ presentationId, data, usedCredentialIds, ... }],
      settings: { ... },
      credentialIssuanceSessions: [{ sessionId, tokenResponse, dpop, ... }],
    },
    events: [...],
    lastEventHash: "...",
  }
}
```

### 6.2 New State (Schema V4)

Two separate encrypted documents sharing the same `mainKey` and `prfKeys`:

#### 6.2.1 Key Container (WSCA-managed)

```
KeyEncryptedContainer {
  mainKey, prfKeys, jwe → softkey container JSON {
    keys: [
      { kid: "sw-0", algorithm: "ES256", d: "<base64url>", created_at: 1720000000 },
      { kid: "sw-1", algorithm: "ES256", d: "<base64url>", created_at: 1720000001 },
      ...
    ],
    lifecycle: {
      "<contextId>": { factor_kind, state, updated_at, key_ids: [...] },
      ...
    }
  }
}
```

This is the **exact format** produced by `SoftkeyPlugin::export_container()` —
an `ExportedContainer` object with a `keys` array and a `lifecycle` map
(`src/plugins/softkey.rs`). The native SDKs already produce and consume it.

**Write the object, not a bare array.** `from_container()` accepts a bare
`[StoredKey, ...]` as well, but only as a fallback for containers exported
before `lifecycle` existed — it loads them with *no* lifecycle contexts. A
client that exports the legacy shape therefore round-trips its own keys
correctly while silently discarding every lifecycle context another client
wrote, which is the §1 rule broken in a second place and by the same
mechanism. `lifecycle` is `#[serde(default)]`, so an object with no lifecycle
contexts is the correct way to say "I have none"; a bare array is not.

The JWE envelope uses the same `A256GCMKW` / `A256GCM` algorithms and the
same `mainKey` as the state container.

#### 6.2.2 State Container (Event-sourced, TypeScript)

```
StateEncryptedContainer {
  mainKey, prfKeys, jwe → WalletStateContainerV4 {
    S: {
      schemaVersion: 4,
      credentials: [{ credentialId, format, data, kid, ... }],
      presentations: [{ presentationId, data, usedCredentialIds, ... }],
      settings: { ... },
      credentialIssuanceSessions: [{ sessionId, tokenResponse, dpop, ... }],
    },
    events: [...],
    lastEventHash: "...",
  }
}
```

#### 6.2.3 Key Differences from V3

| Aspect | V3 | V4 |
|--------|----|----|
| `keypairs[]` in WalletState | Present (JWK private keys) | **Removed** |
| `new_keypair` event payload | `{ kid, keypair: { privateKey, publicKey, ... } }` | **Replaced** with `{ kid, pluginId, publicKeyJwk }` (metadata only, no private key) |
| `delete_keypair` event | Deletes from state `keypairs[]` | Records kid removal; also calls `wscdManager.deleteKey(kid)` |
| Key storage format | JWK inside event-sourced state | Softkey `StoredKey[]` JSON, managed by WASM |
| Encryption | Single JWE | Two JWEs, same `mainKey` |

### 6.3 Schema V4 Type Definitions

```typescript
// --- WalletStateSchemaVersion4.ts ---

export const SCHEMA_VERSION = 4;

/**
  * V4 keypair metadata — no private key material.
  * Private keys live in the WSCA manager (softkey container).
  */
export type KeypairMetadata = {
  kid: string;
  pluginId: string;       // "softkey", future: "r2ps", "fido2", "native"
  publicKeyJwk: JWK;
  algorithm: 'ES256' | 'EdDSA';
}

/**
  * V4 new_keypair event — records metadata only, no private key.
  */
export type WalletSessionEventNewKeypairV4 = {
  type: "new_keypair";
  kid: string;
  pluginId: string;
  publicKeyJwk: JWK;
  algorithm: 'ES256' | 'EdDSA';
}

/**
  * V4 wallet state — keypairs replaced with metadata-only records.
  */
export type WalletStateV4 = {
  schemaVersion: 4;
  keypairMetadata: KeypairMetadata[];
  credentials: SchemaV3.WalletState['credentials'];
  presentations: SchemaV3.WalletState['presentations'];
  settings: SchemaV3.WalletState['settings'];
  credentialIssuanceSessions: SchemaV3.WalletState['credentialIssuanceSessions'];
}
```

### 6.4 Combined Container Envelope

Both containers share the same key hierarchy but are independent documents:

```typescript
/**
  * The top-level structure stored in IndexedDB and synced to the backend.
  */
export type EncryptedWalletData = {
  /** Shared asymmetric key encapsulation (same for both JWEs) */
  mainKey: EphemeralEncapsulationInfo;
  prfKeys: WebauthnPrfEncryptionKeyInfoV2[];
  passwordKey?: AsymmetricPasswordKeyInfo;

  /** Credential + wallet state (event-sourced, V4 schema) */
  stateJwe: string;

  /** WSCA softkey container (StoredKey[] JSON) */
  keyJwe: string;

  /** Format version for the envelope itself */
  envelopeVersion: 2;
}
```

Both `stateJwe` and `keyJwe` are encrypted with the **same `mainKey`** using
`A256GCMKW` / `A256GCM`. This means:

- A single PRF authentication unlocks both.
- Key rotation (new ephemeral ECDH keypair + new mainKey) re-encrypts both
  JWEs atomically.
- The `mainKey` / `prfKeys` / `passwordKey` structure is identical to the
  existing `AsymmetricEncryptedContainer`.

#### 6.4.1 Backwards Compatibility

The envelope is distinguished from V3 by the presence of `envelopeVersion`:

```typescript
function isV4Envelope(container: unknown): container is EncryptedWalletData {
  return typeof container === 'object'
    && container !== null
    && 'envelopeVersion' in container
    && (container as any).envelopeVersion === 2;
}
```

Legacy containers (no `envelopeVersion` field, single `jwe` field) are
treated as V3 and migrated on first open (§8).

## 7. Backend API Changes

### 7.1 Option A: Envelope Approach (Recommended)

The backend continues to store a **single opaque blob** per user. The
`EncryptedWalletData` envelope (containing both `stateJwe` and `keyJwe`)
is serialized as one JSON document and stored in the existing
`privateData` column/field.

**No backend API changes required.**

- Same `GET /user/session/private-data` and
  `POST /user/session/private-data` endpoints.
- Same etag mechanism (SHA-256 of the entire serialized envelope).
- Same optimistic concurrency.

The split is **entirely client-side**. The backend sees one blob; the
client knows it contains two JWEs.

**Trade-off**: Both JWEs are always synced together. A key-only change
(e.g., generating a new keypair) triggers a full blob sync including
unchanged credential state. This is acceptable because:

- The blob is already re-encrypted atomically on every mutation (mainKey
  rotation).
- The sync overhead is dominated by the JWE envelope, not the plaintext
  size.
- Splitting the backend API can be done later (Option B) if performance
  becomes an issue.

### 7.2 Note on Separate Endpoints

Splitting into per-type endpoints (`?type=state`, `?type=keys`) was
considered but is unlikely to provide meaningful benefit. The real bulk
of the private data blob is credential data (SD-JWT/mDL strings), not
key material. The softkey container is typically a few hundred bytes
(a handful of 32-byte P-256 scalars), while a single SD-JWT credential
can be several kilobytes. Separating the endpoints would add API
complexity without reducing sync payload size in practice.

## 8. Migration: V3 → V4

### 8.1 Trigger

Migration occurs on first successful decryption of a V3 container after
the V4 code is deployed. It is performed client-side in
`decryptPrivateData()`.

### 8.2 Migration Steps

```
Input:  V3 AsymmetricEncryptedContainer { mainKey, prfKeys, jwe }
        where jwe decrypts to WalletStateContainer with S.schemaVersion === 3

1. Decrypt jwe with mainKey → WalletStateContainerV3

2. Extract keypairs:
    For each entry in S.keypairs[]:
      Convert CredentialKeyPair to StoredKey:
        { kid: kp.keypair.kid,
          algorithm: kp.keypair.alg,    // "ES256" or "EdDSA"
          d: kp.keypair.privateKey.d,   // base64url P-256 scalar
          created_at: Math.floor(Date.now() / 1000) }

3. Create softkey container:
    softkeyJson = JSON.stringify(storedKeys)

4. Initialize WSCA manager:
    wscdManager = await WscdManager.create(softkeyJson)

5. Build V4 state:
    stateV4 = {
      schemaVersion: 4,
      keypairMetadata: S.keypairs.map(kp => ({
        kid: kp.keypair.kid,
        pluginId: "softkey",
        publicKeyJwk: kp.keypair.publicKey,
        algorithm: kp.keypair.alg,
      })),
      credentials: S.credentials,
      presentations: S.presentations,
      settings: S.settings,
      credentialIssuanceSessions: S.credentialIssuanceSessions,
    }

6. Migrate events:
    For each event in container.events:
      If event.type === "new_keypair":
        Strip privateKey from event payload.
        Replace with { kid, pluginId: "softkey", publicKeyJwk, algorithm }.
      All other events: preserve as-is.

7. Generate new mainKey (key rotation on migration):
    { newMainKey, newMainPublicKeyInfo, newMainPrivateKey } = createAsymmetricMainKey()

8. Encrypt both containers:
    keyJwe = CompactEncrypt(softkeyJson, newMainKey, { alg: "A256GCMKW", enc: "A256GCM" })
    stateJwe = CompactEncrypt(stateV4Container, newMainKey, { alg: "A256GCMKW", enc: "A256GCM" })

9. Re-wrap mainKey for all PRF keys and password key:
    (same re-encapsulation logic as existing updatePrivateData)

10. Emit V4 envelope:
    { envelopeVersion: 2, mainKey: newMainPublicKeyInfo,
      prfKeys: [...], passwordKey: ...,
      stateJwe, keyJwe }

11. Persist to IndexedDB and sync to backend.
```

### 8.3 Rollback Safety

The V3 container is not deleted until the V4 envelope is successfully
persisted to both IndexedDB and the backend. On failure, the V3
container remains valid and the migration retries on next open.

### 8.4 Cross-Platform Considerations

The softkey container format (`StoredKey[]` JSON) is identical across all
platforms. A V4 key container produced by the web wallet can be consumed
by the native SDKs (Kotlin `JweKeystore`, Swift `JweKeystore`) and vice
versa, provided the JWE encryption layer uses the same key hierarchy.

The `keypairMetadata` in the state container is web-specific metadata
that the native SDKs do not use (they maintain their own credential
store). Cross-platform state sync is not a goal of this spec.

## 9. KeystoreAdapter

The `KeystoreAdapter` replaces direct `crypto.subtle` calls in the
current `keystore.ts`. It follows the same pattern as the Kotlin
`WscdKeystoreAdapter`: delegates raw crypto to the WSCA manager,
handles JWT/SD-JWT/mDOC construction locally.

### 9.1 Interface

```typescript
export class KeystoreAdapter {
  constructor(
    private wscdManager: WscdManager,
    private stateContainer: WalletStateContainerV4,
  ) {}

  /**
    * Generate keypairs and return public key metadata.
    * Keys are created in the WSCA manager; metadata recorded in state.
    */
  async generateKeypairs(count?: number): Promise<{
    keypairs: KeypairMetadata[];
    updatedState: WalletStateContainerV4;
  }>;

  /**
    * Generate OID4VCI proof JWTs.
    * Constructs JWT headers/claims in TypeScript, calls wscdManager.sign()
    * for the raw ECDSA signature, assembles compact serialization.
    */
  async generateOpenid4vciProofs(
    nonce: string,
    audience: string,
    issuer: string,
    count?: number,
  ): Promise<{
    proofJwts: string[];
    keypairs: KeypairMetadata[];
    updatedState: WalletStateContainerV4;
  }>;

  /**
    * Sign a VP token (KB-JWT for SD-JWT VP).
    * Imports nothing — calls wscdManager.sign(kid, ...) directly.
    */
  async signJwtPresentation(
    kid: string,
    nonce: string,
    audience: string,
    verifiableCredentials: object[],
  ): Promise<{ vpjwt: string }>;

  /**
    * Generate mDOC DeviceResponse.
    */
  async generateDeviceResponse(
    kid: string,
    mdocCredential: object,
    presentationDefinition: object,
    nonce: string,
    clientId: string,
    responseUri: string,
  ): Promise<{ deviceResponseMDoc: object }>;

  /**
    * Get security properties for a key (for KA request).
    */
  securityProperties(kid: string): SecurityProperties;

  /**
    * Export the WSCA softkey container (cleartext bytes).
    * Caller encrypts via JWE.
    */
  exportKeyContainer(): Uint8Array;
}
```

### 9.2 JWT Construction

JWT header and claims construction stays in TypeScript (using `jose`
library). Only the raw signature operation crosses the WASM boundary:

```typescript
async function signJwt(
  wscdManager: WscdManager,
  kid: string,
  header: object,
  payload: object,
): Promise<string> {
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = new TextEncoder().encode(
    `${encodedHeader}.${encodedPayload}`
  );

  const signature = await wscdManager.sign(kid, signingInput, 'ES256');
  const encodedSignature = base64url(signature);

  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}
```

This mirrors the Kotlin `WscdKeystoreAdapter` pattern where `signer.sign()`
provides raw bytes and the adapter assembles the JWT.

## 10. Event Schema Changes

### 10.1 New Event Types (V4)

```typescript
type WalletSessionEventNewKeypairV4 = {
  type: "new_keypair";
  kid: string;
  pluginId: string;
  publicKeyJwk: JWK;
  algorithm: 'ES256' | 'EdDSA';
  // No privateKey — key material lives in WSCA container
}
```

### 10.2 Removed from Events

The `keypair.privateKey` field (JWK with `d` parameter) is no longer
included in `new_keypair` events. V3 events that contain private key
material are accepted during migration but stripped on fold.

### 10.3 Event-to-WSCA Coordination

When a `new_keypair` event is applied:
1. The WSCA manager has already generated the key (via `generateKey()`).
2. The event records only the metadata (`kid`, `pluginId`, `publicKeyJwk`).
3. The key material exists only in the WSCA softkey container.

When a `delete_keypair` event is applied:
1. The event records the `kid`.
2. `wscdManager.deleteKey(kid)` is called.
3. The key is removed from both the state metadata and the softkey container.

### 10.4 Merge Strategy

V4 keypair events use the same merge strategy as V3 (`new_keypair` and
`delete_keypair` deduplicated by `kid`). The merge operates on metadata
only — no private key material is in the event stream.

The softkey container is not event-sourced. It is the authoritative
source for key existence. On merge conflict:

1. Merge the state events normally (existing V3 merge logic for
    credentials, presentations, settings, sessions).
2. The softkey container from the **local** side wins (keys are
    device-bound in the WSCA model).
3. Any `keypairMetadata` entries in the merged state that reference
    keys not present in the local softkey container are removed
    (orphaned metadata cleanup).

## 11. IndexedDB Schema

### 11.1 Current (Version 3)

```
Database: "wallet-frontend", version 3
  Store: "privateData"
    keyPath: "userHandle"
    Record: { userHandle: string, content: EncryptedContainer }
```

### 11.2 New (Version 4)

```
Database: "wallet-frontend", version 4
  Store: "walletData"
    keyPath: "userHandle"
    Record: { userHandle: string, content: EncryptedWalletData }
```

Migration from IndexedDB v3 to v4:

1. On `onupgradeneeded(3 → 4)`:
    - Create new store `walletData`.
    - Do NOT delete `privateData` store yet (needed for data migration).
2. On first open after upgrade:
    - Read from `privateData` store.
    - Run V3→V4 migration (§8).
    - Write to `walletData` store.
    - Delete record from `privateData` store.

## 12. Security Considerations

### 12.1 Key Material Isolation

In the V3 model, key material (JWK `d` parameter) appears in:
- The decrypted `WalletStateContainer` in JavaScript memory.
- The event stream (in `new_keypair` events).
- The folded state (`S.keypairs[]`).

In the V4 model, key material:
- Lives inside the WASM linear memory (in the `SoftkeyPlugin`
  `HashMap<String, StoredKey>`).
- Is not passed across the WASM boundary by any API other than
  `export_container()`, which the caller immediately encrypts.
- Is not present in the TypeScript event stream or state.

> **Correction.** Version 0.2 of this document additionally claimed
> that "the WASM module's linear memory is not accessible to JavaScript",
> and rested the security case for this migration on that claim. **The claim
> is false for the in-page model.** `wasm-pack build --target web` exports the
> module's `memory`, so `wasm.memory.buffer` is a plain `ArrayBuffer` that any
> same-origin script can read. In-page WASM therefore provides **no
> confidentiality boundary against the page's own JavaScript** — an attacker
> who can run script in the wallet origin can read key material out of linear
> memory just as they could read it out of `S.keypairs[]` today.
>
> What the in-page model *does* buy is real, but it is narrower than §12.1
> previously stated:
> - Key material stops appearing in the event stream and the folded state, so
>   it is no longer written to IndexedDB or synced to the backend in
>   cleartext-at-rest form inside the decrypted blob.
> - The number of places in TypeScript that touch a private key drops to
>   zero, which shrinks the accidental-logging and accidental-serialisation
>   surface.
> - One key-management implementation is shared with the native SDKs.
>
> The original isolation property **does** hold in the extension model (D1),
> where the background service worker is a separate origin and a separate
> process from page script. If §12.1 is load-bearing for this migration, that
> argues for the extension; if implementation-sharing is the actual goal,
> in-page is simpler. This document should not continue to assert both.

### 12.2 Container Export

`export_container()` returns cleartext key material. The caller (TypeScript
encryption layer) MUST encrypt it before persisting. This is the same
contract as the native SDKs.

### 12.3 Side-Channel Considerations

The Rust `SoftkeyPlugin` uses `p256` and `ed25519-dalek` which implement
constant-time operations. WASM execution may or may not preserve
constant-time properties depending on the JavaScript engine's JIT
compilation. This is a known limitation shared with all WASM-based
cryptographic implementations and is acceptable for the `Software`
key storage tier.

For the R2PS and FIDO2 plugins, the sensitive cryptographic operations
occur on the remote HSM or hardware authenticator respectively — the
WASM module only handles protocol framing, not key material.

## 13. privatedata-spec updates that V4 would need

> **This is not the live `privatedata-spec` work.** That is §15, and it
> gates everything. What follows is the additional, V4-only list, and it
> inherits **D2**'s answer: none of it is needed for Stages 0–3.
>
> **Correction.** `SPEC.md` is now **v2.1**, not v2.0, and it already
> carries the piece this document most needed: §8.1 `S.extensions`, a
> normative namespaced mechanism for client-defined state, with §8.2
> deprecating the ad-hoc top-level fields that preceded it. That landed
> without the major bump this section assumed, because it does not change
> the envelope — it only says where client-defined state goes and how a
> client that does not implement a namespace must carry it. The list below
> is therefore V4's list, and inherits **D2**'s answer: none of it is
> needed for Phases 0–2.

Should the V4 split go ahead, `SPEC.md` must be updated to document:

1. The `EncryptedWalletData` envelope format with `envelopeVersion: 2`.
2. The dual-JWE structure (`stateJwe` + `keyJwe`).
3. The V4 `WalletStateContainer` schema (no `keypairs[]`, has
    `keypairMetadata[]`).
4. The softkey container format (`StoredKey[]` JSON) as normative.
5. Migration rules from envelope v1 (legacy, single `jwe`) to v2.
6. The `mainKey` sharing model (both JWEs use the same key).

## 14. Cross-Client Compatibility

### 14.1 Current Client Landscape

Multiple clients share the same backend private data blob:

| Client | Keystore | Blob behavior |
|--------|----------|---------------|
| **wallet-frontend** | WebCrypto + JWE | Reads/writes V3 blob with events. Authoritative. |
| **Kotlin SDK (JweKeystore)** | Same JWE container | Round-trips blob verbatim (`preservedWalletState`). |
| **Kotlin SDK (WscdKeystoreAdapter)** | WSCD manager | Folds `signer.exportPrivateKeypairs()` into the credentials keystore, then exports. |
| **Swift SDK (JweKeystore)** | Same JWE container | Same verbatim round-trip as Kotlin. |
| **Swift SDK (WscdKeystoreAdapter)** | WSCD manager | Implements `exportEncryptedContainer()`. |

### 14.2 Key Finding

**wallet-frontend is still the only client that meaningfully reads AND
writes the private data blob today**, but not for the reason an earlier draft of this
document gave. Native SDK `JweKeystore` (legacy path) returns the blob
verbatim on export — it never overwrites wallet-frontend's data, but also
never persists its own in-session changes.

> **Correction.** An earlier draft said the state is lost because
> wallet-frontend's "typed reducers silently drop it on the next write".
> That is not what happens, and the difference decides the fix. Verified
> against this repository's own code:
>
> - **Unknown `S` fields survive a fold.** `foldState` starts from
>   `container.S` and the reducer spreads `{...state}`, so a field it has
>   never heard of is carried through untouched.
> - **They do not survive a merge.** `mergeDivergentHistoriesWithStrategies`
>   sets `S` to the common-ancestor base state and replays events, so
>   anything not reconstructible from an event it knows is gone.
> - **An unrecognised *event type* is worse than dropped.** Merge buckets
>   events against a literal map of nine known types, so an unknown type
>   dereferences `undefined` and **throws** — on a `412` conflict, which is
>   exactly when merge runs.
>
> So this is not a missing reducer. It is merge that cannot tolerate content
> it does not model, and it fails closed (a crash) for one shape and open
> (silent loss) for the other.

The surviving cross-client hazard is therefore about **merge tolerance**,
not about any one field. `privatedata-spec` v2.1 §8.1 now specifies
`S.extensions` — namespaced client-defined state that a client which does
not implement the namespace MUST carry verbatim — and both native SDKs
implement it. wallet-frontend cannot honour that rule today, and the rule is
what makes staggered adoption across four clients safe at all.

The stakes are also higher than that draft knew. Two namespaces are live or
imminent:

| Namespace | Written by | Cost of losing it |
|---|---|---|
| `org.siros.wscd` | native SDKs (was `S.wscdCredentials`) | an enrolled authenticator becomes unaddressable |
| `org.siros.bbs` | siros-sdk-kotlin, today | **the credential is destroyed** |

`org.siros.bbs` holds a blind BBS credential's secret prover blind, which
**cannot be reconstructed**. A client that drops it does not degrade a
credential, it makes it permanently unpresentable — and the failure lands on
whichever client touches the container *last*, not on the one that caused
it. See §14.3.

### 14.3 Prerequisites (Stage 0)

> **Correction.** An earlier draft listed two blocking
> prerequisites — that `WscdKeystoreAdapter.exportEncryptedContainer()`
> throws in Kotlin and returns `{}` in Swift, and that
> `CredentialPersistence` is unwired. **Both are now implemented and this
> section is no longer blocking.** Kotlin folds
> `signer.exportPrivateKeypairs()` into the credentials keystore via
> `importKeypairJwk()` before delegating, and adds
> `exportWscdCredentialsState()`, `exportCredentialRefreshTokens()` and
> `exportFido2State()`; Swift implements `exportEncryptedContainer()` in
> `Sources/SirosKeystore/WscdKeystoreAdapter.swift`.

> **Update.** An earlier draft's single remaining item was "resolve
> `S.wscdCredentials`: make it normative, or drop it". It has been resolved
> the first way, in `privatedata-spec` v2.1 §8.1, and the resolution is
> broader than one field — so the item below replaces it rather than
> restating it.

Two items remain, and only the first is new work for this repository.

1. **Make merge carry what it does not model** (§14.2) — the Phase-0 gate
    this document did not previously have.

    - Bucket unrecognised event types into a passthrough group instead of
      indexing a fixed map, with a union-and-dedupe default strategy, so an
      unknown type survives a merge rather than throwing during one.
    - Preserve unknown `S` fields across **merge**, not only fold.
    - Surface the null-merge-base case as a user choice rather than
      dead-ending in `"Invalid event history chain"`.

    Blob-format-neutral, and cheap. It is load-bearing three times over:
    extensions now, shared accounts next, and any future format migration
    after that — above all the Automerge conversion, which needs a client
    that can hold a container it cannot fully interpret.

    **This one *is* a gate.** Not on Stage 1, but on any deployment where a
    native SDK and wallet-frontend share an account, which is the only
    configuration the extension mechanism exists for.

2. **Relocate the existing native-SDK extensions** — in the SDKs, not here.
    `S.credentialRefreshTokens` → `org.siros.oid4vci.refresh` (a straight
    relocation; it is already keyed per batch). `S.wscdCredentials` →
    `org.siros.wscd`, re-keyed per `kid`.

    The re-key was blocked until 2026-08-30 and is not blocked now.
    `siros-wscd-manager`'s `preview_sign` and `softkey` plugins both minted
    identifiers from a shared counter (`fido-{next_id}`, `sw-{next_id}`),
    and `preview_sign` persisted `next_id` *inside the exported state* — a
    mutable counter inside a synchronised container, where merging two
    values means nothing. Two unsynchronised devices minted the same `kid`
    for different keys, so a per-`kid` entry would have collided by
    construction. Fixed in siros-wscd-manager#67: identifiers are now
    random. The migration is forward-only — existing `fido-0`/`sw-3` keep
    their identifiers and stay addressable — so no re-enrolment.

    wallet-frontend needs no change for either: it has never modelled these
    fields. Once item 1 lands, it carries them.

Neither changes the envelope written to the backend.

### 14.4 Compatibility Strategy

The migration uses a **V3-compatible intermediate step** (Stage 3) that
lets wallet-frontend use the WASM `WscdManager` internally while
continuing to write V3-format blobs. This avoids cross-client breakage:

```
Stage 0:  Make merge carry unmodelled content, publish the spec
          ↑ GATE for any shared native+web account
Stage 1:  Finish the WASM module (no blob changes)
Stage 3:  wallet-frontend uses WASM internally, writes V3 blobs
          ↑ SAFE: all clients see the same V3 format
Stage 5:  Blob split to V4 envelope — gate on D2, see §2
          ↑ and see D2: probably not on its own schedule
```

In Stage 3, the `KeystoreAdapter` generates keys via the WASM
`WscdManager` but serializes them back into `S.keypairs[]` in V3 format
for the blob. Keys live in both the WASM softkey container (in-memory)
and in the blob (for cross-device sync). This is a transitional state
that can run indefinitely.

## 15. Strand 2 — the `privatedata-spec` update (PR #1)

This is the gate. Nothing else in this document is safe to deploy across a
shared account until it lands, and neither of the superseded documents said
so.

### 15.1 What PR #1 contains

| File | Standing |
|---|---|
| `SPEC.md` v2.1 §6.1 `S.extensions` | Normative. Namespaced client-defined state; entry keys MUST name an entity; values are opaque strings; a client that does not implement a namespace MUST carry it verbatim. |
| `SPEC.md` §6.2 | Deprecates the ad-hoc top-level fields (`S.wscdCredentials`, `S.credentialRefreshTokens`) that preceded it. |
| `docs/EXTENSIONS-DESIGN.md` | Non-normative rationale, prior-art comparison, review record. |
| `docs/SPEC-ALTERNATIVE-AUTOMERGE.md` | A CRDT alternative, written for comparison. **Adopted as the destination** by the agreed direction (§2); specifies Stage 5. |
| `conformance/`, `test-vectors/` | Corpus. Needs one vector per namespace this plan registers. |

### 15.2 Why it blocks

Both superseded documents cite `SPEC.md` §6.1 as if it were published. It is
not: `origin/main` contains no `wscdCredentials` and no extension mechanism.
Three consequences, all live today:

- A third-party client reading the published spec sees no way to carry
  client-defined state, so "carry what you do not model" is not a rule
  anyone is on the hook for.
- `siros-sdk-kotlin` already writes `org.siros.bbs` into a container shape
  that has no published definition.
- The conformance corpus cannot gain a vector for a section that does not
  exist, so nothing mechanically checks the rule §1 depends on.

### 15.3 What has to happen

1. Resolve the outstanding review on PR #1 and merge it. *Owner: whoever
   carries the spec. No code depends on the outcome of the review, only on
   its conclusion.*
2. Register the namespaces this plan uses in §6.1.6: `org.siros.wscd`,
   `org.siros.oid4vci.refresh`, `org.siros.bbs`.
3. Add a conformance vector per namespace, including the one that matters —
   a container carrying a namespace the implementation does not know,
   round-tripped twice.
4. Reduce `docs/ROLLOUT-PLAN.md` to a pointer at this document, so there is
   one plan rather than two that drift.

### 15.4 What it does not need

Not a major version bump, and not the V4 envelope. §6.1 does not change the
envelope — it says where client-defined state goes and how a client that
does not implement a namespace must treat it. That is why it shipped as
v2.1, and why Stages 0–3 of §16 need nothing else from this repo.

## 16. Sequencing

Ordered by what must be true before the next thing starts, not by which
repo matters most. Stage numbers are gates; work inside a stage is
parallel.

The agreed direction in §2 numbers the same work 1–5 from
`wallet-frontend`'s point of view. They line up like this:

| Agreed step | Stage here |
|---|---|
| 1. Stop dropping `S.extensions` | Stage 0 (the `wallet-frontend` rows) |
| 2. Migrate onto `siros-wscd-manager`; `org.siros.wscd` across platforms | Stages 1–3, then Stage 2's re-key |
| 3. Automerge across all platforms | Stage 5, and see §18 |
| 4. Review extension in `wallet-frontend` | not scheduled here — a client feature, not a migration step |
| 5. BBS in `wallet-frontend` | Stage 6 |

The native SDKs' own BBS work runs alongside all of it and is gated by none
of it (§18.3).

`siros-wscd-manager#66` Part B keeps the machine-consumable task graph for
this repo's own items (W-*); the stages below are the cross-repo view.

### Stage 0 — make the rule true (no blob changes)

Everything else assumes §1's rule holds. It does not hold today in either
of the two places it has to.

| Task | Repo | Notes |
|---|---|---|
| Merge PR #1; register `org.siros.{wscd,oid4vci.refresh,bbs}`; add conformance vectors | privatedata-spec | §15. The rule is unpublished until this lands. |
| Bucket unrecognised event types into a passthrough group, union-and-dedupe | **wallet-frontend** | Today merge indexes a literal map of nine types and throws (§14.2). |
| Preserve unknown `S` fields across **merge**, not only fold | **wallet-frontend** | Today they survive a fold and are lost on merge. |
| Surface the null-merge-base case as a user choice | **wallet-frontend** | Today it dead-ends in `"Invalid event history chain"`. |
| ~~Random `kid` allocation~~ | siros-wscd-manager | Done — #67. |

The three `wallet-frontend` rows are the cheapest work in this document and
are load-bearing three times over: extensions now, shared accounts next, any
future format migration after that — above all the Automerge conversion,
which needs a client that can hold a container it cannot fully interpret.

*Gate for:* any deployment where a native SDK and the web wallet share an
account. That is the only configuration the extension mechanism exists for.

### Stage 1 — unblock what is already built

All in `siros-wscd-manager`, all independent of **D1** and **D2**. This
alone takes `wallet-frontend` from software-only to hardware-backed keys
once Stage 3 lands.

| Task | Ref |
|---|---|
| Expose `registerFido2()` — `WasmFido2Transport` ships but nothing registers it | W-1 |
| Stop hardcoding `Algorithm::ES256` in `generateKey()`/`sign()` | W-2 |
| `listKeys()` → `KeyInfo[]`, not `string[]` — the dropped `plugin_id` is what §6.3's `keypairMetadata.pluginId` reads | W-3 |
| Replace the `WasmNoopAuth` stub with a JS `AuthCallback` bridge | W-4 |
| Ship the hand-written TypeScript wrapper of §5.7 | W-8 |

W-1 is the single cheapest high-value item in this plan: a complete,
hardware-verified `previewSign` transport currently ships as dead code.

*Gate:* none.

### Stage 2 — relocate the native SDKs' existing extensions

Forward-only, no re-enrolment. `wallet-frontend` needs no change: it has
never modelled these fields, and after Stage 0 it carries them.

| Task | Repo |
|---|---|
| `S.credentialRefreshTokens` → `org.siros.oid4vci.refresh` (straight relocation, already per-batch) | siros-sdk-kotlin / -swift |
| `S.wscdCredentials` → `org.siros.wscd`, re-keyed per `kid` | siros-sdk-kotlin / -swift |
| Mirror `ExtensionStore` + holder-state storage | siros-sdk-swift (#119) |

The re-key was impossible before 2026-08-30 and is not now. Both
`preview_sign` and `softkey` minted identifiers from a shared counter, and
`preview_sign` persisted `next_id` *inside the exported state* — a mutable
counter in a synchronised container, where merging two values means nothing.
Two unsynchronised devices produced the same `kid` for different keys, so a
per-`kid` entry would have collided by construction. Fixed in #67.

*Gate:* Stage 0's spec half, for the namespace registrations.

### Stage 3 — resolve D1, then integrate

`wallet-frontend` takes the WASM dependency and routes key operations
through it, still writing V3 blobs (§14.4). Merge or close
`wallet-frontend#164` and `#22` as part of this — both are long-lived open
PRs covering ground this work subsumes.

*Gate:* **D1** (§2), Stage 0, Stage 1.

### Stage 4 — acceptance

Issue on one client, present on another, same account, with one client on a
build that has never seen the namespace. Any single client's end-to-end run
proves the feature; only this proves the mechanism.

*Gate:* Stage 2 on two clients.

### Stage 5 — Automerge, across all platforms

Step 3 of the agreed direction, and the one migration this plan has: there
is no standalone V3 → V4 split (§2, D2). `docs/SPEC-ALTERNATIVE-AUTOMERGE.md`
specifies the destination; `privatedata-spec#1` carries it.

The constraint that shapes it: an Automerge document is **not derivable**.
Two clients converting the same container independently produce documents
that duplicate rather than reconcile, with no repair. The conversion happens
once per account and is distributed, elected via the backend ETag as a
compare-and-swap.

BBS data rides along rather than migrating — §18.

*Gate:* Stage 3, so the conversion has one client shape to convert from
rather than two.

### Stage 6 — BBS in `wallet-frontend`

Step 5, and last for a reason: it is the only step that needs the browser to
*model* BBS rather than carry it. Add the six `jwp*` functions to the
crate's `js_api.rs` — same code, fourth binding — then holder-state handling
and presentation.

*Gate:* Stage 0 for safety, Stage 3 for the WASM surface. Independent of
Stage 5: `org.siros.bbs` is carried correctly either side of the conversion.

## 17. What would stop this

- **D1 unresolved.** Stage 3 cannot start, and Stages 0–2 do not depend on
  it, so the plan stalls rather than fails.
- **PR #1 not merged.** Stage 0's spec half is a hard prerequisite for the
  namespace registrations, and without it the rule §1 rests on is
  unpublished.
- **`org.siros.bbs` reaching a client that drops it** before Stage 0's
  `wallet-frontend` half lands. This is the one failure here that destroys
  user data rather than inconveniencing someone.

- **The conversion in Stage 5 running twice.** An Automerge document cannot
  be derived independently by two clients: converting the same container
  twice produces documents that duplicate rather than reconcile, and there
  is no repair. This is the one step whose failure mode is worse than
  stopping.

Size and cost are deliberately not on this list. The measured WASM budget —
`siros-wscd-manager` 94 KB + `zk-cred-bbs` 97 KB brotli, plus ~147 KB for
Automerge, now that it is the direction rather than an alternative — is a
real cost and a known one, and it is not a reason to stop.

## 18. BBS riding along into Automerge

The agreed direction (§2) has the native SDKs continuing to implement BBS
while `wallet-frontend` works through steps 1–4, and expects the BBS data to
**ride along** when Automerge reaches the SDKs. That is a constraint on how
`org.siros.bbs` is shaped *now*, months before the conversion, so it is
worth writing down what it requires and checking it against what shipped.

`docs/SPEC-ALTERNATIVE-AUTOMERGE.md` §2.1 and §2.3 impose two rules on
anything that has to survive the conversion. Both are already met:

| Requirement | `org.siros.bbs` today |
|---|---|
| Collections MUST be maps keyed by the entity's identifier, not lists — Automerge merges concurrent list insertions by interleaving them | Keyed by credential id, one entry per credential. `BbsHolderStateVault.put(credentialId, state)`. |
| Identifiers MUST be allocable without coordination | `randomUint32Id()`, never a counter. This is the rule `siros-wscd-manager#67` had to fix for `kid`; BBS never had the problem. |

So the conversion is a relocation: each `S.extensions["org.siros.bbs"]` entry
becomes a value in an Automerge map under the same credential id. Nothing
about the entries has to change.

### 18.1 The entry stays an opaque scalar, deliberately

An entry's value is a JSON string — base64url fields inside — rather than a
structure Automerge could merge field by field. That looks like a missed
opportunity and is not one.

BBS holder state is **write-once**. It is produced by `accept()` at issuance
and never modified afterwards; the secret prover blind it carries is fixed
for the life of the credential. There is no second writer and no later
version, so there is nothing to merge — and a CRDT that *could* merge two
versions of it field by field would be a hazard rather than a feature, since
any blend of two blinding factors is valid-looking and wrong.

An opaque scalar under an entity-keyed map gives exactly the semantics this
data wants: last-write-wins on a value that is only ever written once.

### 18.2 What would break it

Two changes would turn this from a relocation into a migration, and neither
should be made without revisiting this section:

- **Keying by anything other than one credential.** An aggregate entry — one
  `"bbs"` key holding every credential's state — would make two devices'
  concurrent issuances overwrite each other under last-write-wins, and there
  is no repair: the losing side's blinding factor is not recoverable.
- **Making the entry mutable.** If some future feature rewrites holder state
  after issuance, the write-once argument in §18.1 stops holding and the
  entry needs a merge story of its own.

### 18.3 What it does *not* require

The BBS work in the native SDKs does not need to wait for anything in §16.
It writes through `S.extensions`, which the SDKs already implement, and the
only client that could lose the data is `wallet-frontend` — which is
step 1 of the agreed direction and does not gate the SDKs.

The one thing worth watching: until step 1 lands, a user whose account
touches both a native SDK and the web wallet can lose `org.siros.bbs` on a
merge, and losing it destroys the credential (§1.2). That is an argument for
not putting BBS credentials in front of shared-account users before step 1,
not an argument for slowing the SDK work.
