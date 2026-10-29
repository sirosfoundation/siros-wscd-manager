use async_trait::async_trait;

use crate::error::Result;
use crate::types::{OperationProgress, Secret};

/// What the user is being asked to do with a PIN prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRequestKind {
    /// Enter the PIN already set on the authenticator.
    EnterPin,
    /// Choose a new PIN; the authenticator has none. `min_length` is its
    /// `minPinLength` in Unicode code points.
    SetNewPin { min_length: u32 },
}

/// Callback for authentication events triggered by plugins.
///
/// When a plugin needs user credentials (PIN for OPAQUE, passkey assertion
/// for WebAuthn), it invokes these callbacks. The host application (via
/// UniFFI) implements this trait to show the appropriate UI and return
/// the user's response.
#[async_trait]
pub trait AuthCallback: Send + Sync {
    /// Request a PIN from the user (for OPAQUE authentication, or a CTAP2
    /// authenticator's ClientPin).
    ///
    /// `plugin_id` identifies which plugin (e.g. `"fido2"`, `"r2ps"`) is
    /// asking - a single host-provided [`AuthCallback`] instance can back
    /// multiple registered plugins with very different PIN semantics (a
    /// real hardware secret the user must enter vs. a fixed debug-only
    /// test value), and this callback previously gave the host no way to
    /// tell them apart. Confirmed via live hardware testing: without this,
    /// a host had to guess from ambient UI state which plugin an incoming
    /// request was for, got it wrong, and silently sent a hardcoded test
    /// PIN to a real YubiKey - the authenticator correctly rejected it as
    /// `PIN_INVALID`, but nothing indicated why the wrong PIN kept getting
    /// sent every time. Returns the PIN bytes (wrapped in [`Secret`] so
    /// they're zeroized on drop rather than lingering in memory - a raw
    /// device PIN is worth scrubbing promptly, unlike most other byte
    /// buffers this crate passes around), or an error if the user cancels.
    async fn request_pin(&self, plugin_id: &str) -> Result<Secret>;

    /// Like [`Self::request_pin`], but says whether the user must ENTER an
    /// existing PIN or CHOOSE a new one (a fresh CTAP2 authenticator with
    /// `clientPin: false`). The default delegates to `request_pin`, so
    /// existing implementations keep compiling and behave as before.
    async fn request_pin_for(&self, plugin_id: &str, kind: PinRequestKind) -> Result<Secret> {
        let _ = kind;
        self.request_pin(plugin_id).await
    }

    /// Request a WebAuthn assertion from the host.
    ///
    /// `plugin_id` identifies which plugin is asking - see [`Self::request_pin`]'s
    /// doc comment for why this matters when one host callback backs multiple
    /// registered plugins.
    ///
    /// `challenge` is the server challenge bytes.
    /// `rp_id` is the relying party identifier.
    /// `allowed_credentials` is a list of credential IDs the server will
    /// accept - empty for a registration ceremony (`navigator.credentials.create()`),
    /// non-empty for an assertion (`navigator.credentials.get()`) in the
    /// common case. Note this is a simplification, not a fully explicit
    /// signal: a legitimate discoverable-credential assertion can also have
    /// an empty allow-list, which a host implementation needs to be aware of
    /// if it ever supports that flow.
    ///
    /// Returns the raw authenticator assertion response (clientDataJSON +
    /// authenticatorData + signature), serialized as JSON.
    async fn request_webauthn_assertion(
        &self,
        plugin_id: &str,
        challenge: &[u8],
        rp_id: &str,
        allowed_credentials: &[Vec<u8>],
    ) -> Result<Vec<u8>>;
}

/// Callback for reporting operation progress to the UI layer.
///
/// The SDK feeds this state up to the caller so it can show spinners
/// or progress indicators for long-running operations (HSM network
/// round-trips, OPAQUE protocol exchanges, etc.).
#[async_trait]
pub trait ProgressCallback: Send + Sync {
    /// Called when operation progress changes.
    async fn on_progress(&self, progress: OperationProgress);
}

/// Host-provided raw CTAP2 message transport (WebAuthn "sign extension" /
/// FIDO2 rawSign, `previewSign`).
///
/// The host application owns the channel to the authenticator and all of
/// its transport-specific framing (CTAPHID chunking over USB HID,
/// NFCCTAP_MSG/ISO 7816 APDU wrapping over NFC, BLE GATT framing, ...) -
/// this trait sees only the logical CTAP2 message layer: a command
/// (leading command-code byte + CBOR params) in, a response (leading
/// status byte + CBOR body) out. All CBOR request-building and
/// response-parsing for `previewSign` lives in
/// [`crate::preview_sign_protocol`] (its `make_credential`/`get_assertion`
/// functions), not in this trait or its callers - this is a deliberate,
/// confirmed-on-real-hardware design so that logic exists exactly once,
/// in Rust, rather than being duplicated per host SDK.
#[cfg(feature = "plugin-fido2")]
#[async_trait]
pub trait Ctap2Transport: Send + Sync {
    /// Send a raw CTAP2 command and return the raw response bytes.
    async fn ctap2_send_command(&self, command: &[u8]) -> Result<Vec<u8>>;

    /// Whether this transport runs the user-verification ceremony itself,
    /// so the plugin must NOT perform a CTAP2 ClientPin exchange or send a
    /// `pinUvAuthParam`. False for raw authenticator transports (USB, NFC,
    /// BLE), where the plugin collects the PIN through `AuthCallback` and
    /// derives the token. True for a browser's WebAuthn API, which prompts
    /// for PIN/biometrics and talks ClientPin to the authenticator on its
    /// own - and rejects requests that already carry a `pinUvAuthParam`.
    fn performs_user_verification(&self) -> bool {
        false
    }
}

/// Host-provided Android Keystore access, mirroring `AndroidKeyStoreBackend`
/// (siros-sdk-kotlin's `AndroidKeystoreSigner.kt`) method for method.
///
/// Every method here is a thin, synchronous-feeling wrapper over one or two
/// `android.security.keystore`/`java.security` calls on the Kotlin side —
/// all of them already implemented, tested and shipped in
/// `SystemAndroidKeyStore`. This trait does not add any new low-level
/// Keystore logic of its own; it exists only so [`crate::plugins::android_keystore::AndroidKeystorePlugin`]
/// (the StrongBox→TEE best-effort decision tree, kid↔alias bookkeeping, and
/// `WscdPlugin` conformance) can live once, in Rust, instead of being
/// re-derived per host SDK — the same split this crate already uses for
/// [`Ctap2Transport`] (CTAP2 protocol logic in Rust, raw transport I/O on
/// the host).
///
/// **One deliberate difference from `AndroidKeyStoreBackend`:** that
/// interface's `newSignature(alias) -> Signature` hands back a live,
/// stateful `java.security.Signature`/`CryptoObject` that a
/// `BiometricPrompt` must be shown *before* it is executed, so the
/// biometric unlock is cryptographically bound to that exact operation. A
/// `java.security.Signature` cannot cross UniFFI (it is not a
/// primitive/record-shaped value), so [`Self::sign`] collapses
/// `newSignature`/authenticate/`finish` into one atomic call, implemented
/// host-side exactly as `AndroidKeystoreSigner.sign()` already does it —
/// the same granularity every other plugin's [`AuthCallback::request_webauthn_assertion`]
/// already uses for a platform-UI-bound operation.
#[cfg(feature = "plugin-android-keystore")]
#[async_trait]
pub trait AndroidKeystoreCallback: Send + Sync {
    /// Generates an EC P-256 SIGN key (SHA-256, origin GENERATED) under
    /// `alias`, optionally bound to `attestation_challenge` (Android Key
    /// Attestation), and returns where it was confirmed to land.
    ///
    /// Returns [`crate::error::WscdError::StrongBoxUnavailable`] specifically
    /// when `strong_box` was requested and this device has none (or cannot
    /// use it now) - `AndroidKeyStoreBackend.StrongBoxUnavailable` on the
    /// Kotlin side - so the caller's StrongBox→TEE retry can match on it
    /// precisely rather than retrying after every kind of failure.
    async fn generate(
        &self,
        alias: &str,
        attestation_challenge: Option<&[u8]>,
        strong_box: bool,
        user_authentication_methods: &[String],
        unlocked_device_required: bool,
    ) -> Result<crate::types::AndroidKeystoreSecurityLevel>;

    /// `alias`'s certificate chain as DER, leaf first (empty if it has
    /// none).
    async fn certificate_chain(&self, alias: &str) -> Result<Vec<Vec<u8>>>;

    /// `alias`'s public key, as a JWK (`"kty": "EC", "crv": "P-256", ...`).
    async fn public_key_jwk(&self, alias: &str) -> Result<serde_json::Value>;

    /// Where the Keystore reports `alias` is held right now (StrongBox is
    /// distinguished from the TEE only from Android 12 on).
    async fn security_level(
        &self,
        alias: &str,
    ) -> Result<crate::types::AndroidKeystoreSecurityLevel>;

    /// The per-use authentication methods `alias` requires (`"biometric"`,
    /// `"device_credential"`), or empty if it needs none.
    async fn user_authentication_methods(&self, alias: &str) -> Result<Vec<String>>;

    /// Signs `data` (ECDSA P-256 over SHA-256) with `alias`'s private key,
    /// raw `r || s` (64 bytes, low `s`). If `alias` requires per-use user
    /// authentication, the host prompts for it (bound to this exact
    /// operation) before signing — see this trait's doc comment.
    async fn sign(&self, alias: &str, data: &[u8]) -> Result<Vec<u8>>;

    /// Every alias this backend currently holds.
    async fn aliases(&self) -> Result<Vec<String>>;

    /// Deletes `alias`. Deleting one that does not exist is a no-op.
    async fn delete(&self, alias: &str) -> Result<()>;
}

/// Host-provided access to Apple's Secure Enclave, for the Apple Secure
/// Enclave WSCD plugin.
///
/// Rust has no portable way to drive the Secure Enclave directly: key
/// generation and signing only exist via CryptoKit's
/// `SecureEnclave.P256.Signing.PrivateKey` + Keychain, a Swift-only API with
/// no stable C ABI this crate could call from a `cdylib` without
/// re-deriving CryptoKit's own access-control plumbing. So, exactly like
/// [`Ctap2Transport`], the host owns every actual platform call and this
/// crate owns only the plugin logic that decides when to call it, what to
/// store, and what security properties to report.
///
/// **No per-key attestation - permanent, by design, not staged** (decided
/// 2026-10-29, see
/// [issue #134](https://github.com/sirosfoundation/siros-wscd-manager/issues/134)):
/// keys are generated via plain `SecureEnclave.P256.Signing.PrivateKey` + a
/// Keychain tag, with NO per-key attestation chain. The resulting plugin's
/// `attestation_chain()` always returns `Ok(None)`, and
/// `security_properties().certification` reports `CertificationLevel::None`
/// - an honest reflection that nothing here cryptographically proves the key
/// is Secure-Enclave-resident beyond the OS API's own (unattested)
/// guarantee. This is final, not a gap awaiting a future release:
/// `SecKeyCreateAttestation` - the only candidate general per-key
/// attestation API - was hardware-verified (real Xcode 26.6 / iOS 26.5 +
/// macOS 26.5 SDK headers, not WebSearch) **not to exist** anywhere in
/// Security.framework, and CryptoKit's own
/// `SecureEnclave.P256.Signing.PrivateKey` interface has no
/// attestation-shaped member either. The only real Apple attestation
/// primitive, `DCAppAttestService`/App Attest, is a one-time,
/// non-repeatable, whole-device/app-integrity ceremony - not a general
/// "attest this arbitrary key" primitive - and is already used for a
/// different purpose (Wallet Instance Attestation) elsewhere in this
/// program. This trait will not grow a method built around
/// `SecKeyCreateAttestation`; nothing here is designed around waiting for
/// Apple to ship one.
///
/// A narrower, real building block - App Attest *asserting* over an
/// arbitrary key's thumbprint, rather than attesting the key itself - is
/// already proven elsewhere in this program (`go-wallet-backend`'s
/// `internal/service/app_attest_assertion.go`, used for the WIA instance
/// key, reported at a deliberately lower `secure_enclave_asserted` tier).
/// Porting that pattern to `apple-se`'s keys is real, buildable follow-up
/// work, tracked separately as
/// [issue #140](https://github.com/sirosfoundation/siros-wscd-manager/issues/140)
/// - not implemented by this trait today.
#[cfg(feature = "plugin-apple-se")]
#[async_trait]
pub trait SecureEnclaveCallback: Send + Sync {
    /// Generate a new P-256 signing key in the Secure Enclave, tagged
    /// `key_tag` (a caller-chosen Keychain tag, unique within this plugin's
    /// tag namespace). Returns the public key's uncompressed SEC1 (x, y)
    /// coordinates, 32 bytes each.
    async fn generate_key(&self, key_tag: &str) -> Result<SecureEnclavePublicKey>;

    /// Sign `data` with the Secure Enclave key tagged `key_tag`.
    ///
    /// `SecureEnclave.P256.Signing.PrivateKey.signature(for:)` hashes its
    /// input with SHA-256 internally, so `data` is the exact signing input
    /// here, not pre-hashed - the same contract `Algorithm::ES256` already
    /// has everywhere else in this crate (see
    /// [`crate::types::Algorithm::signs_prehashed_input`]). Returns a raw
    /// `r || s` ECDSA signature, 64 bytes for P-256 - the same wire format
    /// [`crate::plugins::softkey::SoftkeyPlugin`] produces for ES256, which
    /// CryptoKit's `P256.Signing.ECDSASignature.rawRepresentation` already
    /// hands back directly.
    async fn sign(&self, key_tag: &str, data: &[u8]) -> Result<Vec<u8>>;

    /// Delete the Secure Enclave key tagged `key_tag` from the Keychain.
    async fn delete_key(&self, key_tag: &str) -> Result<()>;
}

/// Public key material returned by [`SecureEnclaveCallback::generate_key`].
#[cfg(feature = "plugin-apple-se")]
#[derive(Debug, Clone)]
pub struct SecureEnclavePublicKey {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

/// No-op progress callback for when the caller doesn't care about progress.
pub struct NoopProgress;

#[async_trait]
impl ProgressCallback for NoopProgress {
    async fn on_progress(&self, _progress: OperationProgress) {}
}
