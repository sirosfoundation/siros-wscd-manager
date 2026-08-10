use async_trait::async_trait;

use crate::error::Result;
use crate::types::OperationProgress;

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
    /// sent every time. Returns the PIN bytes, or an error if the user
    /// cancels.
    async fn request_pin(&self, plugin_id: &str) -> Result<Vec<u8>>;

    /// Request a WebAuthn assertion from the host.
    ///
    /// `challenge` is the server challenge bytes.
    /// `rp_id` is the relying party identifier.
    /// `allowed_credentials` is a list of credential IDs the server will accept.
    ///
    /// Returns the raw authenticator assertion response (clientDataJSON +
    /// authenticatorData + signature), serialized as JSON.
    async fn request_webauthn_assertion(
        &self,
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
}

/// No-op progress callback for when the caller doesn't care about progress.
pub struct NoopProgress;

#[async_trait]
impl ProgressCallback for NoopProgress {
    async fn on_progress(&self, _progress: OperationProgress) {}
}
