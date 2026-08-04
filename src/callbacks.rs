use async_trait::async_trait;

use crate::error::Result;
#[cfg(feature = "plugin-fido2")]
use crate::preview_sign_protocol::{GenerateKeyInput, MakeCredentialResult, SignInput, SignResult};
use crate::types::OperationProgress;

/// Callback for authentication events triggered by plugins.
///
/// When a plugin needs user credentials (PIN for OPAQUE, passkey assertion
/// for WebAuthn), it invokes these callbacks. The host application (via
/// UniFFI) implements this trait to show the appropriate UI and return
/// the user's response.
#[async_trait]
pub trait AuthCallback: Send + Sync {
    /// Request a PIN from the user (for OPAQUE authentication).
    /// Returns the PIN bytes, or an error if the user cancels.
    async fn request_pin(&self) -> Result<Vec<u8>>;

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

/// Callback for CTAP2 previewSign transport (WebAuthn "sign extension",
/// FIDO2 rawSign).
///
/// The host application owns the channel to the authenticator — native
/// CTAP2 over BLE/NFC/USB, or a browser's `navigator.credentials` API (see
/// [`crate::wasm_fido2::WasmFido2Transport`]). Either way, the shapes here
/// are the same; only *how* an implementation obtains them differs. The
/// shared parsing/encoding logic for those shapes lives in
/// [`crate::preview_sign_protocol`], not in this trait or its callers.
#[cfg(feature = "plugin-fido2")]
#[async_trait]
pub trait Ctap2Transport: Send + Sync {
    /// Create a credential and, via the `generateKey` extension input,
    /// have the authenticator generate a new signing key on it.
    async fn ctap2_make_credential(
        &self,
        rp_id: &str,
        user_id: &[u8],
        client_data_hash: &[u8],
        generate_key: &GenerateKeyInput,
    ) -> Result<MakeCredentialResult>;

    /// Get an assertion and, via the `signByCredential` extension input,
    /// have the authenticator sign `sign.tbs` with the given key.
    async fn ctap2_get_assertion(
        &self,
        rp_id: &str,
        challenge: &[u8],
        credential_id: &[u8],
        sign: &SignInput,
    ) -> Result<SignResult>;
}

/// No-op progress callback for when the caller doesn't care about progress.
pub struct NoopProgress;

#[async_trait]
impl ProgressCallback for NoopProgress {
    async fn on_progress(&self, _progress: OperationProgress) {}
}
