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

/// Callback for CTAP2 previewSign transport (FIDO2 rawSign extension).
///
/// The host application owns the CTAP2 transport channel to the
/// authenticator. The plugin calls these methods and the host
/// relays the commands over BLE/NFC/USB.
#[async_trait]
pub trait Ctap2Transport: Send + Sync {
    /// Execute a CTAP2 makeCredential with the rawSign extension.
    /// Returns the attestation object bytes.
    async fn ctap2_make_credential(
        &self,
        client_data_hash: &[u8],
        rp_id: &str,
        user_id: &[u8],
        algorithms: &[i64],
    ) -> Result<Vec<u8>>;

    /// Execute a CTAP2 getAssertion with rawSign extension.
    /// `sign_requests` maps credential handles to data-to-be-signed.
    /// Returns signatures in the same order.
    async fn ctap2_get_assertion(
        &self,
        rp_id: &str,
        challenge: &[u8],
        sign_requests: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<Vec<Vec<u8>>>;
}

/// No-op progress callback for when the caller doesn't care about progress.
pub struct NoopProgress;

#[async_trait]
impl ProgressCallback for NoopProgress {
    async fn on_progress(&self, _progress: OperationProgress) {}
}
