use async_trait::async_trait;

use crate::callbacks::{AuthCallback, ProgressCallback};
use crate::error::Result;
use crate::types::{
    Algorithm, AttestationChain, AuthMethod, GeneratedKey, KeyId, KeyInfo, MigrationResult,
    Signature,
};

/// Core trait that every WSCD plugin must implement.
///
/// Each plugin wraps a specific WSCD backend (R2PS remote HSM, Yubico
/// previewSign, software JWE container) and provides a uniform API
/// for key generation, signing, and lifecycle management.
#[async_trait]
pub trait WscdPlugin: Send + Sync {
    /// Unique identifier for this plugin (e.g., "r2ps", "fido2", "softkey").
    fn id(&self) -> &str;

    /// Human-readable display name.
    fn display_name(&self) -> &str;

    /// Which authentication method this plugin needs before operations.
    fn auth_method(&self) -> AuthMethod;

    /// Generate a new key pair.
    ///
    /// `progress` receives status updates for the UI.
    /// `auth` provides callbacks for authentication if needed.
    async fn generate_key(
        &self,
        algorithm: Algorithm,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<GeneratedKey>;

    /// Sign data with the specified key.
    async fn sign(
        &self,
        kid: &KeyId,
        data: &[u8],
        algorithm: Algorithm,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<Signature>;

    /// List all keys managed by this plugin.
    async fn list_keys(&self) -> Result<Vec<KeyInfo>>;

    /// Return the attestation chain for a key, if available.
    async fn attestation_chain(&self, kid: &KeyId) -> Result<Option<AttestationChain>>;

    /// Delete a key.
    async fn delete_key(&self, kid: &KeyId) -> Result<()>;

    /// Export a key's public material for migration to another plugin.
    /// Returns the public key JWK. The private key stays in the current backend.
    async fn export_public_key(&self, kid: &KeyId) -> Result<serde_json::Value>;

    /// Check whether this plugin can accept a migrated key.
    fn supports_import(&self) -> bool {
        false
    }

    /// Import a key (for migration). Only called if `supports_import()` is true.
    /// Returns the new key info in this plugin, or signals re-enrollment.
    async fn import_key(
        &self,
        _algorithm: Algorithm,
        _auth: &dyn AuthCallback,
        _progress: &dyn ProgressCallback,
    ) -> Result<MigrationResult> {
        Err(crate::error::WscdError::Unsupported {
            plugin: self.id().to_string(),
            op: "import_key".to_string(),
        })
    }
}
