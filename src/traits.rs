use async_trait::async_trait;
use std::any::Any;

use crate::callbacks::{AuthCallback, ProgressCallback};
use crate::error::Result;
use crate::types::{
    ActivateLifecycleRequest, ActivationOutcome, Algorithm, AttestationChain, AuthMethod,
    DestroyLifecycleRequest, DestructionOutcome, GeneratedKey, KeyId, KeyInfo, LifecycleStatus,
    MigrationResult, RegisterLifecycleRequest, RegistrationOutcome, RotateLifecycleRequest,
    RotationOutcome, SecurityProperties, Signature,
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

    /// Return the security properties for a key (CS-04 §7.1.3).
    ///
    /// Used by the wallet backend to populate KA claims (`key_storage`,
    /// `user_authentication`, `certification`) and to report `amr` values
    /// after signing operations.
    fn security_properties(&self, kid: &KeyId) -> Result<SecurityProperties>;

    /// Downcast to concrete type for plugin-specific operations.
    fn as_any(&self) -> &dyn Any;

    /// Whether this plugin implements explicit lifecycle operations.
    fn supports_lifecycle(&self) -> bool {
        false
    }

    /// Return lifecycle status for a registration context.
    async fn lifecycle_status(&self, _context_id: &str) -> Result<LifecycleStatus> {
        Err(crate::error::WscdError::Unsupported {
            plugin: self.id().to_string(),
            op: "lifecycle_status".to_string(),
        })
    }

    /// Register lifecycle material and bindings for a context.
    async fn register_lifecycle(
        &self,
        _request: &RegisterLifecycleRequest,
        _auth: &dyn AuthCallback,
        _progress: &dyn ProgressCallback,
    ) -> Result<RegistrationOutcome> {
        Err(crate::error::WscdError::Unsupported {
            plugin: self.id().to_string(),
            op: "register_lifecycle".to_string(),
        })
    }

    /// Activate an existing lifecycle context.
    async fn activate_lifecycle(
        &self,
        _request: &ActivateLifecycleRequest,
        _auth: &dyn AuthCallback,
        _progress: &dyn ProgressCallback,
    ) -> Result<ActivationOutcome> {
        Err(crate::error::WscdError::Unsupported {
            plugin: self.id().to_string(),
            op: "activate_lifecycle".to_string(),
        })
    }

    /// Rotate lifecycle material for an existing context.
    async fn rotate_lifecycle(
        &self,
        _request: &RotateLifecycleRequest,
        _auth: &dyn AuthCallback,
        _progress: &dyn ProgressCallback,
    ) -> Result<RotationOutcome> {
        Err(crate::error::WscdError::Unsupported {
            plugin: self.id().to_string(),
            op: "rotate_lifecycle".to_string(),
        })
    }

    /// Destroy lifecycle material and bindings for a context.
    async fn destroy_lifecycle(
        &self,
        _request: &DestroyLifecycleRequest,
        _auth: &dyn AuthCallback,
        _progress: &dyn ProgressCallback,
    ) -> Result<DestructionOutcome> {
        Err(crate::error::WscdError::Unsupported {
            plugin: self.id().to_string(),
            op: "destroy_lifecycle".to_string(),
        })
    }
}
