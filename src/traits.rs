use async_trait::async_trait;
use std::any::Any;

use crate::callbacks::{AuthCallback, ProgressCallback};
use crate::error::Result;
use crate::factors::{AuthFactors, FactorCapability, SignOptions, SignOutcome};
use crate::types::{
    ActivateLifecycleRequest, ActivationOutcome, Algorithm, AttestationChain, AuthMethod,
    DestroyLifecycleRequest, DestructionOutcome, GeneratedKey, KeyId, KeyInfo, LifecycleStatus,
    MigrationResult, RegisterLifecycleRequest, RegistrationOutcome, RotateLifecycleRequest,
    RotationOutcome, SecurityProperties, Signature,
};

/// Downcast helper, blanket-implemented for every `T: Any` (every plugin,
/// since all are `'static` - required anyway to live behind
/// `Arc<dyn WscdPlugin>`). [`WscdPlugin`] requires this as a supertrait so
/// `as_any()` is available on every plugin automatically instead of each
/// one writing the identical `fn as_any(&self) -> &dyn Any { self }`
/// boilerplate (previously duplicated verbatim across every plugin and
/// test mock - siros-wscd-manager#136). A plain default method on
/// `WscdPlugin` itself can't do this: its body needs `Self: Sized` to
/// coerce `&Self` to `&dyn Any`, and that bound would drop `as_any` out of
/// `dyn WscdPlugin`'s vtable - exactly the trait-object call this method
/// exists for (see the downcasts in `ffi.rs`/`wasm_ffi.rs`). The blanket
/// impl sidesteps that: each concrete plugin type gets its own `Sized`
/// `as_any`, and `WscdPlugin: AsAny` puts it in the supertrait vtable.
pub trait AsAny: Any {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Core trait that every WSCD plugin must implement.
///
/// Each plugin wraps a specific WSCD backend (R2PS remote HSM, Yubico
/// previewSign, software JWE container) and provides a uniform API
/// for key generation, signing, and lifecycle management.
#[async_trait]
pub trait WscdPlugin: Send + Sync + AsAny {
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

    /// Sign data and report the TS12 authentication factors applied to THIS
    /// sign (EC TS12 v1.0.1 section 3.6), together with the signature, so the
    /// factors can never describe an earlier or a concurrent sign.
    ///
    /// The default signs with [`Self::sign`] and reports no factor and a
    /// shortfall (fail closed: a plugin that does not report factors cannot
    /// be used for SCA). With `options.require_fresh_user_authentication`
    /// the default refuses (`Unsupported`): it cannot guarantee freshness.
    /// Plugins that authenticate the user override this.
    async fn sign_with_factors(
        &self,
        kid: &KeyId,
        data: &[u8],
        algorithm: Algorithm,
        options: &SignOptions,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<SignOutcome> {
        options.validate()?;
        if options.require_fresh_user_authentication {
            return Err(crate::error::WscdError::Unsupported {
                plugin: self.id().to_string(),
                op: "require_fresh_user_authentication".to_string(),
            });
        }
        let signature = self.sign(kid, data, algorithm, auth, progress).await?;
        Ok(SignOutcome {
            signature,
            factors: AuthFactors::none(format!(
                "plugin {} does not report TS12 authentication factors",
                self.id()
            )),
        })
    }

    /// Side-effect-free: could a sign with this key reach two TS12
    /// categories? The default says no (fail closed).
    fn authentication_capability(&self, _kid: &KeyId) -> Result<FactorCapability> {
        Ok(FactorCapability::cannot(format!(
            "plugin {} does not report TS12 authentication factors",
            self.id()
        )))
    }

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
