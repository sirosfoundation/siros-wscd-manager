//! UniFFI bridge — exposes the WSCD manager to Swift/Kotlin via FFI.
//!
//! Uses the proc-macro approach (no UDL file). Types are annotated with
//! `#[derive(uniffi::...)]` and methods with `#[uniffi::export]`.

use std::sync::{Arc, Mutex};

use crate::callbacks as cb;
use crate::config::WscdConfig as InternalConfig;
use crate::error::WscdError as InternalError;
use crate::manager::WscdManager as InternalManager;
use crate::plugins::softkey::SoftkeyPlugin;
use crate::types::{
    Algorithm as InternalAlgorithm, AttestationChain as InternalAttestationChain,
    GeneratedKey as InternalGeneratedKey, KeyId as InternalKeyId,
    KeyInfo as InternalKeyInfo, MigrationResult as InternalMigrationResult,
    OperationProgress as InternalOperationProgress, Signature as InternalSignature,
};

// ─── UniFFI-visible types ────────────────────────────────────────────────────

#[derive(uniffi::Enum, Clone)]
pub enum FfiAlgorithm {
    ES256,
    EdDSA,
}

impl From<FfiAlgorithm> for InternalAlgorithm {
    fn from(a: FfiAlgorithm) -> Self {
        match a {
            FfiAlgorithm::ES256 => InternalAlgorithm::ES256,
            FfiAlgorithm::EdDSA => InternalAlgorithm::EdDSA,
        }
    }
}

impl From<InternalAlgorithm> for FfiAlgorithm {
    fn from(a: InternalAlgorithm) -> Self {
        match a {
            InternalAlgorithm::ES256 => FfiAlgorithm::ES256,
            InternalAlgorithm::EdDSA => FfiAlgorithm::EdDSA,
        }
    }
}

#[derive(uniffi::Enum, Clone)]
pub enum FfiAuthMethod {
    None,
    Opaque,
    WebAuthn,
}

#[derive(uniffi::Enum, Clone)]
pub enum FfiOperationProgress {
    Started { operation: String },
    NetworkRoundTrip { step: u32, total: u32 },
    WaitingForUser,
    Complete,
}

impl From<InternalOperationProgress> for FfiOperationProgress {
    fn from(p: InternalOperationProgress) -> Self {
        match p {
            InternalOperationProgress::Started { operation } => {
                FfiOperationProgress::Started { operation }
            }
            InternalOperationProgress::NetworkRoundTrip { step, total } => {
                FfiOperationProgress::NetworkRoundTrip { step, total }
            }
            InternalOperationProgress::WaitingForUser => FfiOperationProgress::WaitingForUser,
            InternalOperationProgress::Complete => FfiOperationProgress::Complete,
        }
    }
}

#[derive(uniffi::Enum, Clone)]
pub enum FfiMigrationResult {
    Migrated { new_kid: String },
    ReEnrollmentRequired { old_kid: String },
}

impl From<InternalMigrationResult> for FfiMigrationResult {
    fn from(m: InternalMigrationResult) -> Self {
        match m {
            InternalMigrationResult::Migrated { new_kid } => FfiMigrationResult::Migrated {
                new_kid: new_kid.0,
            },
            InternalMigrationResult::ReEnrollmentRequired { old_kid } => {
                FfiMigrationResult::ReEnrollmentRequired {
                    old_kid: old_kid.0,
                }
            }
        }
    }
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum FfiWscdError {
    #[error("no plugin: {message}")]
    NoPlugin { message: String },
    #[error("unsupported: {message}")]
    Unsupported { message: String },
    #[error("key not found: {message}")]
    KeyNotFound { message: String },
    #[error("auth required")]
    AuthRequired { message: String },
    #[error("auth cancelled")]
    AuthCancelled { message: String },
    #[error("re-enrollment required: {message}")]
    ReEnrollmentRequired { message: String },
    #[error("plugin error: {message}")]
    Plugin { message: String },
    #[error("callback error: {message}")]
    Callback { message: String },
    #[error("serialization error: {message}")]
    Serialization { message: String },
    #[error("crypto error: {message}")]
    Crypto { message: String },
}

impl From<InternalError> for FfiWscdError {
    fn from(e: InternalError) -> Self {
        let msg = e.to_string();
        match e {
            InternalError::NoPlugin { .. } => FfiWscdError::NoPlugin { message: msg },
            InternalError::NoDefault { .. } => FfiWscdError::NoPlugin { message: msg },
            InternalError::Unsupported { .. } => FfiWscdError::Unsupported { message: msg },
            InternalError::KeyNotFound { .. } => FfiWscdError::KeyNotFound { message: msg },
            InternalError::AuthRequired => FfiWscdError::AuthRequired { message: msg },
            InternalError::AuthCancelled => FfiWscdError::AuthCancelled { message: msg },
            InternalError::ReEnrollmentRequired { .. } => {
                FfiWscdError::ReEnrollmentRequired { message: msg }
            }
            InternalError::Plugin(_) => FfiWscdError::Plugin { message: msg },
            InternalError::Callback(_) => FfiWscdError::Callback { message: msg },
            InternalError::Serialization(_) => FfiWscdError::Serialization { message: msg },
            InternalError::Crypto(_) => FfiWscdError::Crypto { message: msg },
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiKeyInfo {
    pub kid: String,
    pub algorithm: FfiAlgorithm,
    pub plugin_id: String,
    pub created_at: i64,
}

impl From<InternalKeyInfo> for FfiKeyInfo {
    fn from(k: InternalKeyInfo) -> Self {
        FfiKeyInfo {
            kid: k.kid.0,
            algorithm: k.algorithm.into(),
            plugin_id: k.plugin_id,
            created_at: k.created_at,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiGeneratedKey {
    pub kid: String,
    pub public_key_jwk: String,
}

impl From<InternalGeneratedKey> for FfiGeneratedKey {
    fn from(g: InternalGeneratedKey) -> Self {
        FfiGeneratedKey {
            kid: g.kid.0,
            public_key_jwk: g.public_key_jwk.to_string(),
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiSignature {
    pub data: Vec<u8>,
}

impl From<InternalSignature> for FfiSignature {
    fn from(s: InternalSignature) -> Self {
        FfiSignature { data: s.0 }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiAttestationChain {
    pub certificates: Vec<Vec<u8>>,
}

impl From<InternalAttestationChain> for FfiAttestationChain {
    fn from(a: InternalAttestationChain) -> Self {
        FfiAttestationChain {
            certificates: a.certificates,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiWscdConfig {
    pub default_plugin: String,
}

// ─── Callback interfaces ─────────────────────────────────────────────────────

#[uniffi::export(callback_interface)]
pub trait FfiAuthCallback: Send + Sync {
    fn request_pin(&self) -> Result<Vec<u8>, FfiWscdError>;
    fn request_webauthn_assertion(
        &self,
        challenge: Vec<u8>,
        rp_id: String,
        allowed_credentials: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, FfiWscdError>;
}

#[uniffi::export(callback_interface)]
pub trait FfiProgressCallback: Send + Sync {
    fn on_progress(&self, progress: FfiOperationProgress);
}

#[uniffi::export(callback_interface)]
pub trait FfiCtap2Transport: Send + Sync {
    fn ctap2_make_credential(
        &self,
        client_data_hash: Vec<u8>,
        rp_id: String,
        user_id: Vec<u8>,
        algorithms: Vec<i64>,
    ) -> Result<Vec<u8>, FfiWscdError>;

    fn ctap2_get_assertion(
        &self,
        rp_id: String,
        challenge: Vec<u8>,
        credential_handles: Vec<Vec<u8>>,
        data_to_sign: Vec<Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>, FfiWscdError>;
}

// ─── Bridge adapters (foreign callback → Rust async trait) ───────────────────

struct AuthCallbackBridge(Arc<dyn FfiAuthCallback>);

#[async_trait::async_trait]
impl cb::AuthCallback for AuthCallbackBridge {
    async fn request_pin(&self) -> crate::error::Result<Vec<u8>> {
        self.0
            .request_pin()
            .map_err(|e| InternalError::Callback(format!("{e}")))
    }

    async fn request_webauthn_assertion(
        &self,
        challenge: &[u8],
        rp_id: &str,
        allowed_credentials: &[Vec<u8>],
    ) -> crate::error::Result<Vec<u8>> {
        self.0
            .request_webauthn_assertion(
                challenge.to_vec(),
                rp_id.to_string(),
                allowed_credentials.to_vec(),
            )
            .map_err(|e| InternalError::Callback(format!("{e}")))
    }
}

struct ProgressCallbackBridge(Arc<dyn FfiProgressCallback>);

#[async_trait::async_trait]
impl cb::ProgressCallback for ProgressCallbackBridge {
    async fn on_progress(&self, progress: InternalOperationProgress) {
        self.0.on_progress(progress.into());
    }
}

// ─── FfiWscdManager (UniFFI object) ─────────────────────────────────────────

#[derive(uniffi::Object)]
pub struct FfiWscdManager {
    inner: Mutex<InternalManager>,
    rt: tokio::runtime::Runtime,
}

#[uniffi::export]
impl FfiWscdManager {
    #[uniffi::constructor]
    pub fn new(config: FfiWscdConfig) -> Self {
        let internal_config = InternalConfig {
            default_plugin: config.default_plugin,
            ..InternalConfig::default()
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime");
        FfiWscdManager {
            inner: Mutex::new(InternalManager::new(internal_config)),
            rt,
        }
    }

    /// Register the built-in softkey plugin.
    pub fn register_softkey_plugin(&self) -> Result<(), FfiWscdError> {
        let mut mgr = self.inner.lock().map_err(|e| FfiWscdError::Plugin {
            message: e.to_string(),
        })?;
        mgr.register_plugin(Arc::new(SoftkeyPlugin::new()));
        Ok(())
    }

    /// Generate a new key pair.
    pub fn generate_key(
        &self,
        algorithm: FfiAlgorithm,
        auth: Box<dyn FfiAuthCallback>,
        progress: Box<dyn FfiProgressCallback>,
    ) -> Result<FfiGeneratedKey, FfiWscdError> {
        let auth_bridge = AuthCallbackBridge(Arc::from(auth));
        let progress_bridge = ProgressCallbackBridge(Arc::from(progress));
        let mut mgr = self.inner.lock().map_err(|e| FfiWscdError::Plugin {
            message: e.to_string(),
        })?;
        let result = self
            .rt
            .block_on(mgr.generate_key(algorithm.into(), &auth_bridge, &progress_bridge))?;
        Ok(result.into())
    }

    /// Sign data with the specified key.
    pub fn sign(
        &self,
        kid: String,
        data: Vec<u8>,
        algorithm: FfiAlgorithm,
        auth: Box<dyn FfiAuthCallback>,
        progress: Box<dyn FfiProgressCallback>,
    ) -> Result<FfiSignature, FfiWscdError> {
        let auth_bridge = AuthCallbackBridge(Arc::from(auth));
        let progress_bridge = ProgressCallbackBridge(Arc::from(progress));
        let mgr = self.inner.lock().map_err(|e| FfiWscdError::Plugin {
            message: e.to_string(),
        })?;
        let key_id = InternalKeyId(kid);
        let result = self.rt.block_on(mgr.sign(
            &key_id,
            &data,
            algorithm.into(),
            &auth_bridge,
            &progress_bridge,
        ))?;
        Ok(result.into())
    }

    /// List all keys across all registered plugins.
    pub fn list_keys(&self) -> Result<Vec<FfiKeyInfo>, FfiWscdError> {
        let mgr = self.inner.lock().map_err(|e| FfiWscdError::Plugin {
            message: e.to_string(),
        })?;
        let keys = self.rt.block_on(mgr.list_keys())?;
        Ok(keys.into_iter().map(|k| k.into()).collect())
    }

    /// Get the attestation chain for a key (X.509 certificate chain from hardware).
    ///
    /// Returns `None` if the key's plugin doesn't support attestation (e.g. softkey).
    /// For hardware-backed plugins (FIDO2/R2PS), returns the certificate chain
    /// proving the key was generated in a certified WSCD.
    pub fn attestation_chain(
        &self,
        kid: String,
    ) -> Result<Option<FfiAttestationChain>, FfiWscdError> {
        let mgr = self.inner.lock().map_err(|e| FfiWscdError::Plugin {
            message: e.to_string(),
        })?;
        let key_id = InternalKeyId(kid);
        let result = self.rt.block_on(mgr.attestation_chain(&key_id))?;
        Ok(result.map(|a| a.into()))
    }

    /// Delete a key.
    pub fn delete_key(&self, kid: String) -> Result<(), FfiWscdError> {
        let mut mgr = self.inner.lock().map_err(|e| FfiWscdError::Plugin {
            message: e.to_string(),
        })?;
        let key_id = InternalKeyId(kid);
        self.rt.block_on(mgr.delete_key(&key_id))?;
        Ok(())
    }

    /// Migrate a key to a different plugin.
    ///
    /// Returns `ReEnrollmentRequired` if the target cannot import and a new
    /// credential binding is needed with the issuer.
    pub fn migrate_key(
        &self,
        kid: String,
        target_plugin_id: String,
        auth: Box<dyn FfiAuthCallback>,
    ) -> Result<FfiMigrationResult, FfiWscdError> {
        let auth_bridge = AuthCallbackBridge(Arc::from(auth));
        let mut mgr = self.inner.lock().map_err(|e| FfiWscdError::Plugin {
            message: e.to_string(),
        })?;
        let key_id = InternalKeyId(kid);
        let result = self
            .rt
            .block_on(mgr.migrate_key(&key_id, &target_plugin_id, &auth_bridge))?;
        Ok(result.into())
    }

    /// Export softkey plugin container as JSON bytes (caller wraps in JWE).
    pub fn export_softkey_container(&self) -> Result<Vec<u8>, FfiWscdError> {
        let mgr = self.inner.lock().map_err(|e| FfiWscdError::Plugin {
            message: e.to_string(),
        })?;
        let keys = self.rt.block_on(mgr.list_keys()).unwrap_or_default();
        serde_json::to_vec(&keys).map_err(|e| FfiWscdError::Serialization {
            message: e.to_string(),
        })
    }

    /// Import a softkey container (JSON bytes), replacing the current softkey state.
    pub fn import_softkey_container(&self, container: Vec<u8>) -> Result<(), FfiWscdError> {
        let plugin =
            SoftkeyPlugin::from_container(&container).map_err(|e| FfiWscdError::Serialization {
                message: e.to_string(),
            })?;
        let mut mgr = self.inner.lock().map_err(|e| FfiWscdError::Plugin {
            message: e.to_string(),
        })?;
        mgr.register_plugin(Arc::new(plugin));
        Ok(())
    }
}
