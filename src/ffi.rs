//! UniFFI bridge — exposes the WSCD manager to Swift/Kotlin via FFI.
//!
//! Uses the proc-macro approach (no UDL file). Types are annotated with
//! `#[derive(uniffi::...)]` and methods with `#[uniffi::export]`.

use std::sync::{Arc, Mutex};

use crate::callbacks as cb;
#[cfg(feature = "plugin-r2ps")]
use crate::config::R2psConfig;
use crate::config::WscdConfig as InternalConfig;
use crate::error::WscdError as InternalError;
use crate::manager::WscdManager as InternalManager;
use crate::plugins::softkey::SoftkeyPlugin;
use crate::types::{
    Algorithm as InternalAlgorithm, AttestationChain as InternalAttestationChain,
    CertificationLevel as InternalCertificationLevel, GeneratedKey as InternalGeneratedKey,
    KeyId as InternalKeyId, KeyInfo as InternalKeyInfo, KeyStorageType as InternalKeyStorageType,
    MigrationResult as InternalMigrationResult, OperationProgress as InternalOperationProgress,
    SecurityProperties as InternalSecurityProperties, Signature as InternalSignature,
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
            InternalMigrationResult::Migrated { new_kid } => {
                FfiMigrationResult::Migrated { new_kid: new_kid.0 }
            }
            InternalMigrationResult::ReEnrollmentRequired { old_kid } => {
                FfiMigrationResult::ReEnrollmentRequired { old_kid: old_kid.0 }
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
    #[error("auth required: {message}")]
    AuthRequired { message: String },
    #[error("auth cancelled: {message}")]
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

// ─── R2PS FFI types (feature-gated) ──────────────────────────────────────────

/// Configuration for the R2PS plugin, passed from the host SDK.
#[derive(uniffi::Record, Clone)]
pub struct FfiR2psConfig {
    /// R2PS server URL (e.g. "https://r2ps.example.com/r2ps").
    pub server_url: String,
    /// Client ID registered with the R2PS server.
    pub client_id: String,
    /// Context string for service requests.
    pub context: String,
    /// Authentication mode: "opaque" or "webauthn".
    pub auth_mode: String,
    /// Relying Party ID for WebAuthn ceremonies (required when auth_mode = "webauthn").
    pub rp_id: String,
    /// Allowed credential IDs for WebAuthn (base64url-encoded).
    pub allowed_credential_ids: Vec<String>,
    /// PEM-encoded P-256 client private key for JWS envelope signing.
    pub client_key_pem: String,
    /// PEM-encoded P-256 server public key for JWE envelope encryption.
    pub server_public_key_pem: String,
}

/// Host-provided HTTP transport for R2PS protocol messages.
#[uniffi::export(callback_interface)]
pub trait FfiHttpTransport: Send + Sync {
    /// Send a raw request body to the R2PS server and return the response bytes.
    fn send(&self, body: Vec<u8>) -> Result<Vec<u8>, FfiWscdError>;
}

/// Host-provided OPAQUE (RFC 9807) client for R2PS PAKE authentication.
///
/// The wire format must be compatible with bytemare/opaque (Go).
/// The host SDK should use a platform OPAQUE library that implements the
/// same VOPRF suite (P256-SHA256) as the server.
#[uniffi::export(callback_interface)]
pub trait FfiPakeClient: Send + Sync {
    /// Start registration: returns serialized RegistrationRequest.
    fn registration_init(&self, password: Vec<u8>) -> Result<Vec<u8>, FfiWscdError>;
    /// Finalize registration: consumes RegistrationResponse, returns RegistrationRecord.
    fn registration_finalize(&self, server_resp: Vec<u8>) -> Result<Vec<u8>, FfiWscdError>;
    /// Start authentication: returns serialized KE1.
    fn auth_init(&self, password: Vec<u8>) -> Result<Vec<u8>, FfiWscdError>;
    /// Finalize authentication: consumes KE2, returns KE3 + session_key concatenated.
    fn auth_finalize(&self, server_resp: Vec<u8>) -> Result<Vec<u8>, FfiWscdError>;
}

// ─── Security Properties (CS-04 §7.1.3) ─────────────────────────────────────

#[derive(uniffi::Enum, Clone)]
pub enum FfiKeyStorageType {
    Software,
    Hardware,
    RemoteHsm,
    TrustedExecution,
}

impl From<InternalKeyStorageType> for FfiKeyStorageType {
    fn from(k: InternalKeyStorageType) -> Self {
        match k {
            InternalKeyStorageType::Software => FfiKeyStorageType::Software,
            InternalKeyStorageType::Hardware => FfiKeyStorageType::Hardware,
            InternalKeyStorageType::RemoteHsm => FfiKeyStorageType::RemoteHsm,
            InternalKeyStorageType::TrustedExecution => FfiKeyStorageType::TrustedExecution,
        }
    }
}

#[derive(uniffi::Enum, Clone)]
pub enum FfiCertificationLevel {
    None,
    Baseline,
    Substantial,
    High,
}

impl From<InternalCertificationLevel> for FfiCertificationLevel {
    fn from(c: InternalCertificationLevel) -> Self {
        match c {
            InternalCertificationLevel::None => FfiCertificationLevel::None,
            InternalCertificationLevel::Baseline => FfiCertificationLevel::Baseline,
            InternalCertificationLevel::Substantial => FfiCertificationLevel::Substantial,
            InternalCertificationLevel::High => FfiCertificationLevel::High,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiSecurityProperties {
    pub key_storage: FfiKeyStorageType,
    pub user_authentication: Vec<String>,
    pub certification: FfiCertificationLevel,
    pub amr: Vec<String>,
}

impl From<InternalSecurityProperties> for FfiSecurityProperties {
    fn from(s: InternalSecurityProperties) -> Self {
        FfiSecurityProperties {
            key_storage: s.key_storage.into(),
            user_authentication: s.user_authentication,
            certification: s.certification.into(),
            amr: s.amr,
        }
    }
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

// ─── R2PS bridge adapters (foreign callback → r2ps_client traits) ────────────

#[cfg(feature = "plugin-r2ps")]
struct FfiTransportBridge(Arc<dyn FfiHttpTransport>);

#[cfg(feature = "plugin-r2ps")]
impl r2ps_client::Transport for FfiTransportBridge {
    fn send(&self, body: &[u8]) -> r2ps_client::error::Result<Vec<u8>> {
        self.0
            .send(body.to_vec())
            .map_err(|e| r2ps_client::error::R2psError::Transport(format!("{e}")))
    }
}

#[cfg(feature = "plugin-r2ps")]
struct FfiPakeClientBridge {
    inner: std::sync::Mutex<Box<dyn FfiPakeClient>>,
}

#[cfg(feature = "plugin-r2ps")]
impl r2ps_client::PakeClient for FfiPakeClientBridge {
    fn registration_init(&mut self, password: &[u8]) -> r2ps_client::error::Result<Vec<u8>> {
        let pake = self
            .inner
            .lock()
            .map_err(|e| r2ps_client::error::R2psError::Pake(e.to_string()))?;
        pake.registration_init(password.to_vec())
            .map_err(|e| r2ps_client::error::R2psError::Pake(format!("{e}")))
    }

    fn registration_finalize(&mut self, server_resp: &[u8]) -> r2ps_client::error::Result<Vec<u8>> {
        let pake = self
            .inner
            .lock()
            .map_err(|e| r2ps_client::error::R2psError::Pake(e.to_string()))?;
        pake.registration_finalize(server_resp.to_vec())
            .map_err(|e| r2ps_client::error::R2psError::Pake(format!("{e}")))
    }

    fn auth_init(&mut self, password: &[u8]) -> r2ps_client::error::Result<Vec<u8>> {
        let pake = self
            .inner
            .lock()
            .map_err(|e| r2ps_client::error::R2psError::Pake(e.to_string()))?;
        pake.auth_init(password.to_vec())
            .map_err(|e| r2ps_client::error::R2psError::Pake(format!("{e}")))
    }

    fn auth_finalize(
        &mut self,
        server_resp: &[u8],
    ) -> r2ps_client::error::Result<(Vec<u8>, Vec<u8>)> {
        let pake = self
            .inner
            .lock()
            .map_err(|e| r2ps_client::error::R2psError::Pake(e.to_string()))?;
        let combined = pake
            .auth_finalize(server_resp.to_vec())
            .map_err(|e| r2ps_client::error::R2psError::Pake(format!("{e}")))?;
        // The callback returns KE3 || session_key concatenated.
        // KE3 is the first part, session_key (32 bytes) is the last 32 bytes.
        if combined.len() < 32 {
            return Err(r2ps_client::error::R2psError::Pake(
                "auth_finalize response too short: expected KE3 + 32-byte session key".into(),
            ));
        }
        let split = combined.len() - 32;
        let ke3 = combined[..split].to_vec();
        let session_key = combined[split..].to_vec();
        Ok((ke3, session_key))
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
        let rt = tokio::runtime::Builder::new_multi_thread()
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
        let result =
            self.rt
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
    ///
    /// Exports the actual StoredKey data (including private material)
    /// so it can round-trip through import_softkey_container.
    pub fn export_softkey_container(&self) -> Result<Vec<u8>, FfiWscdError> {
        let mgr = self.inner.lock().map_err(|e| FfiWscdError::Plugin {
            message: e.to_string(),
        })?;
        // Get the softkey plugin and use its native export
        let plugin = mgr
            .get_plugin_by_id("softkey")
            .map_err(|e| FfiWscdError::NoPlugin {
                message: e.to_string(),
            })?;
        let softkey = plugin
            .as_any()
            .downcast_ref::<crate::plugins::softkey::SoftkeyPlugin>()
            .ok_or_else(|| FfiWscdError::Plugin {
                message: "softkey plugin is not a SoftkeyPlugin".to_string(),
            })?;
        softkey
            .export_container()
            .map_err(|e| FfiWscdError::Serialization {
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

    /// Get the security properties for a key (CS-04 §7.1.3).
    ///
    /// Returns key storage type, user authentication methods, certification level,
    /// and AMR values from the last signing operation.
    pub fn security_properties(&self, kid: String) -> Result<FfiSecurityProperties, FfiWscdError> {
        let mgr = self.inner.lock().map_err(|e| FfiWscdError::Plugin {
            message: e.to_string(),
        })?;
        let key_id = InternalKeyId(kid);
        let props = mgr.security_properties(&key_id)?;
        Ok(props.into())
    }
}

// ─── R2PS plugin registration (feature-gated) ───────────────────────────────

#[cfg(feature = "plugin-r2ps")]
#[uniffi::export]
impl FfiWscdManager {
    /// Register the R2PS plugin for remote HSM signing.
    ///
    /// The host SDK must provide:
    /// - `transport`: HTTP transport for sending R2PS protocol messages
    /// - `pake`: OPAQUE (RFC 9807) client compatible with bytemare/opaque
    /// - `config`: R2PS server connection parameters including PEM-encoded P-256
    ///   keys for JWS/JWE envelope protection
    pub fn register_r2ps_plugin(
        &self,
        config: FfiR2psConfig,
        transport: Box<dyn FfiHttpTransport>,
        pake: Box<dyn FfiPakeClient>,
    ) -> Result<(), FfiWscdError> {
        use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};

        let client_key = p256::SecretKey::from_pkcs8_pem(&config.client_key_pem).map_err(|e| {
            FfiWscdError::Crypto {
                message: format!("invalid client key PEM: {e}"),
            }
        })?;

        let server_pub = p256::PublicKey::from_public_key_pem(&config.server_public_key_pem)
            .map_err(|e| FfiWscdError::Crypto {
                message: format!("invalid server public key PEM: {e}"),
            })?;

        let transport_bridge = FfiTransportBridge(Arc::from(transport));
        let pake_bridge = FfiPakeClientBridge {
            inner: std::sync::Mutex::new(pake),
        };

        let r2ps_client = r2ps_client::R2psClient::new(
            config.client_id.clone(),
            config.context.clone(),
            client_key,
            server_pub,
            transport_bridge,
            pake_bridge,
        );

        let r2ps_config = R2psConfig {
            server_url: config.server_url,
            client_id: config.client_id,
            context: config.context,
            auth_mode: config.auth_mode,
            rp_id: config.rp_id,
            allowed_credential_ids: config.allowed_credential_ids,
        };

        let plugin =
            crate::plugins::r2ps::R2psPlugin::new(r2ps_client, r2ps_config).map_err(|e| {
                FfiWscdError::Plugin {
                    message: format!("R2PS plugin init failed: {e}"),
                }
            })?;

        let mut mgr = self.inner.lock().map_err(|e| FfiWscdError::Plugin {
            message: e.to_string(),
        })?;
        mgr.register_plugin(Arc::new(plugin));
        Ok(())
    }
}
