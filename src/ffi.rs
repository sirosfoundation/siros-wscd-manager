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
use crate::factors as fct;
use crate::manager::WscdManager as InternalManager;
use crate::plugins::softkey::SoftkeyPlugin;
use crate::types::Secret as InternalSecret;
use crate::types::{
    ActivateLifecycleRequest as InternalActivateLifecycleRequest,
    ActivationOutcome as InternalActivationOutcome, Algorithm as InternalAlgorithm,
    AttestationChain as InternalAttestationChain, AttestationFormat as InternalAttestationFormat,
    CertificationLevel as InternalCertificationLevel,
    DestroyLifecycleRequest as InternalDestroyLifecycleRequest, DestroyMode as InternalDestroyMode,
    DestructionOutcome as InternalDestructionOutcome, FactorKind as InternalFactorKind,
    GeneratedKey as InternalGeneratedKey, KeyId as InternalKeyId, KeyInfo as InternalKeyInfo,
    KeyStorageType as InternalKeyStorageType, LifecycleState as InternalLifecycleState,
    LifecycleStatus as InternalLifecycleStatus, MigrationResult as InternalMigrationResult,
    OperationProgress as InternalOperationProgress,
    RegisterLifecycleRequest as InternalRegisterLifecycleRequest,
    RegistrationOutcome as InternalRegistrationOutcome,
    RotateLifecycleRequest as InternalRotateLifecycleRequest,
    RotationOutcome as InternalRotationOutcome, SecurityProperties as InternalSecurityProperties,
    Signature as InternalSignature,
};

// ─── UniFFI-visible types ────────────────────────────────────────────────────

#[derive(uniffi::Enum, Clone)]
pub enum FfiAlgorithm {
    ES256,
    EdDSA,
    /// See [`InternalAlgorithm::Bls12381G1Schnorr`] — BBS key binding,
    /// COSE -65609. Only the `fido2` plugin can serve this, and only on
    /// YubiKey 5.8 alpha firmware.
    Bls12381G1Schnorr,
}

impl From<FfiAlgorithm> for InternalAlgorithm {
    fn from(a: FfiAlgorithm) -> Self {
        match a {
            FfiAlgorithm::ES256 => InternalAlgorithm::ES256,
            FfiAlgorithm::EdDSA => InternalAlgorithm::EdDSA,
            FfiAlgorithm::Bls12381G1Schnorr => InternalAlgorithm::Bls12381G1Schnorr,
        }
    }
}

impl From<InternalAlgorithm> for FfiAlgorithm {
    fn from(a: InternalAlgorithm) -> Self {
        match a {
            InternalAlgorithm::ES256 => FfiAlgorithm::ES256,
            InternalAlgorithm::EdDSA => FfiAlgorithm::EdDSA,
            InternalAlgorithm::Bls12381G1Schnorr => FfiAlgorithm::Bls12381G1Schnorr,
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

#[derive(uniffi::Enum, Clone)]
pub enum FfiFactorKind {
    Opaque,
    WebAuthn,
    RawSign,
}

impl From<FfiFactorKind> for InternalFactorKind {
    fn from(v: FfiFactorKind) -> Self {
        match v {
            FfiFactorKind::Opaque => InternalFactorKind::Opaque,
            FfiFactorKind::WebAuthn => InternalFactorKind::WebAuthn,
            FfiFactorKind::RawSign => InternalFactorKind::RawSign,
        }
    }
}

impl From<InternalFactorKind> for FfiFactorKind {
    fn from(v: InternalFactorKind) -> Self {
        match v {
            InternalFactorKind::Opaque => FfiFactorKind::Opaque,
            InternalFactorKind::WebAuthn => FfiFactorKind::WebAuthn,
            InternalFactorKind::RawSign => FfiFactorKind::RawSign,
        }
    }
}

#[derive(uniffi::Enum, Clone)]
pub enum FfiLifecycleState {
    Uninitialized,
    Registered,
    Active,
    Suspended,
    Destroyed,
}

impl From<InternalLifecycleState> for FfiLifecycleState {
    fn from(v: InternalLifecycleState) -> Self {
        match v {
            InternalLifecycleState::Uninitialized => FfiLifecycleState::Uninitialized,
            InternalLifecycleState::Registered => FfiLifecycleState::Registered,
            InternalLifecycleState::Active => FfiLifecycleState::Active,
            InternalLifecycleState::Suspended => FfiLifecycleState::Suspended,
            InternalLifecycleState::Destroyed => FfiLifecycleState::Destroyed,
        }
    }
}

impl From<FfiLifecycleState> for InternalLifecycleState {
    fn from(v: FfiLifecycleState) -> Self {
        match v {
            FfiLifecycleState::Uninitialized => InternalLifecycleState::Uninitialized,
            FfiLifecycleState::Registered => InternalLifecycleState::Registered,
            FfiLifecycleState::Active => InternalLifecycleState::Active,
            FfiLifecycleState::Suspended => InternalLifecycleState::Suspended,
            FfiLifecycleState::Destroyed => InternalLifecycleState::Destroyed,
        }
    }
}

#[derive(uniffi::Enum, Clone)]
pub enum FfiDestroyMode {
    LocalOnly,
    RemoteRevokeIfSupported,
    Strict,
}

impl From<FfiDestroyMode> for InternalDestroyMode {
    fn from(v: FfiDestroyMode) -> Self {
        match v {
            FfiDestroyMode::LocalOnly => InternalDestroyMode::LocalOnly,
            FfiDestroyMode::RemoteRevokeIfSupported => InternalDestroyMode::RemoteRevokeIfSupported,
            FfiDestroyMode::Strict => InternalDestroyMode::Strict,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiLifecycleStatus {
    pub context_id: String,
    pub plugin_id: String,
    pub factor_kind: FfiFactorKind,
    pub state: FfiLifecycleState,
    pub updated_at: i64,
}

impl From<InternalLifecycleStatus> for FfiLifecycleStatus {
    fn from(v: InternalLifecycleStatus) -> Self {
        FfiLifecycleStatus {
            context_id: v.context_id,
            plugin_id: v.plugin_id,
            factor_kind: v.factor_kind.into(),
            state: v.state.into(),
            updated_at: v.updated_at,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiRegisterLifecycleRequest {
    pub plugin_id: String,
    pub context_id: String,
    pub factor_kind: FfiFactorKind,
}

impl From<FfiRegisterLifecycleRequest> for InternalRegisterLifecycleRequest {
    fn from(v: FfiRegisterLifecycleRequest) -> Self {
        InternalRegisterLifecycleRequest {
            plugin_id: v.plugin_id,
            context_id: v.context_id,
            factor_kind: v.factor_kind.into(),
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiActivateLifecycleRequest {
    pub plugin_id: String,
    pub context_id: String,
}

impl From<FfiActivateLifecycleRequest> for InternalActivateLifecycleRequest {
    fn from(v: FfiActivateLifecycleRequest) -> Self {
        InternalActivateLifecycleRequest {
            plugin_id: v.plugin_id,
            context_id: v.context_id,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiRotateLifecycleRequest {
    pub plugin_id: String,
    pub context_id: String,
}

impl From<FfiRotateLifecycleRequest> for InternalRotateLifecycleRequest {
    fn from(v: FfiRotateLifecycleRequest) -> Self {
        InternalRotateLifecycleRequest {
            plugin_id: v.plugin_id,
            context_id: v.context_id,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiDestroyLifecycleRequest {
    pub plugin_id: String,
    pub context_id: String,
    pub mode: FfiDestroyMode,
    pub reason: Option<String>,
}

impl From<FfiDestroyLifecycleRequest> for InternalDestroyLifecycleRequest {
    fn from(v: FfiDestroyLifecycleRequest) -> Self {
        InternalDestroyLifecycleRequest {
            plugin_id: v.plugin_id,
            context_id: v.context_id,
            mode: v.mode.into(),
            reason: v.reason,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiRegistrationOutcome {
    pub context_id: String,
    pub state: FfiLifecycleState,
}

impl From<InternalRegistrationOutcome> for FfiRegistrationOutcome {
    fn from(v: InternalRegistrationOutcome) -> Self {
        FfiRegistrationOutcome {
            context_id: v.context_id,
            state: v.state.into(),
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiActivationOutcome {
    pub context_id: String,
    pub state: FfiLifecycleState,
}

impl From<InternalActivationOutcome> for FfiActivationOutcome {
    fn from(v: InternalActivationOutcome) -> Self {
        FfiActivationOutcome {
            context_id: v.context_id,
            state: v.state.into(),
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiRotationOutcome {
    pub context_id: String,
    pub state: FfiLifecycleState,
}

impl From<InternalRotationOutcome> for FfiRotationOutcome {
    fn from(v: InternalRotationOutcome) -> Self {
        FfiRotationOutcome {
            context_id: v.context_id,
            state: v.state.into(),
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiDestructionOutcome {
    pub context_id: String,
    pub state: FfiLifecycleState,
    pub remote_performed: bool,
}

impl From<InternalDestructionOutcome> for FfiDestructionOutcome {
    fn from(v: InternalDestructionOutcome) -> Self {
        FfiDestructionOutcome {
            context_id: v.context_id,
            state: v.state.into(),
            remote_performed: v.remote_performed,
        }
    }
}

// Note: variant fields are named `msg`, NOT `message` - UniFFI's Kotlin
// codegen translates this record field verbatim, and every error class it
// generates already subclasses `kotlin.Exception`/`Throwable`, which has
// its own `message` property. A field literally named `message` produces
// a real Kotlin compile error ("conflicting declarations" / "hides member
// of supertype and needs an 'override' modifier") in every generated
// variant class - confirmed by regenerating real Kotlin bindings from this
// crate. Do not rename this back to `message`.
#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum FfiWscdError {
    #[error("no plugin: {msg}")]
    NoPlugin { msg: String },
    #[error("unsupported: {msg}")]
    Unsupported { msg: String },
    #[error("key not found: {msg}")]
    KeyNotFound { msg: String },
    #[error("auth required: {msg}")]
    AuthRequired { msg: String },
    #[error("auth cancelled: {msg}")]
    AuthCancelled { msg: String },
    #[error("re-enrollment required: {msg}")]
    ReEnrollmentRequired { msg: String },
    #[error("plugin error: {msg}")]
    Plugin { msg: String },
    #[error("callback error: {msg}")]
    Callback { msg: String },
    #[error("serialization error: {msg}")]
    Serialization { msg: String },
    #[error("crypto error: {msg}")]
    Crypto { msg: String },
    /// A CTAP2 PIN set/use was refused; `reason` says why so the host can
    /// re-prompt. `msg` never contains PIN material.
    #[error("PIN error: {msg}")]
    Pin { reason: FfiPinFailure, msg: String },
}

/// See [`crate::error::PinFailure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiPinFailure {
    TooShort { min_length: u32 },
    TooLong,
    InvalidEncoding,
    PolicyViolation,
    Invalid,
    Blocked,
    AuthBlocked,
    NotSet,
}

impl From<crate::error::PinFailure> for FfiPinFailure {
    fn from(f: crate::error::PinFailure) -> Self {
        use crate::error::PinFailure as P;
        match f {
            P::TooShort { min_length } => Self::TooShort { min_length },
            P::TooLong => Self::TooLong,
            P::InvalidEncoding => Self::InvalidEncoding,
            P::PolicyViolation => Self::PolicyViolation,
            P::Invalid => Self::Invalid,
            P::Blocked => Self::Blocked,
            P::AuthBlocked => Self::AuthBlocked,
            P::NotSet => Self::NotSet,
        }
    }
}

impl From<InternalError> for FfiWscdError {
    fn from(e: InternalError) -> Self {
        let msg = e.to_string();
        match e {
            InternalError::NoPlugin { .. } => FfiWscdError::NoPlugin { msg },
            InternalError::NoDefault { .. } => FfiWscdError::NoPlugin { msg },
            InternalError::Unsupported { .. } => FfiWscdError::Unsupported { msg },
            InternalError::KeyNotFound { .. } => FfiWscdError::KeyNotFound { msg },
            InternalError::AuthRequired => FfiWscdError::AuthRequired { msg },
            InternalError::AuthCancelled => FfiWscdError::AuthCancelled { msg },
            InternalError::ReEnrollmentRequired { .. } => {
                FfiWscdError::ReEnrollmentRequired { msg }
            }
            InternalError::Plugin(_) => FfiWscdError::Plugin { msg },
            InternalError::Callback(_) => FfiWscdError::Callback { msg },
            InternalError::Serialization(_) => FfiWscdError::Serialization { msg },
            InternalError::Crypto(_) => FfiWscdError::Crypto { msg },
            InternalError::Pin(f) => FfiWscdError::Pin {
                reason: f.into(),
                msg,
            },
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

/// Mirrors [`InternalAttestationFormat`] — see its doc comment.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum FfiAttestationFormat {
    X509Chain,
    Opaque,
}

impl From<InternalAttestationFormat> for FfiAttestationFormat {
    fn from(f: InternalAttestationFormat) -> Self {
        match f {
            InternalAttestationFormat::X509Chain => FfiAttestationFormat::X509Chain,
            InternalAttestationFormat::Opaque => FfiAttestationFormat::Opaque,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiAttestationChain {
    pub format: FfiAttestationFormat,
    pub certificates: Vec<Vec<u8>>,
    pub client_data_hash: Vec<u8>,
    pub opaque_attestation: Vec<u8>,
}

impl From<InternalAttestationChain> for FfiAttestationChain {
    fn from(a: InternalAttestationChain) -> Self {
        FfiAttestationChain {
            format: a.format.into(),
            certificates: a.certificates,
            client_data_hash: a.client_data_hash,
            opaque_attestation: a.opaque_attestation,
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

// ─── TS12 authentication factors (EC TS12 v1.0.1 section 3.6) ───────────────

/// The `amr` entry's key.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq, Debug)]
pub enum FfiFactorCategory {
    Knowledge,
    Possession,
    Inherence,
}

impl From<fct::FactorCategory> for FfiFactorCategory {
    fn from(c: fct::FactorCategory) -> Self {
        match c {
            fct::FactorCategory::Knowledge => Self::Knowledge,
            fct::FactorCategory::Possession => Self::Possession,
            fct::FactorCategory::Inherence => Self::Inherence,
        }
    }
}

impl From<FfiFactorCategory> for fct::FactorCategory {
    fn from(c: FfiFactorCategory) -> Self {
        match c {
            FfiFactorCategory::Knowledge => Self::Knowledge,
            FfiFactorCategory::Possession => Self::Possession,
            FfiFactorCategory::Inherence => Self::Inherence,
        }
    }
}

/// One `amr` entry: `{<category>: <method>}`. `method` is a TS12 vocabulary
/// value such as `key_in_remote_wscd` or `pin_6_or_more_digits`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiAuthFactor {
    pub category: FfiFactorCategory,
    pub method: String,
}

impl From<fct::AuthFactor> for FfiAuthFactor {
    fn from(f: fct::AuthFactor) -> Self {
        Self {
            category: f.category.into(),
            method: f.method,
        }
    }
}

/// The factors applied to ONE sign. When `satisfies_two_categories` is false
/// the SDK must refuse SCA; `shortfall` says why.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiAuthFactors {
    pub factors: Vec<FfiAuthFactor>,
    pub satisfies_two_categories: bool,
    pub shortfall: Option<String>,
}

impl From<fct::AuthFactors> for FfiAuthFactors {
    fn from(f: fct::AuthFactors) -> Self {
        Self {
            satisfies_two_categories: f.satisfies_two_categories(),
            shortfall: f.shortfall().map(str::to_string),
            factors: f.factors().iter().cloned().map(Into::into).collect(),
        }
    }
}

/// Per-sign options. All defaults reproduce a plain `sign`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiSignOptions {
    /// Force a NEW user authentication for this sign (no cached session or
    /// token). Only paths that really perform a fresh PIN/UV in this call
    /// honour it (R2PS OPAQUE, FIDO2 on a raw transport). Any plugin that
    /// cannot guarantee it (softkey, R2PS WebAuthn, a transport that runs
    /// UV itself) fails with `Unsupported` BEFORE signing.
    #[uniffi(default = false)]
    pub require_fresh_user_authentication: bool,
    /// A knowledge/inherence factor the host performed for this sign. Used
    /// only when the plugin observed user verification without learning its
    /// method (R2PS WebAuthn, a UV-performing CTAP2 transport).
    #[uniffi(default = None)]
    pub host_verified_factor: Option<FfiAuthFactor>,
}

impl TryFrom<FfiSignOptions> for fct::SignOptions {
    type Error = InternalError;
    fn try_from(o: FfiSignOptions) -> Result<Self, InternalError> {
        let options = fct::SignOptions {
            require_fresh_user_authentication: o.require_fresh_user_authentication,
            host_verified_factor: o
                .host_verified_factor
                .map(|f| fct::AuthFactor::new(f.category.into(), &f.method))
                .transpose()?,
        };
        options.validate()?;
        Ok(options)
    }
}

/// A signature and the factors applied to produce THIS signature.
#[derive(uniffi::Record, Clone)]
pub struct FfiSignOutcome {
    pub signature: FfiSignature,
    pub factors: FfiAuthFactors,
}

/// Side-effect-free pre-consent answer to "can this key's plugin reach two
/// categories?".
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiFactorCapability {
    pub can_reach_two_categories: bool,
    /// True when only `FfiSignOptions.host_verified_factor` can supply the
    /// second category (then `can_reach_two_categories` is false).
    pub requires_host_verified_factor: bool,
    pub reason: Option<String>,
}

impl From<fct::FactorCapability> for FfiFactorCapability {
    fn from(c: fct::FactorCapability) -> Self {
        Self {
            can_reach_two_categories: c.can_reach_two_categories,
            requires_host_verified_factor: c.requires_host_verified_factor,
            reason: c.reason,
        }
    }
}

// ─── Callback interfaces ─────────────────────────────────────────────────────

#[uniffi::export(callback_interface)]
pub trait FfiAuthCallback: Send + Sync {
    /// Ask the user to ENTER the PIN already set on the authenticator (or
    /// the OPAQUE PIN for r2ps).
    fn request_pin(&self, plugin_id: String) -> Result<Vec<u8>, FfiWscdError>;
    /// Ask the user to CHOOSE a new PIN for an authenticator that has none
    /// (CTAP2 `clientPin: false`). Show "Choose a PIN" (ideally with
    /// confirmation) and enforce `min_length` characters; the value is sent
    /// to the authenticator's setPIN. Called instead of `request_pin`, never
    /// in addition to it, within one ceremony.
    fn request_new_pin(&self, plugin_id: String, min_length: u32) -> Result<Vec<u8>, FfiWscdError>;
    fn request_webauthn_assertion(
        &self,
        plugin_id: String,
        challenge: Vec<u8>,
        rp_id: String,
        allowed_credentials: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, FfiWscdError>;
}

#[uniffi::export(callback_interface)]
pub trait FfiProgressCallback: Send + Sync {
    fn on_progress(&self, progress: FfiOperationProgress);
}

/// Host-provided raw CTAP2 message transport for the previewSign (WebAuthn
/// "sign extension") plugin.
///
/// The host SDK owns the channel to the authenticator (BLE/NFC/USB) and
/// all of its transport-specific framing (CTAPHID chunking over USB HID,
/// NFCCTAP_MSG/ISO 7816 APDU wrapping over NFC, ...) - this callback sees
/// only the logical CTAP2 message layer: `command` is a leading
/// command-code byte followed by CBOR params (already built by this
/// crate); the return value is a leading status byte followed by CBOR
/// body (or just the status byte on error), exactly as received from the
/// authenticator. ALL previewSign CBOR request-building and
/// response-parsing lives in [`crate::preview_sign_protocol`] - do not
/// reimplement it in a host SDK. This design is confirmed against real
/// YubiKey 5.8 hardware (2026-08-04).
#[cfg(feature = "plugin-fido2")]
#[uniffi::export(callback_interface)]
pub trait FfiCtap2Transport: Send + Sync {
    fn ctap2_send_command(&self, command: Vec<u8>) -> Result<Vec<u8>, FfiWscdError>;
}

#[cfg(feature = "plugin-fido2")]
#[derive(uniffi::Record, Clone)]
pub struct FfiEcPublicKey {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

/// Host-provided access to Apple's Secure Enclave for the `apple-se` plugin.
///
/// The host implements this over CryptoKit's
/// `SecureEnclave.P256.Signing.PrivateKey` + a Keychain tag - Rust has no
/// portable way to drive the Secure Enclave directly, the same reason
/// [`FfiCtap2Transport`] exists for FIDO2 authenticators. See
/// [`crate::callbacks::SecureEnclaveCallback`]'s doc comment (the trait this
/// bridges to) for the staged-release no-attestation contract and the raw
/// `r || s` signature format expected back from `sign`.
#[cfg(feature = "plugin-apple-se")]
#[uniffi::export(callback_interface)]
pub trait FfiSecureEnclaveCallback: Send + Sync {
    fn generate_key(&self, key_tag: String) -> Result<FfiSecureEnclavePublicKey, FfiWscdError>;
    fn sign(&self, key_tag: String, data: Vec<u8>) -> Result<Vec<u8>, FfiWscdError>;
    fn delete_key(&self, key_tag: String) -> Result<(), FfiWscdError>;
}

#[cfg(feature = "plugin-apple-se")]
#[derive(uniffi::Record, Clone)]
pub struct FfiSecureEnclavePublicKey {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

/// This crate's own version (`CARGO_PKG_VERSION`), for host apps to
/// display in diagnostics/dev screens - the single source of truth,
/// regardless of how a build resolved the dependency (published vs
/// `mavenLocal`/local `Package.swift` override).
#[uniffi::export]
pub fn wscd_manager_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Decode an EC2 COSE_Key (kty=2) into its (x, y) coordinates. Exposed to
/// native SDKs so a [`FfiCtap2Transport`] implementation can reuse this
/// crate's COSE parsing instead of shipping its own.
#[cfg(feature = "plugin-fido2")]
#[uniffi::export]
pub fn decode_cose_ec2_public_key(cose_bytes: Vec<u8>) -> Result<FfiEcPublicKey, FfiWscdError> {
    let (x, y) = crate::preview_sign_protocol::decode_cose_ec2_public_key(&cose_bytes)?;
    Ok(FfiEcPublicKey { x, y })
}

/// Extract the previewSign signature (extension output key `6`) from a
/// getAssertion response's `authenticatorData`.
#[cfg(feature = "plugin-fido2")]
#[uniffi::export]
pub fn extract_previewsign_signature(authenticator_data: Vec<u8>) -> Result<Vec<u8>, FfiWscdError> {
    Ok(crate::preview_sign_protocol::extract_previewsign_signature(
        &authenticator_data,
    )?)
}

// ─── Bridge adapters (foreign callback → Rust async trait) ───────────────────

struct AuthCallbackBridge(Arc<dyn FfiAuthCallback>);

#[async_trait::async_trait]
impl cb::AuthCallback for AuthCallbackBridge {
    async fn request_pin(&self, plugin_id: &str) -> crate::error::Result<InternalSecret> {
        self.0
            .request_pin(plugin_id.to_string())
            .map(InternalSecret)
            .map_err(|e| InternalError::Callback(format!("{e}")))
    }

    async fn request_pin_for(
        &self,
        plugin_id: &str,
        kind: cb::PinRequestKind,
    ) -> crate::error::Result<InternalSecret> {
        match kind {
            cb::PinRequestKind::EnterPin => self.request_pin(plugin_id).await,
            cb::PinRequestKind::SetNewPin { min_length } => self
                .0
                .request_new_pin(plugin_id.to_string(), min_length)
                .map(InternalSecret)
                .map_err(|e| InternalError::Callback(format!("{e}"))),
        }
    }

    async fn request_webauthn_assertion(
        &self,
        plugin_id: &str,
        challenge: &[u8],
        rp_id: &str,
        allowed_credentials: &[Vec<u8>],
    ) -> crate::error::Result<Vec<u8>> {
        self.0
            .request_webauthn_assertion(
                plugin_id.to_string(),
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

// ─── CTAP2 bridge adapter (foreign callback → Ctap2Transport) ────────────────

#[cfg(feature = "plugin-fido2")]
struct Ctap2TransportBridge {
    inner: Arc<dyn FfiCtap2Transport>,
}

#[cfg(feature = "plugin-fido2")]
#[async_trait::async_trait]
impl cb::Ctap2Transport for Ctap2TransportBridge {
    async fn ctap2_send_command(&self, command: &[u8]) -> crate::error::Result<Vec<u8>> {
        self.inner
            .ctap2_send_command(command.to_vec())
            .map_err(|e| InternalError::Callback(format!("{e}")))
    }
}

// ─── Secure Enclave bridge adapter (foreign callback → SecureEnclaveCallback) ─

#[cfg(feature = "plugin-apple-se")]
struct SecureEnclaveCallbackBridge {
    inner: Arc<dyn FfiSecureEnclaveCallback>,
}

/// Maps a [`FfiWscdError`] the host threw from inside a
/// [`FfiSecureEnclaveCallback`] method back to the matching [`InternalError`]
/// variant, rather than collapsing everything into `InternalError::Callback`.
///
/// This matters specifically for `AuthCancelled`/`AuthRequired`: a host
/// implementation throws one of those when the user cancels (or hasn't yet
/// satisfied) the Secure Enclave key's biometric/passcode gate, and
/// `WscdPlugin::sign`/`generate_key` callers branch on that distinction to
/// decide whether retrying makes sense - see the error-mapping contract
/// documented on `internal_errors_map_to_the_intended_ffi_variants` (the
/// reverse direction of this same mapping). Collapsing it into a generic
/// `Callback` error would silently take that signal away for this plugin
/// only, while every other plugin kept it.
#[cfg(feature = "plugin-apple-se")]
fn secure_enclave_callback_error(e: FfiWscdError) -> InternalError {
    match e {
        FfiWscdError::AuthCancelled { .. } => InternalError::AuthCancelled,
        FfiWscdError::AuthRequired { .. } => InternalError::AuthRequired,
        // Preserved so `AppleSecureEnclavePlugin::delete_key` can treat "the
        // host's Keychain item is already gone" as idempotent success
        // rather than a stuck failure - see that method's doc comment for
        // the crash-window this closes.
        FfiWscdError::KeyNotFound { msg } => InternalError::KeyNotFound { kid: msg },
        other => InternalError::Callback(other.to_string()),
    }
}

#[cfg(feature = "plugin-apple-se")]
#[async_trait::async_trait]
impl cb::SecureEnclaveCallback for SecureEnclaveCallbackBridge {
    async fn generate_key(
        &self,
        key_tag: &str,
    ) -> crate::error::Result<cb::SecureEnclavePublicKey> {
        self.inner
            .generate_key(key_tag.to_string())
            .map(|k| cb::SecureEnclavePublicKey { x: k.x, y: k.y })
            .map_err(secure_enclave_callback_error)
    }

    async fn sign(&self, key_tag: &str, data: &[u8]) -> crate::error::Result<Vec<u8>> {
        self.inner
            .sign(key_tag.to_string(), data.to_vec())
            .map_err(secure_enclave_callback_error)
    }

    async fn delete_key(&self, key_tag: &str) -> crate::error::Result<()> {
        self.inner
            .delete_key(key_tag.to_string())
            .map_err(secure_enclave_callback_error)
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

// ─── FfiWscdManager (UniFFI object) ─────────────────────────────────────────

#[derive(uniffi::Object)]
pub struct FfiWscdManager {
    inner: Mutex<InternalManager>,
    rt: tokio::runtime::Runtime,
}

impl FfiWscdManager {
    /// Lock `inner`, recovering from poison instead of propagating it.
    ///
    /// A foreign callback (e.g. a CTAP2 transport implemented in Kotlin/Swift)
    /// can raise an error UniFFI can't map to the callback trait's error type,
    /// which UniFFI turns into a Rust-side panic. That panic can unwind while
    /// this mutex is held, poisoning it — even though `InternalManager`'s
    /// state was never actually mutated mid-panic and remains perfectly
    /// usable. Without this recovery, one transient callback failure (USB
    /// unplugged, permission denied, timeout) would permanently break every
    /// subsequent FFI call for the life of the process.
    fn lock_inner(&self) -> std::sync::MutexGuard<'_, InternalManager> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
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
        let mut mgr = self.lock_inner();
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
        let mut mgr = self.lock_inner();
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
        let mgr = self.lock_inner();
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

    /// Sign data and report the TS12 authentication factors applied to this
    /// very sign. Additive: `sign` and `security_properties().amr` are
    /// unchanged. See [`FfiSignOptions`] for the fresh-authentication flag.
    pub fn sign_with_factors(
        &self,
        kid: String,
        data: Vec<u8>,
        algorithm: FfiAlgorithm,
        options: FfiSignOptions,
        auth: Box<dyn FfiAuthCallback>,
        progress: Box<dyn FfiProgressCallback>,
    ) -> Result<FfiSignOutcome, FfiWscdError> {
        let options: fct::SignOptions = options.try_into()?;
        let auth_bridge = AuthCallbackBridge(Arc::from(auth));
        let progress_bridge = ProgressCallbackBridge(Arc::from(progress));
        let mgr = self.lock_inner();
        let key_id = InternalKeyId(kid);
        let outcome = self.rt.block_on(mgr.sign_with_factors(
            &key_id,
            &data,
            algorithm.into(),
            &options,
            &auth_bridge,
            &progress_bridge,
        ))?;
        Ok(FfiSignOutcome {
            signature: outcome.signature.into(),
            factors: outcome.factors.into(),
        })
    }

    /// Whether a sign with this key could reach two TS12 categories. Never
    /// prompts; ask it before showing the user a transaction.
    pub fn authentication_capability(
        &self,
        kid: String,
    ) -> Result<FfiFactorCapability, FfiWscdError> {
        let mgr = self.lock_inner();
        Ok(mgr.authentication_capability(&InternalKeyId(kid))?.into())
    }

    /// List all keys across all registered plugins.
    pub fn list_keys(&self) -> Result<Vec<FfiKeyInfo>, FfiWscdError> {
        let mgr = self.lock_inner();
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
        let mgr = self.lock_inner();
        let key_id = InternalKeyId(kid);
        let result = self.rt.block_on(mgr.attestation_chain(&key_id))?;
        Ok(result.map(|a| a.into()))
    }

    /// Delete a key.
    pub fn delete_key(&self, kid: String) -> Result<(), FfiWscdError> {
        let mut mgr = self.lock_inner();
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
        let mut mgr = self.lock_inner();
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
        let mgr = self.lock_inner();
        // Get the softkey plugin and use its native export
        let plugin = mgr
            .get_plugin_by_id("softkey")
            .map_err(|e| FfiWscdError::NoPlugin { msg: e.to_string() })?;
        let softkey = plugin
            .as_any()
            .downcast_ref::<crate::plugins::softkey::SoftkeyPlugin>()
            .ok_or_else(|| FfiWscdError::Plugin {
                msg: "softkey plugin is not a SoftkeyPlugin".to_string(),
            })?;
        softkey
            .export_container()
            .map_err(|e| FfiWscdError::Serialization { msg: e.to_string() })
    }

    /// Import a softkey container (JSON bytes), replacing the current softkey state.
    pub fn import_softkey_container(&self, container: Vec<u8>) -> Result<(), FfiWscdError> {
        let plugin = SoftkeyPlugin::from_container(&container)
            .map_err(|e| FfiWscdError::Serialization { msg: e.to_string() })?;
        let mut mgr = self.lock_inner();
        mgr.register_plugin(Arc::new(plugin));
        Ok(())
    }

    /// Get the security properties for a key (CS-04 §7.1.3).
    ///
    /// Returns key storage type, user authentication methods, certification level,
    /// and AMR values from the last signing operation.
    pub fn security_properties(&self, kid: String) -> Result<FfiSecurityProperties, FfiWscdError> {
        let mgr = self.lock_inner();
        let key_id = InternalKeyId(kid);
        let props = mgr.security_properties(&key_id)?;
        Ok(props.into())
    }

    /// Export a key's public key as a JSON-encoded JWK string.
    ///
    /// Unlike `generate_key`'s return value (cached host-side right after
    /// generation), this looks the key up on the manager directly - the only
    /// way to recover a key's public JWK when it was created via a path other
    /// than `generate_key` (e.g. `register_lifecycle`/`activate_lifecycle`),
    /// or in a host process that didn't cache it itself.
    pub fn export_public_key(&self, kid: String) -> Result<String, FfiWscdError> {
        let mgr = self.lock_inner();
        let key_id = InternalKeyId(kid);
        let jwk = self.rt.block_on(mgr.export_public_key(&key_id))?;
        Ok(jwk.to_string())
    }

    /// Return lifecycle status for a plugin context.
    pub fn lifecycle_status(
        &self,
        plugin_id: String,
        context_id: String,
    ) -> Result<FfiLifecycleStatus, FfiWscdError> {
        let mgr = self.lock_inner();
        let status = self
            .rt
            .block_on(mgr.lifecycle_status(&plugin_id, &context_id))?;
        Ok(status.into())
    }

    /// Register lifecycle bindings for a context.
    pub fn register_lifecycle(
        &self,
        request: FfiRegisterLifecycleRequest,
        auth: Box<dyn FfiAuthCallback>,
        progress: Box<dyn FfiProgressCallback>,
    ) -> Result<FfiRegistrationOutcome, FfiWscdError> {
        let auth_bridge = AuthCallbackBridge(Arc::from(auth));
        let progress_bridge = ProgressCallbackBridge(Arc::from(progress));
        let mgr = self.lock_inner();
        let internal_request: InternalRegisterLifecycleRequest = request.into();
        let outcome = self.rt.block_on(mgr.register_lifecycle(
            &internal_request,
            &auth_bridge,
            &progress_bridge,
        ))?;
        Ok(outcome.into())
    }

    /// Activate an existing lifecycle context.
    pub fn activate_lifecycle(
        &self,
        request: FfiActivateLifecycleRequest,
        auth: Box<dyn FfiAuthCallback>,
        progress: Box<dyn FfiProgressCallback>,
    ) -> Result<FfiActivationOutcome, FfiWscdError> {
        let auth_bridge = AuthCallbackBridge(Arc::from(auth));
        let progress_bridge = ProgressCallbackBridge(Arc::from(progress));
        let mgr = self.lock_inner();
        let internal_request: InternalActivateLifecycleRequest = request.into();
        let outcome = self.rt.block_on(mgr.activate_lifecycle(
            &internal_request,
            &auth_bridge,
            &progress_bridge,
        ))?;
        Ok(outcome.into())
    }

    /// Rotate lifecycle bindings for a context.
    pub fn rotate_lifecycle(
        &self,
        request: FfiRotateLifecycleRequest,
        auth: Box<dyn FfiAuthCallback>,
        progress: Box<dyn FfiProgressCallback>,
    ) -> Result<FfiRotationOutcome, FfiWscdError> {
        let auth_bridge = AuthCallbackBridge(Arc::from(auth));
        let progress_bridge = ProgressCallbackBridge(Arc::from(progress));
        let mgr = self.lock_inner();
        let internal_request: InternalRotateLifecycleRequest = request.into();
        let outcome = self.rt.block_on(mgr.rotate_lifecycle(
            &internal_request,
            &auth_bridge,
            &progress_bridge,
        ))?;
        Ok(outcome.into())
    }

    /// Destroy lifecycle bindings for a context.
    pub fn destroy_lifecycle(
        &self,
        request: FfiDestroyLifecycleRequest,
        auth: Box<dyn FfiAuthCallback>,
        progress: Box<dyn FfiProgressCallback>,
    ) -> Result<FfiDestructionOutcome, FfiWscdError> {
        let auth_bridge = AuthCallbackBridge(Arc::from(auth));
        let progress_bridge = ProgressCallbackBridge(Arc::from(progress));
        let mgr = self.lock_inner();
        let internal_request: InternalDestroyLifecycleRequest = request.into();
        let outcome = self.rt.block_on(mgr.destroy_lifecycle(
            &internal_request,
            &auth_bridge,
            &progress_bridge,
        ))?;
        Ok(outcome.into())
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
    /// - `config`: R2PS server connection parameters including PEM-encoded P-256
    ///   keys for JWS/JWE envelope protection
    ///
    /// OPAQUE (RFC 9807) PAKE authentication (used when `config.auth_mode ==
    /// "opaque"`) is handled entirely in Rust via `r2ps_client::OpaqueClient`
    /// - no host-provided PAKE callback is needed (or possible) any more.
    pub fn register_r2ps_plugin(
        &self,
        config: FfiR2psConfig,
        transport: Box<dyn FfiHttpTransport>,
    ) -> Result<(), FfiWscdError> {
        use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};

        let client_key = p256::SecretKey::from_pkcs8_pem(&config.client_key_pem).map_err(|e| {
            FfiWscdError::Crypto {
                msg: format!("invalid client key PEM: {e}"),
            }
        })?;

        let server_pub = p256::PublicKey::from_public_key_pem(&config.server_public_key_pem)
            .map_err(|e| FfiWscdError::Crypto {
                msg: format!("invalid server public key PEM: {e}"),
            })?;

        let transport_bridge = FfiTransportBridge(Arc::from(transport));

        let r2ps_client = r2ps_client::R2psClient::new(
            config.client_id.clone(),
            config.context.clone(),
            client_key,
            server_pub,
            transport_bridge,
            r2ps_client::OpaqueClient::new(),
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
                    msg: format!("R2PS plugin init failed: {e}"),
                }
            })?;

        let mut mgr = self.lock_inner();
        mgr.register_plugin(Arc::new(plugin));
        Ok(())
    }
}

// ─── FIDO2 previewSign plugin registration ───────────────────────────────────

#[cfg(feature = "plugin-fido2")]
#[uniffi::export]
impl FfiWscdManager {
    /// Register the FIDO2 previewSign (rawSign) plugin for hardware
    /// authenticators such as YubiKey.
    ///
    /// The caller supplies a [`FfiCtap2Transport`] implementation that
    /// handles USB/BLE/NFC communication with the FIDO2 authenticator.
    pub fn register_fido2_plugin(
        &self,
        transport: Box<dyn FfiCtap2Transport>,
    ) -> Result<(), FfiWscdError> {
        let bridge = Ctap2TransportBridge {
            inner: Arc::from(transport),
        };
        let plugin = crate::plugins::fido2_sign::Fido2SignPlugin::new(Box::new(bridge));
        let mut mgr = self.lock_inner();
        mgr.register_plugin(Arc::new(plugin));
        Ok(())
    }

    /// Read-only description of the FIDO2 authenticator behind the
    /// registered `plugin_id` plugin (must be `"fido2"`; any other plugin
    /// gives `Unsupported`). Sends CTAP2 getInfo and, only when a PIN is set,
    /// getPinRetries (which consumes no retry). Never asks for a PIN, never
    /// sets one, never requests a token. Uses the registered transport as is:
    /// the library opens no connection of its own, so an already-open USB
    /// connection is reused.
    pub fn describe_authenticator(
        &self,
        plugin_id: String,
    ) -> Result<FfiAuthenticatorInfo, FfiWscdError> {
        // Hold the manager lock across the CTAP exchange, like generate_key
        // and sign do: the transport is one single-channel device and
        // neither the plugin nor the bridge serialises I/O, so overlapping
        // calls would interleave commands and get "busy" errors.
        let mgr = self.lock_inner();
        let plugin = mgr.get_plugin_by_id(&plugin_id)?;
        let fido2 = plugin
            .as_any()
            .downcast_ref::<crate::plugins::fido2_sign::Fido2SignPlugin>()
            .ok_or_else(|| FfiWscdError::Unsupported {
                msg: format!("plugin {plugin_id} does not support describe_authenticator"),
            })?;
        Ok(self.rt.block_on(fido2.describe_authenticator())?.into())
    }

    /// Register the FIDO2 previewSign plugin restored from a previously
    /// [`export_fido2_state`]-exported blob (key handles + public keys only,
    /// no private material - that never leaves the authenticator). The host
    /// app must persist that blob itself and pass it back here on the next
    /// launch, or every enrolled FIDO2 key becomes unreachable (its `kid`
    /// still exists in credential/session metadata, but the manager has no
    /// record of the credential handle needed to sign with it again).
    pub fn register_fido2_plugin_with_state(
        &self,
        transport: Box<dyn FfiCtap2Transport>,
        state: Vec<u8>,
    ) -> Result<(), FfiWscdError> {
        let bridge = Ctap2TransportBridge {
            inner: Arc::from(transport),
        };
        let plugin =
            crate::plugins::fido2_sign::Fido2SignPlugin::from_state(Box::new(bridge), &state)
                .map_err(|e| FfiWscdError::Serialization { msg: e.to_string() })?;
        // Bindings are recorded at generate time only; a restored plugin's
        // keys would otherwise route to the default plugin and fail.
        let kids = plugin.key_ids();
        let mut mgr = self.lock_inner();
        mgr.register_plugin(Arc::new(plugin));
        mgr.bind_keys("fido2", kids)
            .map_err(|e| FfiWscdError::Plugin { msg: e.to_string() })?;
        Ok(())
    }

    /// Export the FIDO2 plugin's key state (credential handles + public
    /// keys) for the host app to persist and later restore via
    /// [`register_fido2_plugin_with_state`].
    pub fn export_fido2_state(&self) -> Result<Vec<u8>, FfiWscdError> {
        let mgr = self.lock_inner();
        let plugin = mgr
            .get_plugin_by_id("fido2")
            .map_err(|e| FfiWscdError::NoPlugin { msg: e.to_string() })?;
        let fido2 = plugin
            .as_any()
            .downcast_ref::<crate::plugins::fido2_sign::Fido2SignPlugin>()
            .ok_or_else(|| FfiWscdError::Plugin {
                msg: "fido2 plugin is not a Fido2SignPlugin".to_string(),
            })?;
        fido2
            .export_state()
            .map_err(|e| FfiWscdError::Serialization { msg: e.to_string() })
    }
}

// ─── Apple Secure Enclave plugin registration ───────────────────────────────

#[cfg(feature = "plugin-apple-se")]
#[uniffi::export]
impl FfiWscdManager {
    /// Register the Apple Secure Enclave (`apple-se`) plugin.
    ///
    /// The caller supplies a [`FfiSecureEnclaveCallback`] implementation
    /// backed by CryptoKit's `SecureEnclave.P256.Signing.PrivateKey` + a
    /// Keychain tag. **Staged release:** keys this plugin generates carry
    /// no per-key attestation chain - see
    /// [`crate::callbacks::SecureEnclaveCallback`]'s doc comment.
    pub fn register_apple_secure_enclave_plugin(
        &self,
        callback: Box<dyn FfiSecureEnclaveCallback>,
    ) -> Result<(), FfiWscdError> {
        let bridge = SecureEnclaveCallbackBridge {
            inner: Arc::from(callback),
        };
        let plugin =
            crate::plugins::apple_secure_enclave::AppleSecureEnclavePlugin::new(Box::new(bridge));
        let mut mgr = self.lock_inner();
        mgr.register_plugin(Arc::new(plugin));
        Ok(())
    }

    /// Register the Apple Secure Enclave plugin restored from a previously
    /// [`export_apple_secure_enclave_state`]-exported blob (Keychain tags +
    /// public keys only, no private material - that never leaves the
    /// Secure Enclave). The host app must persist that blob itself and pass
    /// it back here on the next launch, or every enrolled `apple-se` key
    /// becomes unreachable (its `kid` still exists in credential/session
    /// metadata, but the manager has no record of the Keychain tag needed
    /// to sign with it again).
    pub fn register_apple_secure_enclave_plugin_with_state(
        &self,
        callback: Box<dyn FfiSecureEnclaveCallback>,
        state: Vec<u8>,
    ) -> Result<(), FfiWscdError> {
        let bridge = SecureEnclaveCallbackBridge {
            inner: Arc::from(callback),
        };
        let plugin =
            crate::plugins::apple_secure_enclave::AppleSecureEnclavePlugin::from_container(
                Box::new(bridge),
                &state,
            )
            .map_err(|e| FfiWscdError::Serialization { msg: e.to_string() })?;
        // Bindings are recorded at generate time only; a restored plugin's
        // keys would otherwise route to the default plugin and fail - same
        // reasoning as `register_fido2_plugin_with_state`.
        let kids = plugin.key_ids();
        let mut mgr = self.lock_inner();
        mgr.register_plugin(Arc::new(plugin));
        mgr.bind_keys("apple-se", kids)
            .map_err(|e| FfiWscdError::Plugin { msg: e.to_string() })?;
        Ok(())
    }

    /// Export the Apple Secure Enclave plugin's key state (Keychain tags +
    /// public keys) for the host app to persist and later restore via
    /// [`register_apple_secure_enclave_plugin_with_state`].
    pub fn export_apple_secure_enclave_state(&self) -> Result<Vec<u8>, FfiWscdError> {
        let mgr = self.lock_inner();
        let plugin = mgr
            .get_plugin_by_id("apple-se")
            .map_err(|e| FfiWscdError::NoPlugin { msg: e.to_string() })?;
        let apple_se = plugin
            .as_any()
            .downcast_ref::<crate::plugins::apple_secure_enclave::AppleSecureEnclavePlugin>()
            .ok_or_else(|| FfiWscdError::Plugin {
                msg: "apple-se plugin is not an AppleSecureEnclavePlugin".to_string(),
            })?;
        apple_se
            .export_container()
            .map_err(|e| FfiWscdError::Serialization { msg: e.to_string() })
    }
}

/// See [`crate::authenticator_info::AuthenticatorInfo`].
#[cfg(feature = "plugin-fido2")]
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiClientPinState {
    /// A PIN is set (`clientPin: true`): the user must enter it.
    Set,
    /// PIN supported but not set (`clientPin: false`): one will be chosen.
    NotSet,
    /// `clientPin` option absent: no PIN support.
    Unsupported,
}

#[cfg(feature = "plugin-fido2")]
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum FfiEnrolmentSuitability {
    Suitable,
    Unsuitable { reason: String },
}

#[cfg(feature = "plugin-fido2")]
#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiAuthenticatorInfo {
    pub versions: Vec<String>,
    /// 16 bytes.
    pub aaguid: Vec<u8>,
    pub client_pin: FfiClientPinState,
    /// 4 when the authenticator does not advertise it.
    pub min_pin_length: u32,
    pub force_pin_change: bool,
    /// Remaining PIN attempts; `None` unless a PIN is set.
    pub pin_retries: Option<u32>,
    pub pin_uv_auth_protocols: Vec<u32>,
    pub extensions: Vec<String>,
    pub options: std::collections::HashMap<String, bool>,
    pub enrolment_suitability: FfiEnrolmentSuitability,
}

#[cfg(feature = "plugin-fido2")]
impl From<crate::authenticator_info::AuthenticatorInfo> for FfiAuthenticatorInfo {
    fn from(i: crate::authenticator_info::AuthenticatorInfo) -> Self {
        use crate::authenticator_info::EnrolmentSuitability as S;
        use crate::ctap2_client_pin::PinState as P;
        Self {
            versions: i.versions,
            aaguid: i.aaguid.to_vec(),
            client_pin: match i.client_pin {
                P::Set => FfiClientPinState::Set,
                P::NotSet => FfiClientPinState::NotSet,
                P::Unsupported => FfiClientPinState::Unsupported,
            },
            min_pin_length: i.min_pin_length,
            force_pin_change: i.force_pin_change,
            pin_retries: i.pin_retries,
            pin_uv_auth_protocols: i.pin_uv_auth_protocols,
            extensions: i.extensions,
            options: i.options.into_iter().collect(),
            enrolment_suitability: match i.enrolment_suitability {
                S::Suitable => FfiEnrolmentSuitability::Suitable,
                S::Unsuitable { reason } => FfiEnrolmentSuitability::Unsuitable { reason },
            },
        }
    }
}

#[cfg(test)]
mod poison_recovery_tests {
    use super::*;

    /// A foreign-callback failure (e.g. a CTAP2 transport error UniFFI can't
    /// map to the callback trait's error type) surfaces as a Rust panic while
    /// `inner` is locked, poisoning it. Simulate that directly by panicking
    /// on another thread while holding the lock, then confirm a later call
    /// still succeeds instead of permanently failing with "poisoned lock".
    #[test]
    fn manager_recovers_after_inner_mutex_is_poisoned() {
        let manager = FfiWscdManager::new(FfiWscdConfig {
            default_plugin: "softkey".to_string(),
        });

        let poison_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = manager.lock_inner();
            panic!("simulated foreign-callback failure while holding the lock");
        }));
        assert!(poison_result.is_err());
        assert!(manager.inner.is_poisoned());

        manager
            .register_softkey_plugin()
            .expect("register_softkey_plugin should recover from a poisoned lock");
    }
}

#[cfg(test)]
mod ffi_boundary_tests {
    use super::*;

    struct StubAuth;

    impl FfiAuthCallback for StubAuth {
        fn request_pin(&self, _plugin_id: String) -> Result<Vec<u8>, FfiWscdError> {
            Ok(b"1234".to_vec())
        }
        fn request_new_pin(
            &self,
            _plugin_id: String,
            _min_length: u32,
        ) -> Result<Vec<u8>, FfiWscdError> {
            Ok(b"1234".to_vec())
        }
        fn request_webauthn_assertion(
            &self,
            _plugin_id: String,
            _challenge: Vec<u8>,
            _rp_id: String,
            _allowed_credentials: Vec<Vec<u8>>,
        ) -> Result<Vec<u8>, FfiWscdError> {
            Err(FfiWscdError::Unsupported {
                msg: "webauthn".into(),
            })
        }
    }

    struct SilentProgress;

    impl FfiProgressCallback for SilentProgress {
        fn on_progress(&self, _progress: FfiOperationProgress) {}
    }

    fn callbacks() -> (Box<dyn FfiAuthCallback>, Box<dyn FfiProgressCallback>) {
        (Box::new(StubAuth), Box::new(SilentProgress))
    }

    /// Verify a signature under the JWK that crossed the FFI boundary, the
    /// way a host SDK's own verifier would.
    ///
    /// Comparing two signatures to each other only proves they agree, which
    /// is exactly the failure this PR is about: a consistently wrong key
    /// produces consistently matching bytes. The public key is the only
    /// external reference point available on this side.
    fn verify_under_exported_jwk(jwk_json: &str, data: &[u8], signature: &[u8]) {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        let jwk: serde_json::Value = serde_json::from_str(jwk_json).unwrap();
        let mut sec1 = vec![0x04u8];
        sec1.extend(Base64UrlUnpadded::decode_vec(jwk["x"].as_str().unwrap()).unwrap());
        sec1.extend(Base64UrlUnpadded::decode_vec(jwk["y"].as_str().unwrap()).unwrap());
        let vk = VerifyingKey::from(p256::PublicKey::from_sec1_bytes(&sec1).unwrap());
        vk.verify(data, &Signature::from_slice(signature).unwrap())
            .expect("the signature must verify under the exported public key");
    }

    /// Every internal error must reach the host as the matching FFI variant.
    ///
    /// This is the only place the mapping exists, and hosts branch on it:
    /// `KeyNotFound` means re-enroll, `AuthCancelled` means the user said no
    /// and must not be retried, `Unsupported` means pick another plugin. A
    /// variant collapsed into the wrong bucket sends the host down the wrong
    /// recovery path — and because `From` is exhaustive over the internal
    /// enum, the compiler cannot tell a *misrouted* arm from a correct one.
    ///
    /// `NoDefault` deliberately maps to `NoPlugin`: the host has no separate
    /// variant for it, and both mean "nothing is configured to serve this".
    /// Written down here so that stays a decision rather than an accident.
    #[test]
    fn internal_errors_map_to_the_intended_ffi_variants() {
        let cases: Vec<(InternalError, &str)> = vec![
            (InternalError::NoPlugin { kid: "k".into() }, "NoPlugin"),
            (InternalError::NoDefault { op: "sign".into() }, "NoPlugin"),
            (
                InternalError::Unsupported {
                    plugin: "p".into(),
                    op: "o".into(),
                },
                "Unsupported",
            ),
            (
                InternalError::KeyNotFound { kid: "k".into() },
                "KeyNotFound",
            ),
            (InternalError::AuthRequired, "AuthRequired"),
            (InternalError::AuthCancelled, "AuthCancelled"),
            (
                InternalError::ReEnrollmentRequired { kid: "k".into() },
                "ReEnrollmentRequired",
            ),
            (InternalError::Plugin("x".into()), "Plugin"),
            (InternalError::Callback("x".into()), "Callback"),
            (InternalError::Serialization("x".into()), "Serialization"),
            (InternalError::Crypto("x".into()), "Crypto"),
            (
                InternalError::Pin(crate::error::PinFailure::PolicyViolation),
                "Pin",
            ),
        ];

        for (internal, expected_variant) in cases {
            let internal_message = internal.to_string();
            let ffi = FfiWscdError::from(internal);
            let actual_variant = match ffi {
                FfiWscdError::NoPlugin { .. } => "NoPlugin",
                FfiWscdError::Unsupported { .. } => "Unsupported",
                FfiWscdError::KeyNotFound { .. } => "KeyNotFound",
                FfiWscdError::AuthRequired { .. } => "AuthRequired",
                FfiWscdError::AuthCancelled { .. } => "AuthCancelled",
                FfiWscdError::ReEnrollmentRequired { .. } => "ReEnrollmentRequired",
                FfiWscdError::Plugin { .. } => "Plugin",
                FfiWscdError::Callback { .. } => "Callback",
                FfiWscdError::Serialization { .. } => "Serialization",
                FfiWscdError::Crypto { .. } => "Crypto",
                FfiWscdError::Pin { .. } => "Pin",
            };
            assert_eq!(
                actual_variant, expected_variant,
                "{internal_message:?} was mapped to {actual_variant}"
            );
            // The original diagnostic must survive: it is the only detail the
            // host can show a user or put in a bug report.
            assert!(
                format!("{ffi}").contains(&internal_message),
                "{expected_variant} lost the original message {internal_message:?}"
            );
        }
    }

    /// One full pass across the FFI object: register, generate, sign, export,
    /// container round trip.
    ///
    /// The exported functions are thin, but "thin" is exactly where the
    /// mistakes are — `generate_key` takes `&mut` on the manager while `sign`
    /// takes `&`, both under the same mutex and the same `block_on`, and the
    /// container export reaches the plugin through a `downcast_ref` that
    /// returns `None` rather than failing loudly if the registered plugin is
    /// not the expected type. None of that was executed by any test.
    #[test]
    fn generate_sign_and_container_round_trip_across_the_boundary() {
        let manager = FfiWscdManager::new(FfiWscdConfig {
            default_plugin: "softkey".to_string(),
        });
        manager.register_softkey_plugin().unwrap();

        let (auth, progress) = callbacks();
        let generated = manager
            .generate_key(FfiAlgorithm::ES256, auth, progress)
            .unwrap();
        assert_eq!(
            generated.kid.len(),
            43,
            "kid is the JWK thumbprint (RFC 7638)"
        );
        // The JWK crosses the boundary as a string, so it must still be JSON.
        let jwk: serde_json::Value = serde_json::from_str(&generated.public_key_jwk).unwrap();
        assert_eq!(jwk["crv"], "P-256");

        let (auth, progress) = callbacks();
        let signature = manager
            .sign(
                generated.kid.clone(),
                b"payload".to_vec(),
                FfiAlgorithm::ES256,
                auth,
                progress,
            )
            .unwrap();
        assert_eq!(signature.data.len(), 64);
        verify_under_exported_jwk(&generated.public_key_jwk, b"payload", &signature.data);

        assert_eq!(manager.list_keys().unwrap().len(), 1);
        assert!(manager
            .attestation_chain(generated.kid.clone())
            .unwrap()
            .is_none());
        assert_eq!(
            manager.export_public_key(generated.kid.clone()).unwrap(),
            generated.public_key_jwk,
            "export_public_key must return the same key generate_key published"
        );
        let props = manager.security_properties(generated.kid.clone()).unwrap();
        assert!(matches!(props.key_storage, FfiKeyStorageType::Software));

        // Export, import into a *fresh* manager, and check the key still
        // signs there — this is how a host persists softkeys across launches,
        // and a container that does not carry private material would pass a
        // shape check but fail right here.
        let container = manager.export_softkey_container().unwrap();
        let restored = FfiWscdManager::new(FfiWscdConfig {
            default_plugin: "softkey".to_string(),
        });
        restored.import_softkey_container(container).unwrap();
        let (auth, progress) = callbacks();
        let restored_signature = restored
            .sign(
                generated.kid.clone(),
                b"payload".to_vec(),
                FfiAlgorithm::ES256,
                auth,
                progress,
            )
            .unwrap();
        // The real assertion: the restored key still signs something the
        // originally-published public key verifies. Equality with the first
        // signature is a secondary check on RFC 6979 determinism, and would
        // hold just as well if both were made with the same *wrong* key.
        verify_under_exported_jwk(
            &generated.public_key_jwk,
            b"payload",
            &restored_signature.data,
        );
        assert_eq!(
            restored_signature.data, signature.data,
            "ECDSA here is deterministic (RFC 6979), so the restored key must \
             reproduce the signature bit for bit"
        );
        assert_eq!(
            restored.export_public_key(generated.kid.clone()).unwrap(),
            generated.public_key_jwk,
            "the restored container must hold the same key, not a fresh one"
        );

        manager.delete_key(generated.kid.clone()).unwrap();
        assert!(manager.list_keys().unwrap().is_empty());
        assert!(matches!(
            manager.sign(
                generated.kid,
                b"payload".to_vec(),
                FfiAlgorithm::ES256,
                Box::new(StubAuth),
                Box::new(SilentProgress),
            ),
            Err(FfiWscdError::KeyNotFound { .. })
        ));
    }

    /// The additive TS12 surface crosses the boundary: record defaults give
    /// a plain sign, a plugin with no user verification reports an explicit
    /// shortfall, and the fresh-authentication flag is refused (not ignored)
    /// by a plugin that cannot honour it.
    #[test]
    fn ts12_factors_cross_the_boundary_and_fail_closed() {
        let manager = FfiWscdManager::new(FfiWscdConfig {
            default_plugin: "softkey".to_string(),
        });
        manager.register_softkey_plugin().unwrap();
        let (auth, progress) = callbacks();
        let generated = manager
            .generate_key(FfiAlgorithm::ES256, auth, progress)
            .unwrap();

        let cap = manager
            .authentication_capability(generated.kid.clone())
            .unwrap();
        assert!(!cap.can_reach_two_categories && cap.reason.is_some());

        let options = FfiSignOptions {
            require_fresh_user_authentication: false,
            host_verified_factor: None,
        };
        let (auth, progress) = callbacks();
        let outcome = manager
            .sign_with_factors(
                generated.kid.clone(),
                b"payload".to_vec(),
                FfiAlgorithm::ES256,
                options,
                auth,
                progress,
            )
            .unwrap();
        assert_eq!(outcome.signature.data.len(), 64);
        assert!(outcome.factors.factors.is_empty());
        assert!(!outcome.factors.satisfies_two_categories);
        assert!(outcome.factors.shortfall.is_some());

        let (auth, progress) = callbacks();
        assert!(matches!(
            manager.sign_with_factors(
                generated.kid.clone(),
                b"payload".to_vec(),
                FfiAlgorithm::ES256,
                FfiSignOptions {
                    require_fresh_user_authentication: true,
                    host_verified_factor: None,
                },
                auth,
                progress,
            ),
            Err(FfiWscdError::Unsupported { .. })
        ));

        // A host cannot assert possession, nor an off-vocabulary method.
        for bad in [
            FfiAuthFactor {
                category: FfiFactorCategory::Possession,
                method: "key_in_remote_wscd".into(),
            },
            FfiAuthFactor {
                category: FfiFactorCategory::Inherence,
                method: "retina".into(),
            },
        ] {
            let (auth, progress) = callbacks();
            assert!(manager
                .sign_with_factors(
                    generated.kid.clone(),
                    b"payload".to_vec(),
                    FfiAlgorithm::ES256,
                    FfiSignOptions {
                        require_fresh_user_authentication: false,
                        host_verified_factor: Some(bad),
                    },
                    auth,
                    progress,
                )
                .is_err());
        }
    }

    /// Exporting state for a plugin that was never registered must be an
    /// error, not a panic or an empty blob.
    ///
    /// A host that stored an empty container as if it were real state would
    /// overwrite the user's actual keys on the next save.
    #[test]
    fn exporting_state_for_an_unregistered_plugin_fails() {
        let manager = FfiWscdManager::new(FfiWscdConfig {
            default_plugin: "softkey".to_string(),
        });
        assert!(matches!(
            manager.export_softkey_container(),
            Err(FfiWscdError::NoPlugin { .. })
        ));
        assert!(matches!(
            manager.export_fido2_state(),
            Err(FfiWscdError::NoPlugin { .. })
        ));
        // Garbage in must not become an empty-but-valid key store.
        assert!(manager
            .import_softkey_container(b"not json".to_vec())
            .is_err());
    }
}

#[cfg(all(test, feature = "plugin-apple-se"))]
mod apple_se_ffi_tests {
    use super::*;
    use p256::ecdsa::{signature::Signer as _, SigningKey};
    use p256::elliptic_curve::sec1::ToSec1Point;
    use p256::elliptic_curve::Generate;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// A fake [`FfiSecureEnclaveCallback`] exercising the real UniFFI
    /// boundary (`SecureEnclaveCallbackBridge`, `secure_enclave_callback_error`)
    /// end to end, the same way `ffi_boundary_tests`' `StubAuth` does for
    /// `AuthCallbackBridge`. Generates and signs with real P-256 keys (same
    /// `p256` crate `SoftkeyPlugin` uses) rather than placeholder bytes - a
    /// `generate_key` that returns coordinates not actually on the curve
    /// would make `verify_under_exported_jwk` fail for an unrelated reason
    /// (an invalid point, not a wrong signature), defeating the point of
    /// verifying under the real exported JWK instead of a self-comparison.
    /// `fail_with` lets a test make every call return a specific
    /// `FfiWscdError`, to prove the bridge's error mapping without needing
    /// a real Secure Enclave.
    struct FakeHost {
        keys: StdMutex<HashMap<String, SigningKey>>,
        fail_with: StdMutex<Option<FfiWscdError>>,
    }

    impl FakeHost {
        fn new() -> Self {
            Self {
                keys: StdMutex::new(HashMap::new()),
                fail_with: StdMutex::new(None),
            }
        }
    }

    // Implemented for `Arc<FakeHost>` rather than `FakeHost` directly so a
    // test can keep its own `Arc` clone and mutate `fail_with`/inspect
    // `keys` AFTER handing a `Box::new(host.clone())` to
    // `register_apple_secure_enclave_plugin` - which takes ownership of
    // whatever it's given and otherwise leaves no way back in.
    impl FfiSecureEnclaveCallback for Arc<FakeHost> {
        fn generate_key(&self, key_tag: String) -> Result<FfiSecureEnclavePublicKey, FfiWscdError> {
            if let Some(e) = self.fail_with.lock().unwrap().clone() {
                return Err(e);
            }
            let sk = SigningKey::generate();
            let point = p256::PublicKey::from(sk.verifying_key()).to_sec1_point(false);
            let x = point.x().expect("uncompressed point has an x").to_vec();
            let y = point.y().expect("uncompressed point has a y").to_vec();
            self.keys.lock().unwrap().insert(key_tag, sk);
            Ok(FfiSecureEnclavePublicKey { x, y })
        }

        fn sign(&self, key_tag: String, data: Vec<u8>) -> Result<Vec<u8>, FfiWscdError> {
            if let Some(e) = self.fail_with.lock().unwrap().clone() {
                return Err(e);
            }
            let keys = self.keys.lock().unwrap();
            let sk = keys
                .get(&key_tag)
                .ok_or_else(|| FfiWscdError::KeyNotFound {
                    msg: key_tag.clone(),
                })?;
            let sig: p256::ecdsa::Signature = sk.sign(&data);
            Ok(sig.to_bytes().to_vec())
        }

        fn delete_key(&self, key_tag: String) -> Result<(), FfiWscdError> {
            if let Some(e) = self.fail_with.lock().unwrap().clone() {
                return Err(e);
            }
            if self.keys.lock().unwrap().remove(&key_tag).is_none() {
                return Err(FfiWscdError::KeyNotFound { msg: key_tag });
            }
            Ok(())
        }
    }

    impl Clone for FfiWscdError {
        fn clone(&self) -> Self {
            // `FfiWscdError` doesn't derive `Clone` - round-trip through its
            // `Display` impl into the one variant these tests need, `msg`
            // preserved, since the test only cares which variant it is.
            match self {
                FfiWscdError::AuthCancelled { msg } => {
                    FfiWscdError::AuthCancelled { msg: msg.clone() }
                }
                FfiWscdError::AuthRequired { msg } => {
                    FfiWscdError::AuthRequired { msg: msg.clone() }
                }
                other => FfiWscdError::Callback {
                    msg: other.to_string(),
                },
            }
        }
    }

    // Duplicated rather than shared with `ffi_boundary_tests` - that module
    // already duplicates its own `callbacks()` again for
    // `describe_authenticator_tests` below rather than exposing its
    // private test helpers across sibling modules, so this follows the same
    // established convention.
    struct StubAuth;

    impl FfiAuthCallback for StubAuth {
        fn request_pin(&self, _plugin_id: String) -> Result<Vec<u8>, FfiWscdError> {
            Ok(b"1234".to_vec())
        }
        fn request_new_pin(
            &self,
            _plugin_id: String,
            _min_length: u32,
        ) -> Result<Vec<u8>, FfiWscdError> {
            Ok(b"1234".to_vec())
        }
        fn request_webauthn_assertion(
            &self,
            _plugin_id: String,
            _challenge: Vec<u8>,
            _rp_id: String,
            _allowed_credentials: Vec<Vec<u8>>,
        ) -> Result<Vec<u8>, FfiWscdError> {
            Err(FfiWscdError::Unsupported {
                msg: "webauthn".into(),
            })
        }
    }

    struct SilentProgress;

    impl FfiProgressCallback for SilentProgress {
        fn on_progress(&self, _progress: FfiOperationProgress) {}
    }

    /// `secure_enclave_callback_error` must preserve `KeyNotFound` as
    /// `InternalError::KeyNotFound`, not collapse it into the generic
    /// `Callback` bucket - `AppleSecureEnclavePlugin::delete_key`'s
    /// idempotent-delete fix (treating "the host says it's already gone"
    /// as success) depends on seeing the real variant here. The Rust-level
    /// plugin test (`a_delete_whose_registry_update_never_persisted_is_not_stuck_forever`)
    /// exercises the plugin logic directly against a fake that already
    /// returns `WscdError::KeyNotFound`, so it would stay green even if
    /// THIS mapping regressed - this test is what actually guards it.
    #[test]
    fn secure_enclave_callback_error_preserves_key_not_found() {
        let mapped = secure_enclave_callback_error(FfiWscdError::KeyNotFound {
            msg: "some-tag".to_string(),
        });
        assert!(matches!(mapped, InternalError::KeyNotFound { kid } if kid == "some-tag"));
    }

    fn manager() -> FfiWscdManager {
        FfiWscdManager::new(FfiWscdConfig {
            default_plugin: "apple-se".into(),
        })
    }

    fn callbacks() -> (Box<dyn FfiAuthCallback>, Box<dyn FfiProgressCallback>) {
        (Box::new(StubAuth), Box::new(SilentProgress))
    }

    /// Verify a signature under the JWK that crossed the FFI boundary - see
    /// `ffi_boundary_tests::verify_under_exported_jwk`'s doc comment for why
    /// this, not a self-comparison, is the real test.
    fn verify_under_exported_jwk(jwk_json: &str, data: &[u8], signature: &[u8]) {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        let jwk: serde_json::Value = serde_json::from_str(jwk_json).unwrap();
        let mut sec1 = vec![0x04u8];
        sec1.extend(Base64UrlUnpadded::decode_vec(jwk["x"].as_str().unwrap()).unwrap());
        sec1.extend(Base64UrlUnpadded::decode_vec(jwk["y"].as_str().unwrap()).unwrap());
        let vk = VerifyingKey::from(p256::PublicKey::from_sec1_bytes(&sec1).unwrap());
        vk.verify(data, &Signature::from_slice(signature).unwrap())
            .expect("the signature must verify under the exported public key");
    }

    /// End-to-end through the real UniFFI surface: register, generate,
    /// sign, verify the signature under the exported public key (not just
    /// against itself - see `ffi_boundary_tests::verify_under_exported_jwk`'s
    /// doc comment for why that distinction matters), delete, and confirm a
    /// deleted key is really gone from both sides.
    #[test]
    fn generate_sign_delete_round_trip_through_the_real_ffi_boundary() {
        let m = manager();
        m.register_apple_secure_enclave_plugin(Box::new(Arc::new(FakeHost::new())))
            .unwrap();

        let (auth, progress) = callbacks();
        let key = m.generate_key(FfiAlgorithm::ES256, auth, progress).unwrap();

        let (auth, progress) = callbacks();
        let sig = m
            .sign(
                key.kid.clone(),
                b"hello".to_vec(),
                FfiAlgorithm::ES256,
                auth,
                progress,
            )
            .unwrap();
        verify_under_exported_jwk(&key.public_key_jwk, b"hello", &sig.data);

        m.delete_key(key.kid.clone()).unwrap();
        assert!(matches!(
            m.export_public_key(key.kid),
            Err(FfiWscdError::KeyNotFound { .. })
        ));
    }

    /// The Copilot review finding this test guards against: a host throwing
    /// `AuthCancelled` (the user declined the Secure Enclave's biometric/
    /// passcode prompt) must reach the manager's caller as `AuthCancelled`,
    /// not a generic `Callback` error - callers branch on this to decide
    /// whether retrying makes sense (see `secure_enclave_callback_error`'s
    /// doc comment).
    #[test]
    fn auth_cancelled_and_auth_required_survive_the_callback_boundary() {
        for case in [
            FfiWscdError::AuthCancelled {
                msg: "user cancelled".into(),
            },
            FfiWscdError::AuthRequired {
                msg: "needs auth".into(),
            },
        ] {
            let host = Arc::new(FakeHost::new());
            *host.fail_with.lock().unwrap() = Some(case.clone());
            let m = manager();
            m.register_apple_secure_enclave_plugin(Box::new(host))
                .unwrap();

            let (auth, progress) = callbacks();
            let err = match m.generate_key(FfiAlgorithm::ES256, auth, progress) {
                Ok(_) => panic!("the fake host is configured to always fail"),
                Err(e) => e,
            };
            match case {
                FfiWscdError::AuthCancelled { .. } => {
                    assert!(matches!(err, FfiWscdError::AuthCancelled { .. }))
                }
                FfiWscdError::AuthRequired { .. } => {
                    assert!(matches!(err, FfiWscdError::AuthRequired { .. }))
                }
                _ => unreachable!(),
            }
        }
    }

    /// The other Copilot review finding: a failed Keychain deletion must
    /// leave the registry entry in place so a retry can reach the callback
    /// again, instead of silently orphaning the live Secure Enclave key.
    #[test]
    fn a_failed_delete_can_be_retried_instead_of_orphaning_the_key() {
        // Kept as our own `Arc` clone (see the `impl ... for Arc<FakeHost>`
        // doc comment) so `fail_with` can be flipped on AFTER generating a
        // key through the SAME registered plugin instance - swapping in a
        // second, unrelated `FakeHost` would just wipe the plugin's own key
        // registry and fail for the wrong reason.
        let host = Arc::new(FakeHost::new());
        let m = manager();
        m.register_apple_secure_enclave_plugin(Box::new(host.clone()))
            .unwrap();

        let (auth, progress) = callbacks();
        let key = m.generate_key(FfiAlgorithm::ES256, auth, progress).unwrap();

        *host.fail_with.lock().unwrap() = Some(FfiWscdError::Callback {
            msg: "keychain busy".into(),
        });
        assert!(m.delete_key(key.kid.clone()).is_err());

        // The entry must still be exportable/resolvable after the failed
        // delete - proving it was NOT removed from the registry up front.
        assert!(m.export_public_key(key.kid.clone()).is_ok());

        // And a retry, once the host recovers, must actually reach the
        // callback and succeed - not just "not error locally".
        *host.fail_with.lock().unwrap() = None;
        m.delete_key(key.kid.clone())
            .expect("a retried delete should succeed once the host recovers");
        assert!(matches!(
            m.export_public_key(key.kid),
            Err(FfiWscdError::KeyNotFound { .. })
        ));
    }

    /// Copilot review finding on this PR: `export_and_restore_container_round_trips_the_registry`
    /// (the Rust-level plugin test) only checked JWK fields against an
    /// EMPTY fake enclave after restore - a regression that broke signing
    /// after restore (a lost Keychain tag, or a missing `bind_keys` call so
    /// the manager never learns the restored plugin owns this kid) would
    /// not have been caught. This test restores through the REAL UniFFI
    /// surface (`export_apple_secure_enclave_state` ->
    /// `register_apple_secure_enclave_plugin_with_state`) and then signs -
    /// deliberately with `default_plugin: "softkey"`, so a successful sign
    /// can only mean `bind_keys("apple-se", ...)` actually ran; if it
    /// didn't, `m2.sign` would route to the (apple-se-key-ignorant)
    /// softkey default and fail with `NoPlugin`/`KeyNotFound` instead.
    #[test]
    fn export_restore_and_sign_round_trip_through_the_real_ffi_boundary() {
        let host = Arc::new(FakeHost::new());
        let m1 = FfiWscdManager::new(FfiWscdConfig {
            default_plugin: "apple-se".into(),
        });
        m1.register_apple_secure_enclave_plugin(Box::new(host.clone()))
            .unwrap();

        let (auth, progress) = callbacks();
        let key = m1
            .generate_key(FfiAlgorithm::ES256, auth, progress)
            .unwrap();
        let exported = m1.export_apple_secure_enclave_state().unwrap();

        // A fresh manager - simulating a process restart - with a DIFFERENT
        // default plugin. The SAME `host` is reused: a real Keychain
        // persists independently of this process, which is exactly what
        // `host` (kept alive across both managers) stands in for here.
        let m2 = FfiWscdManager::new(FfiWscdConfig {
            default_plugin: "softkey".into(),
        });
        m2.register_softkey_plugin().unwrap();
        m2.register_apple_secure_enclave_plugin_with_state(Box::new(host), exported)
            .unwrap();

        let (auth, progress) = callbacks();
        let sig = m2
            .sign(
                key.kid.clone(),
                b"hello".to_vec(),
                FfiAlgorithm::ES256,
                auth,
                progress,
            )
            .expect("signing through the restored plugin must succeed, routed there by bind_keys");
        verify_under_exported_jwk(&key.public_key_jwk, b"hello", &sig.data);
    }
}

#[cfg(all(test, feature = "plugin-fido2"))]
mod describe_authenticator_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts commands; answers getInfo (clientPin set, previewSign) and
    /// getPinRetries only.
    struct CountingTransport(Arc<AtomicUsize>);

    impl FfiCtap2Transport for CountingTransport {
        fn ctap2_send_command(&self, command: Vec<u8>) -> Result<Vec<u8>, FfiWscdError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            let mut out = vec![0u8];
            let value = match command[0] {
                0x04 => ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Integer(2.into()),
                        ciborium::Value::Array(vec![ciborium::Value::Text("previewSign".into())]),
                    ),
                    (
                        ciborium::Value::Integer(3.into()),
                        ciborium::Value::Bytes(vec![7; 16]),
                    ),
                    (
                        ciborium::Value::Integer(4.into()),
                        ciborium::Value::Map(vec![(
                            ciborium::Value::Text("clientPin".into()),
                            ciborium::Value::Bool(true),
                        )]),
                    ),
                ]),
                0x06 => ciborium::Value::Map(vec![(
                    ciborium::Value::Integer(3.into()),
                    ciborium::Value::Integer(5.into()),
                )]),
                other => panic!("unexpected command 0x{other:02x}"),
            };
            ciborium::ser::into_writer(&value, &mut out).unwrap();
            Ok(out)
        }
    }

    /// Fails the test if two commands are ever in flight at once.
    struct OverlapDetector {
        in_flight: Arc<AtomicUsize>,
        overlapped: Arc<AtomicUsize>,
    }

    impl FfiCtap2Transport for OverlapDetector {
        fn ctap2_send_command(&self, command: Vec<u8>) -> Result<Vec<u8>, FfiWscdError> {
            if self.in_flight.fetch_add(1, Ordering::SeqCst) != 0 {
                self.overlapped.fetch_add(1, Ordering::SeqCst);
            }
            std::thread::sleep(std::time::Duration::from_millis(30));
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            CountingTransport(Arc::new(AtomicUsize::new(0))).ctap2_send_command(command)
        }
    }

    #[test]
    fn concurrent_describes_never_overlap_on_the_transport() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let overlapped = Arc::new(AtomicUsize::new(0));
        let m = Arc::new(manager());
        m.register_fido2_plugin(Box::new(OverlapDetector {
            in_flight: in_flight.clone(),
            overlapped: overlapped.clone(),
        }))
        .unwrap();
        let threads: Vec<_> = (0..3)
            .map(|_| {
                let m = m.clone();
                std::thread::spawn(move || m.describe_authenticator("fido2".into()).unwrap())
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(
            overlapped.load(Ordering::SeqCst),
            0,
            "CTAP commands overlapped"
        );
    }

    fn manager() -> FfiWscdManager {
        FfiWscdManager::new(FfiWscdConfig {
            default_plugin: "softkey".into(),
        })
    }

    #[test]
    fn describes_through_the_one_registered_transport_every_time() {
        let calls = Arc::new(AtomicUsize::new(0));
        let m = manager();
        m.register_fido2_plugin(Box::new(CountingTransport(calls.clone())))
            .unwrap();
        for round in 1..=2 {
            let info = m.describe_authenticator("fido2".into()).unwrap();
            assert_eq!(info.client_pin, FfiClientPinState::Set);
            assert_eq!(info.pin_retries, Some(5));
            assert_eq!(info.aaguid, vec![7u8; 16]);
            assert_eq!(
                info.enrolment_suitability,
                FfiEnrolmentSuitability::Suitable
            );
            // getInfo + getPinRetries per call, all on the one transport
            // object registered above: nothing is reconnected or recreated.
            assert_eq!(calls.load(Ordering::SeqCst), 2 * round);
        }
    }

    #[test]
    fn other_plugins_and_unknown_ids_are_refused() {
        let m = manager();
        m.register_softkey_plugin().unwrap();
        assert!(matches!(
            m.describe_authenticator("softkey".into()),
            Err(FfiWscdError::Unsupported { .. })
        ));
        assert!(matches!(
            m.describe_authenticator("nope".into()),
            Err(FfiWscdError::NoPlugin { .. })
        ));
    }
}
