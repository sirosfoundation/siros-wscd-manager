use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Identifies a key managed by the WSCD layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct KeyId(pub String);

impl KeyId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for KeyId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Metadata for a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub kid: KeyId,
    pub algorithm: Algorithm,
    pub plugin_id: String,
    pub created_at: i64,
}

/// Supported algorithms.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Algorithm {
    ES256,
    EdDSA,
}

impl Algorithm {
    pub fn as_str(&self) -> &str {
        match self {
            Algorithm::ES256 => "ES256",
            Algorithm::EdDSA => "EdDSA",
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A generated key handle returned by `generate_key`.
#[derive(Debug, Clone)]
pub struct GeneratedKey {
    pub kid: KeyId,
    pub public_key_jwk: serde_json::Value,
}

/// Result of a signing operation.
#[derive(Debug, Clone)]
pub struct Signature(pub Vec<u8>);

/// Attestation chain for a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationChain {
    pub certificates: Vec<Vec<u8>>,
}

/// Describes the authentication method a plugin requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// No authentication needed (e.g., softkey).
    None,
    /// OPAQUE password-authenticated key exchange (needs PIN).
    Opaque,
    /// WebAuthn passkey assertion.
    WebAuthn,
}

/// Progress state pushed to the caller during long-running operations.
#[derive(Debug, Clone)]
pub enum OperationProgress {
    /// Operation started.
    Started { operation: String },
    /// Waiting for network round-trip.
    NetworkRoundTrip { step: u32, total: u32 },
    /// Waiting for user interaction (PIN, biometric, etc.).
    WaitingForUser,
    /// Operation complete.
    Complete,
}

/// Authentication factor used for lifecycle operations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FactorKind {
    Opaque,
    WebAuthn,
    RawSign,
}

/// Lifecycle state for a plugin-specific registration context.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LifecycleState {
    Uninitialized,
    Registered,
    Active,
    Suspended,
    Destroyed,
}

/// Destruction mode for lifecycle teardown.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DestroyMode {
    LocalOnly,
    RemoteRevokeIfSupported,
    Strict,
}

/// Current lifecycle status for a context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleStatus {
    pub context_id: String,
    pub plugin_id: String,
    pub factor_kind: FactorKind,
    pub state: LifecycleState,
    pub updated_at: i64,
}

/// Request to register a lifecycle context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterLifecycleRequest {
    pub plugin_id: String,
    pub context_id: String,
    pub factor_kind: FactorKind,
}

/// Request to activate a lifecycle context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivateLifecycleRequest {
    pub plugin_id: String,
    pub context_id: String,
}

/// Request to rotate lifecycle material for a context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateLifecycleRequest {
    pub plugin_id: String,
    pub context_id: String,
}

/// Request to destroy lifecycle material and bindings for a context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroyLifecycleRequest {
    pub plugin_id: String,
    pub context_id: String,
    pub mode: DestroyMode,
    pub reason: Option<String>,
}

/// Outcome of a registration operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOutcome {
    pub context_id: String,
    pub state: LifecycleState,
}

/// Outcome of an activation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationOutcome {
    pub context_id: String,
    pub state: LifecycleState,
}

/// Outcome of a rotation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationOutcome {
    pub context_id: String,
    pub state: LifecycleState,
}

/// Outcome of a destruction operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestructionOutcome {
    pub context_id: String,
    pub state: LifecycleState,
    pub remote_performed: bool,
}

/// A secret that zeroizes on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Secret(pub Vec<u8>);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Outcome of a key migration.
#[derive(Debug, Clone)]
pub enum MigrationResult {
    /// Key migrated successfully; new key ID in target plugin.
    Migrated { new_kid: KeyId },
    /// Migration requires full re-enrollment with the issuer.
    ReEnrollmentRequired { old_kid: KeyId },
}

/// How the key is stored (CS-04 §7.1.3 `key_storage` claim).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyStorageType {
    /// Software-only key (e.g. WebCrypto, JWE container).
    Software,
    /// Hardware-backed key (e.g. Secure Element, FIDO authenticator).
    Hardware,
    /// Remote HSM accessed via R2PS or similar protocol.
    RemoteHsm,
    /// Trusted Execution Environment (TEE / StrongBox).
    TrustedExecution,
}

impl KeyStorageType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Software => "software",
            Self::Hardware => "hardware",
            Self::RemoteHsm => "remote_hsm",
            Self::TrustedExecution => "trusted_execution",
        }
    }
}

/// Certification level of the WSCD (CS-04 §7.1.3 `certification` claim).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificationLevel {
    /// No certification.
    None,
    /// Baseline (self-assessed).
    Baseline,
    /// Substantial (third-party evaluation, e.g. CC EAL4+).
    Substantial,
    /// High (national scheme, e.g. Common Criteria EAL4+ AVA_VAN.5).
    High,
}

impl CertificationLevel {
    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Baseline => "baseline",
            Self::Substantial => "substantial",
            Self::High => "high",
        }
    }
}

/// Security properties of a key, as reported by the WSCD plugin.
///
/// Used by the wallet backend to populate KA JWT claims per CS-04 §7.1.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProperties {
    /// How the key material is stored.
    pub key_storage: KeyStorageType,
    /// ISO 18045 user authentication mechanisms protecting key use.
    pub user_authentication: Vec<String>,
    /// Certification level of the WSCD.
    pub certification: CertificationLevel,
    /// Authentication methods used in the last signing operation (RFC 8176 `amr` values).
    pub amr: Vec<String>,
}
