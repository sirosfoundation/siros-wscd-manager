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
    /// Schnorr over BLS12-381 G1, on the curve's standard base point,
    /// SHA-256 challenge, SEC1 nonce encoding — COSE algorithm **-65609**
    /// (`EcsdsaBls12_381_BP1_Sha256_SEC1`, a placeholder identifier).
    ///
    /// This is the key binding algorithm for blind BBS credentials (see
    /// the `zk-cred-bbs` crate's `PROFILE.md`). It exists on YubiKey 5.8
    /// alpha firmware and nowhere else — **no platform secure element can
    /// do BLS12-381**, so a plugin backed by Android Keystore or the iOS
    /// Secure Enclave must reject it rather than substitute a curve.
    ///
    /// Its signing contract differs from the other two: see
    /// [`Algorithm::signs_prehashed_input`].
    Bls12381G1Schnorr,
}

impl Algorithm {
    pub fn as_str(&self) -> &str {
        match self {
            Algorithm::ES256 => "ES256",
            Algorithm::EdDSA => "EdDSA",
            Algorithm::Bls12381G1Schnorr => "EcsdsaBls12381Bp1Sha256Sec1",
        }
    }
}

impl Algorithm {
    /// Whether `data` passed to [`crate::traits::WscdPlugin::sign`] is the
    /// exact message to be signed, rather than input the plugin should
    /// hash first.
    ///
    /// **This distinction is load-bearing, not cosmetic.** ES256 signing
    /// here takes arbitrary-length input (a JWS signing input, say) and the
    /// plugin hashes it, because a real YubiKey rejects long input with
    /// CTAP2 `0x03`. A BBS key binding challenge arrives *already*
    /// SHA-256'd by the caller — `zk-cred-bbs` hashes it to fit the
    /// authenticator's 64-octet ceiling — so hashing it again produces
    /// `SHA-256(SHA-256(challenge))`, and every resulting proof fails
    /// verification with no indication of why.
    pub fn signs_prehashed_input(&self) -> bool {
        matches!(self, Algorithm::Bls12381G1Schnorr)
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
    /// The clientDataHash bound into the attestation signature at key
    /// creation (CTAP2 `authenticatorMakeCredential`'s `clientDataHash`
    /// parameter, not a full WebAuthn clientDataJSON — there is no browser
    /// in this flow). Required to verify `certificates`' attestation
    /// statement (the signature covers `authData || client_data_hash`);
    /// empty for plugins/attestation formats that don't need it (e.g.
    /// none/self-attestation).
    pub client_data_hash: Vec<u8>,
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

impl std::ops::Deref for Secret {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        &self.0
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
