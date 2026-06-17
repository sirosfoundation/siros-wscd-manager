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
