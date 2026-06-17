use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, Signer as Ed25519Signer};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::callbacks::{AuthCallback, ProgressCallback};
use crate::error::{Result, WscdError};
use crate::traits::WscdPlugin;
use crate::types::{
    Algorithm, AttestationChain, AuthMethod, GeneratedKey, KeyId, KeyInfo, MigrationResult,
    OperationProgress, Signature,
};

/// Software-based WSCD plugin that stores keys in a JWE-encrypted container.
///
/// This replicates the Kotlin JweKeystore approach: keys are P-256 ECDSA
/// keys stored in memory and serialized to an encrypted container that
/// can be persisted by the host application.
pub struct SoftkeyPlugin {
    inner: Mutex<SoftkeyState>,
}

#[derive(Default)]
struct SoftkeyState {
    keys: HashMap<String, StoredKey>,
    next_id: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredKey {
    kid: String,
    algorithm: String,
    /// Private key scalar, base64url-encoded (32 bytes for P-256)
    d: String,
    created_at: i64,
}

impl SoftkeyPlugin {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(SoftkeyState::default()),
        }
    }

    /// Import from a serialized container (for restoring state).
    pub fn from_container(container: &[u8]) -> Result<Self> {
        let keys: Vec<StoredKey> = serde_json::from_slice(container)
            .map_err(|e| WscdError::Serialization(e.to_string()))?;
        let mut state = SoftkeyState::default();
        for key in keys {
            state.next_id = state.next_id.max(
                key.kid
                    .strip_prefix("sw-")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
                    + 1,
            );
            state.keys.insert(key.kid.clone(), key);
        }
        Ok(Self {
            inner: Mutex::new(state),
        })
    }

    /// Export the key container as JSON bytes.
    /// The caller is responsible for encrypting this (JWE) before persisting.
    pub fn export_container(&self) -> Result<Vec<u8>> {
        let state = self
            .inner
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        let keys: Vec<&StoredKey> = state.keys.values().collect();
        serde_json::to_vec(&keys).map_err(|e| WscdError::Serialization(e.to_string()))
    }

    fn load_p256_signing_key(stored: &StoredKey) -> Result<SigningKey> {
        let scalar_bytes = Base64UrlUnpadded::decode_vec(&stored.d)
            .map_err(|e| WscdError::Crypto(e.to_string()))?;
        let secret_key =
            SecretKey::from_slice(&scalar_bytes).map_err(|e| WscdError::Crypto(e.to_string()))?;
        Ok(SigningKey::from(secret_key))
    }

    /// Build a public key JWK from a P-256 verifying key.
    fn public_key_jwk_p256(vk: &VerifyingKey) -> Result<serde_json::Value> {
        let point = p256::PublicKey::from(vk).to_encoded_point(false);
        let x = Base64UrlUnpadded::encode_string(
            point
                .x()
                .ok_or_else(|| WscdError::Crypto("missing x coordinate".into()))?,
        );
        let y = Base64UrlUnpadded::encode_string(
            point
                .y()
                .ok_or_else(|| WscdError::Crypto("missing y coordinate".into()))?,
        );
        Ok(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        }))
    }
}

impl Default for SoftkeyPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WscdPlugin for SoftkeyPlugin {
    fn id(&self) -> &str {
        "softkey"
    }

    fn display_name(&self) -> &str {
        "Software Key Store"
    }

    fn auth_method(&self) -> AuthMethod {
        AuthMethod::None
    }

    async fn generate_key(
        &self,
        algorithm: Algorithm,
        _auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<GeneratedKey> {
        progress
            .on_progress(OperationProgress::Started {
                operation: "generate_key".to_string(),
            })
            .await;

        let (d_encoded, jwk_value) = match algorithm {
            Algorithm::ES256 => {
                let secret_key = SecretKey::random(&mut OsRng);
                let signing_key = SigningKey::from(secret_key.clone());
                let verifying_key = signing_key.verifying_key();
                let d = Base64UrlUnpadded::encode_string(&secret_key.to_bytes());
                let jwk = Self::public_key_jwk_p256(verifying_key)?;
                (d, jwk)
            }
            Algorithm::EdDSA => {
                let signing_key = Ed25519SigningKey::generate(&mut OsRng);
                let d = Base64UrlUnpadded::encode_string(signing_key.as_bytes());
                let public_bytes = signing_key.verifying_key().to_bytes();
                let x = Base64UrlUnpadded::encode_string(&public_bytes);
                let jwk = serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": x,
                });
                (d, jwk)
            }
        };

        let kid = {
            let mut state = self
                .inner
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;
            let kid = format!("sw-{}", state.next_id);
            state.next_id += 1;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let stored = StoredKey {
                kid: kid.clone(),
                algorithm: algorithm.as_str().to_string(),
                d: d_encoded,
                created_at: now,
            };
            state.keys.insert(kid.clone(), stored);
            kid
        };

        progress.on_progress(OperationProgress::Complete).await;

        Ok(GeneratedKey {
            kid: KeyId(kid),
            public_key_jwk: jwk_value,
        })
    }

    async fn sign(
        &self,
        kid: &KeyId,
        data: &[u8],
        _algorithm: Algorithm,
        _auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<Signature> {
        progress
            .on_progress(OperationProgress::Started {
                operation: "sign".to_string(),
            })
            .await;

        let sig_bytes = {
            let state = self
                .inner
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;
            let stored = state
                .keys
                .get(kid.as_str())
                .ok_or_else(|| WscdError::KeyNotFound {
                    kid: kid.to_string(),
                })?;

            match stored.algorithm.as_str() {
                "ES256" => {
                    let signing_key = Self::load_p256_signing_key(stored)?;
                    let sig: p256::ecdsa::Signature = signing_key.sign(data);
                    sig.to_bytes().to_vec()
                }
                "EdDSA" => {
                    let scalar_bytes = Base64UrlUnpadded::decode_vec(&stored.d)
                        .map_err(|e| WscdError::Crypto(e.to_string()))?;
                    let key_bytes: [u8; 32] = scalar_bytes
                        .try_into()
                        .map_err(|_| WscdError::Crypto("invalid Ed25519 key length".into()))?;
                    let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
                    let sig = signing_key.sign(data);
                    sig.to_bytes().to_vec()
                }
                alg => {
                    return Err(WscdError::Unsupported {
                        plugin: "softkey".to_string(),
                        op: format!("sign with algorithm {alg}"),
                    });
                }
            }
        };

        progress.on_progress(OperationProgress::Complete).await;

        Ok(Signature(sig_bytes))
    }

    async fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        let state = self
            .inner
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        Ok(state
            .keys
            .values()
            .map(|k| {
                let algorithm = match k.algorithm.as_str() {
                    "EdDSA" => Algorithm::EdDSA,
                    _ => Algorithm::ES256,
                };
                KeyInfo {
                    kid: KeyId(k.kid.clone()),
                    algorithm,
                    plugin_id: "softkey".to_string(),
                    created_at: k.created_at,
                }
            })
            .collect())
    }

    async fn attestation_chain(&self, _kid: &KeyId) -> Result<Option<AttestationChain>> {
        // Software keys have no hardware attestation
        Ok(None)
    }

    async fn delete_key(&self, kid: &KeyId) -> Result<()> {
        let mut state = self
            .inner
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        state
            .keys
            .remove(kid.as_str())
            .ok_or_else(|| WscdError::KeyNotFound {
                kid: kid.to_string(),
            })?;
        Ok(())
    }

    async fn export_public_key(&self, kid: &KeyId) -> Result<serde_json::Value> {
        let state = self
            .inner
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        let stored = state
            .keys
            .get(kid.as_str())
            .ok_or_else(|| WscdError::KeyNotFound {
                kid: kid.to_string(),
            })?;

        match stored.algorithm.as_str() {
            "ES256" => {
                let signing_key = Self::load_p256_signing_key(stored)?;
                let public_key = signing_key.verifying_key();
                Self::public_key_jwk_p256(public_key)
            }
            "EdDSA" => {
                let scalar_bytes = Base64UrlUnpadded::decode_vec(&stored.d)
                    .map_err(|e| WscdError::Crypto(e.to_string()))?;
                let key_bytes: [u8; 32] = scalar_bytes
                    .try_into()
                    .map_err(|_| WscdError::Crypto("invalid Ed25519 key length".into()))?;
                let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
                let public_bytes = signing_key.verifying_key().to_bytes();
                let x = Base64UrlUnpadded::encode_string(&public_bytes);
                Ok(serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": x,
                }))
            }
            alg => Err(WscdError::Unsupported {
                plugin: "softkey".to_string(),
                op: format!("export_public_key for algorithm {alg}"),
            }),
        }
    }

    fn supports_import(&self) -> bool {
        true
    }

    async fn import_key(
        &self,
        algorithm: Algorithm,
        _auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<MigrationResult> {
        // For import into softkey, we generate a fresh key (the old key's
        // credential binding is broken, so re-enrollment may be needed).
        // The caller (WscdManager) decides whether re-enrollment is required
        // based on the credential type.
        let generated = self.generate_key(algorithm, _auth, progress).await?;
        Ok(MigrationResult::Migrated {
            new_kid: generated.kid,
        })
    }
}
