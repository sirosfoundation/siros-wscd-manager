use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as Ed25519SigningKey};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::elliptic_curve::Generate;
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::callbacks::{AuthCallback, ProgressCallback};
use crate::error::{Result, WscdError};
use crate::traits::WscdPlugin;
use crate::types::{
    ActivateLifecycleRequest, ActivationOutcome, DestroyLifecycleRequest, DestructionOutcome,
    RegisterLifecycleRequest, RegistrationOutcome, RotateLifecycleRequest, RotationOutcome,
};
use crate::types::{
    Algorithm, AttestationChain, AuthMethod, CertificationLevel, FactorKind, GeneratedKey, KeyId,
    KeyInfo, KeyStorageType, LifecycleState, LifecycleStatus, MigrationResult, OperationProgress,
    SecurityProperties, Signature,
};

/// Software-based WSCD plugin that stores keys in a JWE-encrypted container.
///
/// This replicates the Kotlin JweKeystore approach: keys are P-256 ECDSA
/// keys stored in memory and serialized to an encrypted container that
/// can be persisted by the host application.
pub struct SoftkeyPlugin {
    inner: Mutex<SoftkeyState>,
    lifecycle: Mutex<HashMap<String, LifecycleContext>>,
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

#[derive(Clone, Serialize, Deserialize)]
struct LifecycleContext {
    factor_kind: FactorKind,
    state: LifecycleState,
    updated_at: i64,
    key_ids: Vec<KeyId>,
}

/// Wire shape for [`SoftkeyPlugin::export_container`]/[`SoftkeyPlugin::from_container`] -
/// snapshots the stored keys and the plugin's separate `lifecycle` map
/// (context ID -> which keys it owns) in one blob, mirroring
/// `PreviewSignPlugin`'s `ExportedPluginState`, so `destroyLifecycle`/
/// `rotateLifecycle` still work against a restored plugin after a process
/// restart, not just `listKeys`. `lifecycle` defaults to empty on
/// deserialize so a blob exported before this field existed still loads
/// (with no lifecycle contexts, matching the old behavior exactly).
#[derive(Serialize, Deserialize)]
struct ExportedContainer {
    keys: Vec<StoredKey>,
    #[serde(default)]
    lifecycle: HashMap<String, LifecycleContext>,
}

impl SoftkeyPlugin {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(SoftkeyState::default()),
            lifecycle: Mutex::new(HashMap::new()),
        }
    }

    /// Lock `inner`, recovering from poison instead of propagating it - see
    /// `FfiWscdManager::lock_inner`'s doc comment (src/ffi.rs) for why: a
    /// panic elsewhere while this lock is held must not permanently brick
    /// every subsequent call to this plugin for the life of the process.
    fn lock_inner(&self) -> std::sync::MutexGuard<'_, SoftkeyState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Lock `lifecycle`, recovering from poison - see [`Self::lock_inner`].
    fn lock_lifecycle(&self) -> std::sync::MutexGuard<'_, HashMap<String, LifecycleContext>> {
        self.lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Import from a serialized container (for restoring state).
    pub fn from_container(container: &[u8]) -> Result<Self> {
        // Older containers are a bare `[StoredKey, ...]` array with no
        // lifecycle bookkeeping; newer ones are an `ExportedContainer`
        // object. Try the new shape first, falling back to the old one so
        // a container exported before this field existed still loads
        // (with no lifecycle contexts, matching the old behavior exactly).
        let (keys, lifecycle) = match serde_json::from_slice::<ExportedContainer>(container) {
            Ok(exported) => (exported.keys, exported.lifecycle),
            Err(_) => {
                let keys: Vec<StoredKey> = serde_json::from_slice(container)
                    .map_err(|e| WscdError::Serialization(e.to_string()))?;
                (keys, HashMap::new())
            }
        };
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
            lifecycle: Mutex::new(lifecycle),
        })
    }

    /// Export the key container (plus lifecycle bookkeeping) as JSON bytes.
    /// The caller is responsible for encrypting this (JWE) before persisting.
    ///
    /// Locks `lifecycle` before `inner` - the same order `register_lifecycle`
    /// uses when it holds both at once, so the two can never deadlock against
    /// each other regardless of call interleaving.
    pub fn export_container(&self) -> Result<Vec<u8>> {
        let lifecycle = self.lock_lifecycle();
        let state = self.lock_inner();
        let exported = ExportedContainer {
            keys: state.keys.values().cloned().collect(),
            lifecycle: lifecycle.clone(),
        };
        serde_json::to_vec(&exported).map_err(|e| WscdError::Serialization(e.to_string()))
    }

    fn load_p256_signing_key(stored: &StoredKey) -> Result<SigningKey> {
        let scalar_bytes = Base64UrlUnpadded::decode_vec(&stored.d)
            .map_err(|e| WscdError::Crypto(e.to_string()))?;
        let secret_key =
            SecretKey::from_slice(&scalar_bytes).map_err(|e| WscdError::Crypto(e.to_string()))?;
        Ok(SigningKey::from(secret_key))
    }

    fn now_unix() -> i64 {
        crate::timeutil::now_unix()
    }

    /// Build a public key JWK from a P-256 verifying key.
    fn public_key_jwk_p256(vk: &VerifyingKey) -> Result<serde_json::Value> {
        let point = p256::PublicKey::from(vk).to_sec1_point(false);
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
                let signing_key = SigningKey::generate();
                let secret_key = signing_key.to_bytes();
                let verifying_key = signing_key.verifying_key();
                let d = Base64UrlUnpadded::encode_string(&secret_key);
                let jwk = Self::public_key_jwk_p256(verifying_key)?;
                (d, jwk)
            }
            Algorithm::EdDSA => {
                let signing_key = Ed25519SigningKey::generate(&mut rand::rand_core::UnwrapErr(
                    rand::rngs::SysRng,
                ));
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
            let mut state = self.lock_inner();
            let kid = format!("sw-{}", state.next_id);
            state.next_id += 1;

            let now = Self::now_unix();

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
            let state = self.lock_inner();
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
        let state = self.lock_inner();
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
        let mut state = self.lock_inner();
        state
            .keys
            .remove(kid.as_str())
            .ok_or_else(|| WscdError::KeyNotFound {
                kid: kid.to_string(),
            })?;
        Ok(())
    }

    async fn export_public_key(&self, kid: &KeyId) -> Result<serde_json::Value> {
        let state = self.lock_inner();
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

    fn security_properties(&self, kid: &KeyId) -> Result<SecurityProperties> {
        let state = self
            .inner
            .lock()
            .map_err(|e: std::sync::PoisonError<_>| WscdError::Plugin(e.to_string()))?;
        if !state.keys.contains_key(kid.as_str()) {
            return Err(WscdError::KeyNotFound {
                kid: kid.to_string(),
            });
        }
        Ok(SecurityProperties {
            key_storage: KeyStorageType::Software,
            user_authentication: vec![],
            certification: CertificationLevel::None,
            amr: vec!["swk".to_string()],
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn supports_lifecycle(&self) -> bool {
        true
    }

    async fn lifecycle_status(&self, context_id: &str) -> Result<LifecycleStatus> {
        let lifecycle = self.lock_lifecycle();
        let ctx = lifecycle
            .get(context_id)
            .ok_or_else(|| WscdError::KeyNotFound {
                kid: context_id.to_string(),
            })?;
        Ok(LifecycleStatus {
            context_id: context_id.to_string(),
            plugin_id: self.id().to_string(),
            factor_kind: ctx.factor_kind,
            state: ctx.state,
            updated_at: ctx.updated_at,
        })
    }

    async fn register_lifecycle(
        &self,
        request: &RegisterLifecycleRequest,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<RegistrationOutcome> {
        let generated = self.generate_key(Algorithm::ES256, auth, progress).await?;
        let now = Self::now_unix();
        let mut lifecycle = self.lock_lifecycle();

        // Re-registering an already-registered context (Enroll tapped again
        // without an intervening Destroy) used to just overwrite `key_ids`
        // with the newest key, silently orphaning whatever key(s) the old
        // context pointed at: they stayed in `state.keys` forever since
        // destroy_lifecycle only ever looks at the CURRENT context's
        // key_ids. Purge the old context's keys first so re-registering
        // behaves like an implicit destroy-then-register and never leaks
        // keys - mirrors the same fix in preview_sign.rs's register_lifecycle.
        if let Some(old_ctx) = lifecycle.get(&request.context_id) {
            let mut state = self.lock_inner();
            for stale_kid in &old_ctx.key_ids {
                state.keys.remove(stale_kid.as_str());
            }
        }

        lifecycle.insert(
            request.context_id.clone(),
            LifecycleContext {
                factor_kind: request.factor_kind,
                state: LifecycleState::Registered,
                updated_at: now,
                key_ids: vec![generated.kid],
            },
        );
        Ok(RegistrationOutcome {
            context_id: request.context_id.clone(),
            state: LifecycleState::Registered,
        })
    }

    async fn activate_lifecycle(
        &self,
        request: &ActivateLifecycleRequest,
        _auth: &dyn AuthCallback,
        _progress: &dyn ProgressCallback,
    ) -> Result<ActivationOutcome> {
        let now = Self::now_unix();
        let mut lifecycle = self.lock_lifecycle();
        let ctx = lifecycle
            .get_mut(&request.context_id)
            .ok_or_else(|| WscdError::KeyNotFound {
                kid: request.context_id.clone(),
            })?;
        ctx.state = LifecycleState::Active;
        ctx.updated_at = now;
        Ok(ActivationOutcome {
            context_id: request.context_id.clone(),
            state: LifecycleState::Active,
        })
    }

    async fn rotate_lifecycle(
        &self,
        request: &RotateLifecycleRequest,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<RotationOutcome> {
        let generated = self.generate_key(Algorithm::ES256, auth, progress).await?;
        let now = Self::now_unix();
        let mut lifecycle = self.lock_lifecycle();
        let ctx = lifecycle
            .get_mut(&request.context_id)
            .ok_or_else(|| WscdError::KeyNotFound {
                kid: request.context_id.clone(),
            })?;
        ctx.key_ids.push(generated.kid);
        ctx.updated_at = now;
        Ok(RotationOutcome {
            context_id: request.context_id.clone(),
            state: ctx.state,
        })
    }

    async fn destroy_lifecycle(
        &self,
        request: &DestroyLifecycleRequest,
        _auth: &dyn AuthCallback,
        _progress: &dyn ProgressCallback,
    ) -> Result<DestructionOutcome> {
        let key_ids = {
            let lifecycle = self.lock_lifecycle();
            lifecycle
                .get(&request.context_id)
                .map(|ctx| ctx.key_ids.clone())
                .ok_or_else(|| WscdError::KeyNotFound {
                    kid: request.context_id.clone(),
                })?
        };
        {
            let mut state = self.lock_inner();
            for kid in &key_ids {
                state.keys.remove(kid.as_str());
            }
        }
        let now = Self::now_unix();
        let mut lifecycle = self.lock_lifecycle();
        if let Some(ctx) = lifecycle.get_mut(&request.context_id) {
            ctx.state = LifecycleState::Destroyed;
            ctx.updated_at = now;
            ctx.key_ids.clear();
        }
        Ok(DestructionOutcome {
            context_id: request.context_id.clone(),
            state: LifecycleState::Destroyed,
            remote_performed: false,
        })
    }
}

#[cfg(test)]
mod container_persistence_tests {
    use super::*;
    use crate::callbacks::NoopProgress;

    struct UnusedAuth;

    #[async_trait]
    impl AuthCallback for UnusedAuth {
        async fn request_pin(&self, _plugin_id: &str) -> Result<crate::types::Secret> {
            panic!("auth should not be used by destroy_lifecycle/rotate_lifecycle");
        }
        async fn request_webauthn_assertion(
            &self,
            _plugin_id: &str,
            _challenge: &[u8],
            _rp_id: &str,
            _allowed_credentials: &[Vec<u8>],
        ) -> Result<Vec<u8>> {
            panic!("auth should not be used by destroy_lifecycle/rotate_lifecycle");
        }
    }

    fn sample_exported_container() -> ExportedContainer {
        let mut lifecycle = HashMap::new();
        lifecycle.insert(
            "ctx-1".to_string(),
            LifecycleContext {
                factor_kind: FactorKind::Opaque,
                state: LifecycleState::Registered,
                updated_at: 1_700_000_000,
                key_ids: vec![KeyId("sw-0".to_string())],
            },
        );
        ExportedContainer {
            keys: vec![StoredKey {
                kid: "sw-0".to_string(),
                algorithm: "ES256".to_string(),
                d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                created_at: 1_700_000_000,
            }],
            lifecycle,
        }
    }

    #[test]
    fn export_container_round_trips_keys_and_lifecycle() {
        let exported = sample_exported_container();
        let bytes = serde_json::to_vec(&exported).unwrap();
        let plugin = SoftkeyPlugin::from_container(&bytes).unwrap();

        let state = plugin.lock_inner();
        assert_eq!(state.keys.len(), 1);
        assert!(state.keys.contains_key("sw-0"));
        drop(state);

        let lifecycle = plugin.lock_lifecycle();
        assert_eq!(lifecycle.len(), 1);
        assert_eq!(lifecycle["ctx-1"].key_ids, vec![KeyId("sw-0".to_string())]);
        drop(lifecycle);

        let re_exported_bytes = plugin.export_container().unwrap();
        let re_exported: ExportedContainer = serde_json::from_slice(&re_exported_bytes).unwrap();
        assert_eq!(re_exported.keys.len(), 1);
        assert_eq!(re_exported.lifecycle.len(), 1);
    }

    #[test]
    fn old_container_without_lifecycle_field_still_loads() {
        // Simulates a container exported before `lifecycle` existed on the
        // wire - a bare `[StoredKey, ...]` array.
        let legacy_json =
            r#"[{"kid":"sw-0","algorithm":"ES256","d":"AAAA","created_at":1700000000}]"#;
        let plugin = SoftkeyPlugin::from_container(legacy_json.as_bytes()).unwrap();
        assert!(plugin.lock_lifecycle().is_empty());
        assert_eq!(plugin.lock_inner().keys.len(), 1);
    }

    #[tokio::test]
    async fn destroy_lifecycle_works_against_a_restored_plugin() {
        let exported = sample_exported_container();
        let bytes = serde_json::to_vec(&exported).unwrap();
        let plugin = SoftkeyPlugin::from_container(&bytes).unwrap();

        let request = DestroyLifecycleRequest {
            plugin_id: "softkey".to_string(),
            context_id: "ctx-1".to_string(),
            mode: crate::types::DestroyMode::LocalOnly,
            reason: None,
        };
        let outcome = plugin
            .destroy_lifecycle(&request, &UnusedAuth, &NoopProgress)
            .await
            .expect("destroy_lifecycle should find the restored context");
        assert_eq!(outcome.state, LifecycleState::Destroyed);

        // The key that context owned should now be gone.
        assert!(plugin.lock_inner().keys.is_empty());
    }
}
