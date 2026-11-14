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
/// The WSCD's own durable backing for the softkey plugin's key
/// container. The plugin's process memory is a CACHE of this, never the
/// source of truth: every mutation ([WscdPlugin::generate_key],
/// `delete_key`) writes the full container through BEFORE the mutating
/// call returns - a generated key is durable the moment it exists,
/// whatever later happens to the flow that requested it (the 2026-11-14
/// on-device loss: the fold into the host's container waited for a
/// flow-completion export, an app restart fell in the window, and the
/// stored credential outlived its own bound key - unrecoverable, every
/// later presentation failed "key not resolvable" forever).
///
/// The container bytes are exactly [`SoftkeyPlugin::export_container`]'s
/// output (the `ExportedContainer` shape, backwards-compatible to the
/// bare array) - one blob, written whole, atomically from the
/// implementation's own perspective. Non-file backings (a database row,
/// an OS keystore, a remote store) implement the same two operations.
///
/// Failures are the implementation's to report; the plugin treats a
/// failed write-through as non-fatal (the key IS generated and usable
/// this session) but LOUD, and the next mutation retries.
pub trait KeyBackingStore: Send + Sync {
    /// The full container as [`SoftkeyPlugin::export_container`] produces
    /// it. Write it durably - atomically, from an observer's
    /// perspective - or report the failure.
    fn write_container(&self, container: &[u8]) -> std::io::Result<()>;

    /// The container as last written, or None when the backing has never
    /// seen one (a first boot). Read exactly what a prior write stored.
    fn read_container(&self) -> std::io::Result<Option<Vec<u8>>>;
}

/// The file backing (`plugins.softkey.keys_file`): the container as a
/// single file, written tmp-then-rename so a crash mid-write never leaves
/// a torn or empty store.
pub struct FileKeyBackingStore {
    path: std::path::PathBuf,
}

impl FileKeyBackingStore {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}

impl KeyBackingStore for FileKeyBackingStore {
    fn write_container(&self, container: &[u8]) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, container)?;
        std::fs::rename(&tmp, &self.path)
    }

    fn read_container(&self) -> std::io::Result<Option<Vec<u8>>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

pub struct SoftkeyPlugin {
    inner: Mutex<SoftkeyState>,
    lifecycle: Mutex<HashMap<String, LifecycleContext>>,
    /// The WSCD's own durable backing (config: `plugins.softkey.keys_file`).
    /// When set, every mutation writes the full container through INSIDE
    /// the mutating critical section - see [`KeyBackingStore`]'s doc
    /// comment for the invariant. None: the historic volatile behaviour
    /// (tests, and hosts that own durability themselves through
    /// export/import).
    backing: Option<std::sync::Arc<dyn KeyBackingStore>>,
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
            backing: None,
        }
    }

    /// The WSCD-owned durable form: the plugin over a backing store,
    /// seeded from it when it has ever been written (a None read is a
    /// first boot - an empty plugin). See [`KeyBackingStore`]'s doc
    /// comment for the invariant.
    pub fn with_backing_store(backing: std::sync::Arc<dyn KeyBackingStore>) -> Result<Self> {
        let mut plugin = Self::new();
        if let Some(bytes) = backing
            .read_container()
            .map_err(|e| WscdError::Serialization(format!("backing unreadable: {e}")))?
        {
            plugin = Self::from_container(&bytes)?;
        }
        plugin.backing = Some(backing);
        Ok(plugin)
    }

    /// The file-backed form (`plugins.softkey.keys_file`).
    pub fn with_keys_file(keys_file: std::path::PathBuf) -> Result<Self> {
        Self::with_backing_store(std::sync::Arc::new(FileKeyBackingStore::new(keys_file)))
    }

    /// The write-through: the full container, atomically to [Self::keys_file].
    /// Called INSIDE the mutating lock, so the file never holds a torn view.
    /// Fail-soft (the key IS generated and usable this session; the next
    /// mutation retries the write) but LOUD: eprintln, the plugin's error
    /// path when no host callback is in flight.
    fn write_through(&self) {
        let Some(backing) = &self.backing else { return };
        // Locks lifecycle before inner - export_container's own order, so
        // the two can never deadlock against a concurrent call holding
        // both (register_lifecycle's order matches).
        let exported = {
            let lifecycle = self.lock_lifecycle();
            let state = self.lock_inner();
            ExportedContainer {
                keys: state.keys.values().cloned().collect(),
                lifecycle: lifecycle.clone(),
            }
        };
        let bytes = match serde_json::to_vec(&exported) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!(
                    "softkey: durable write-through failed ({}); the next mutation retries",
                    WscdError::Serialization(e.to_string())
                );
                return;
            }
        };
        if let Err(e) = backing.write_container(&bytes) {
            eprintln!("softkey: durable write-through failed ({e}); the next mutation retries");
        }
    }

    /// Lock `inner`, recovering from poison instead of propagating it - see
    /// `FfiWscdManager::lock_inner`'s doc comment (src/ffi.rs) for why: a
    /// panic elsewhere while this lock is held must not permanently brick
    /// every subsequent call to this plugin for the life of the process.
    fn lock_inner(&self) -> std::sync::MutexGuard<'_, SoftkeyState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Lock `lifecycle`, recovering from poison - see [`Self::lock_inner`].
    fn lock_lifecycle(&self) -> std::sync::MutexGuard<'_, HashMap<String, LifecycleContext>> {
        self.lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
            backing: None,
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
            // Deliberately unsupported rather than silently substituted.
            // A BBS key binding key must live on BLS12-381 G1; there is no
            // software fallback here today, and quietly generating a P-256
            // key would produce a credential that cannot be presented.
            Algorithm::Bls12381G1Schnorr => {
                return Err(WscdError::Unsupported {
                    plugin: self.id().to_string(),
                    op: "generate_key(Bls12381G1Schnorr)".to_string(),
                });
            }
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
            // Durable BEFORE the lock drops and the call returns - the
            // WSCD's own store, not a host's later export (the 2026-11-14
            // on-device loss: the fold waited for a flow-completion export,
            // an app restart fell in the window, and the credential
            // outlived its own bound key - unrecoverable).
            self.write_through();
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
        // The deletion's write-through: a deleted key leaves the durable
        // store before the call returns (same invariant, the removal half).
        self.write_through();
        drop(state);
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

    /// A temp-dir backing-file helper for the invariance tests.
    fn temp_keys_file(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "softkey-invariant-{}-{}",
            name,
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join("keys.json")
    }

    /// THE INVARIANT: a generated key is durable BEFORE generate_key
    /// returns. The 2026-11-14 on-device loss (the Spherity PID
    /// credential): the fold into the host's container waited for a
    /// flow-completion export, an app restart fell in the window, and
    /// the stored credential outlived its own bound key - every later
    /// presentation failed "key not resolvable" forever.
    #[tokio::test]
    async fn a_generated_key_is_durable_before_generate_key_returns() {
        let keys_file = temp_keys_file("gen-durable");
        let _ = std::fs::remove_file(&keys_file);
        let plugin = SoftkeyPlugin::with_keys_file(keys_file.clone()).expect("plugin");

        let kid = plugin
            .generate_key(Algorithm::ES256, &UnusedAuth, &NoopProgress)
            .await
            .expect("generate")
            .kid;

        // A FRESH plugin instance over the same file (a process restart)
        // must see the key: the file was written BEFORE generate returned.
        let restarted = SoftkeyPlugin::with_keys_file(keys_file).expect("reload");
        let listed = restarted.list_keys().await.expect("list");
        assert!(
            listed.iter().any(|k| k.kid.as_str() == kid.as_str()),
            "the generated key did not survive the process: the write-through invariant is broken"
        );
    }

    /// The deletion's twin: a deleted key is GONE from the backing before
    /// delete_key returns - or a restart resurrects a key its own plugin
    /// reported deleted.
    #[tokio::test]
    async fn a_deleted_key_is_gone_before_delete_key_returns() {
        let keys_file = temp_keys_file("delete-durable");
        let _ = std::fs::remove_file(&keys_file);
        let plugin = SoftkeyPlugin::with_keys_file(keys_file.clone()).expect("plugin");
        let kid = plugin
            .generate_key(Algorithm::ES256, &UnusedAuth, &NoopProgress)
            .await
            .expect("generate")
            .kid;

        plugin.delete_key(&kid).await.expect("delete");

        let restarted = SoftkeyPlugin::with_keys_file(keys_file).expect("reload");
        let listed = restarted.list_keys().await.expect("list");
        assert!(
            !listed.iter().any(|k| k.kid.as_str() == kid.as_str()),
            "the deleted key survived the process: the deletion write-through is broken"
        );
    }

    /// The custom backing: a non-file store (the trait's reason for
    /// existing - a DB row, an OS keystore) sees the same invariant
    /// through the same two operations.
    #[tokio::test]
    async fn a_custom_backing_store_sees_every_write_through() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static WRITES: AtomicUsize = AtomicUsize::new(0);
        struct CountingBacking;
        impl KeyBackingStore for CountingBacking {
            fn write_container(&self, _container: &[u8]) -> std::io::Result<()> {
                WRITES.fetch_add(1, Ordering::SeqCst);
                // Keep the last container in memory: read returns it.
                LAST.with(|c| *c.borrow_mut() = Some(_container.to_vec()));
                Ok(())
            }
            fn read_container(&self) -> std::io::Result<Option<Vec<u8>>> {
                LAST.with(|c| Ok(c.borrow().clone()))
            }
        }
        thread_local! {
            static LAST: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
        }

        let plugin =
            SoftkeyPlugin::with_backing_store(std::sync::Arc::new(CountingBacking)).expect("plugin");
        let before = WRITES.load(Ordering::SeqCst);
        plugin
            .generate_key(Algorithm::ES256, &UnusedAuth, &NoopProgress)
            .await
            .expect("generate");
        assert!(
            WRITES.load(Ordering::SeqCst) > before,
            "the custom backing saw no write-through"
        );
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
