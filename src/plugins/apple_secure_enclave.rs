use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::callbacks::{AuthCallback, ProgressCallback, SecureEnclaveCallback};
use crate::error::{Result, WscdError};
use crate::traits::WscdPlugin;
use crate::types::{
    Algorithm, AttestationChain, AuthMethod, CertificationLevel, GeneratedKey, KeyId, KeyInfo,
    KeyStorageType, MigrationResult, OperationProgress, SecurityProperties, Signature,
};

/// Apple Secure Enclave WSCD plugin.
///
/// Generates P-256 signing keys in the Secure Enclave (via the host's
/// [`SecureEnclaveCallback`] implementation, backed by CryptoKit's
/// `SecureEnclave.P256.Signing.PrivateKey` + a Keychain tag) and stores
/// only the resulting `kid -> key_tag` mapping and public key here - the
/// private key material never leaves the Secure Enclave and this plugin
/// never sees it, mirroring how [`crate::plugins::preview_sign::PreviewSignPlugin`]
/// only ever stores a FIDO2 authenticator's credential handle, not key
/// material.
///
/// # Staged release: no per-key attestation
///
/// This plugin reports `security_properties().certification` as
/// [`CertificationLevel::None`] and [`WscdPlugin::attestation_chain`] always
/// returns `Ok(None)` - see [`SecureEnclaveCallback`]'s doc comment for why.
/// `security_properties().key_storage` is still honestly
/// [`KeyStorageType::Hardware`]: the OS API itself refuses to hand back
/// anything but a Secure-Enclave-resident key, which is a real (if
/// unattested) guarantee, unlike a claim this plugin would otherwise have
/// no basis for.
///
/// # Supported algorithm
///
/// ES256 (P-256) only - the Secure Enclave has no EdDSA support, and
/// nowhere near enough of a pairing-friendly curve for
/// [`Algorithm::Bls12381G1Schnorr`]. This mirrors the single-algorithm
/// restriction [`crate::plugins::preview_sign`]'s Android counterpart
/// (`AndroidKeystoreSigner`) already self-imposes, not a new asymmetry.
pub struct AppleSecureEnclavePlugin {
    callback: Box<dyn SecureEnclaveCallback>,
    state: Mutex<PluginState>,
}

#[derive(Default, Serialize, Deserialize)]
struct PluginState {
    keys: HashMap<String, StoredKey>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredKey {
    /// The Keychain tag this key was generated under - the only handle
    /// the host needs to find it again via `SecureEnclaveCallback`.
    key_tag: String,
    /// Public key x-coordinate (32 bytes, P-256).
    pub_x: Vec<u8>,
    /// Public key y-coordinate (32 bytes, P-256).
    pub_y: Vec<u8>,
    created_at: i64,
}

/// Wire shape for [`AppleSecureEnclavePlugin::export_container`]/
/// [`AppleSecureEnclavePlugin::from_container`] - only public identifiers,
/// never key material (which stays in the Secure Enclave), the same
/// contract [`crate::plugins::preview_sign::PreviewSignPlugin::export_state`]
/// already has for FIDO2.
#[derive(Serialize, Deserialize)]
struct ExportedContainer {
    keys: HashMap<String, StoredKey>,
}

impl AppleSecureEnclavePlugin {
    pub fn new(callback: Box<dyn SecureEnclaveCallback>) -> Self {
        Self {
            callback,
            state: Mutex::new(PluginState::default()),
        }
    }

    /// Restore from a previously [`Self::export_container`]-exported blob.
    pub fn from_container(
        callback: Box<dyn SecureEnclaveCallback>,
        container: &[u8],
    ) -> Result<Self> {
        let exported: ExportedContainer = serde_json::from_slice(container)
            .map_err(|e| WscdError::Serialization(e.to_string()))?;
        Ok(Self {
            callback,
            state: Mutex::new(PluginState {
                keys: exported.keys,
            }),
        })
    }

    /// Export the key registry (Keychain tags + public keys only, no
    /// private material) as JSON bytes, for the host app to persist and
    /// restore via [`Self::from_container`] on next launch.
    pub fn export_container(&self) -> Result<Vec<u8>> {
        let state = self.lock_state();
        let exported = ExportedContainer {
            keys: state.keys.clone(),
        };
        serde_json::to_vec(&exported).map_err(|e| WscdError::Serialization(e.to_string()))
    }

    /// Lock `state`, recovering from poison instead of propagating it -
    /// same reasoning as `SoftkeyPlugin::lock_inner`: a foreign-callback
    /// panic elsewhere must not permanently brick this plugin for the rest
    /// of the process.
    fn lock_state(&self) -> std::sync::MutexGuard<'_, PluginState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Ids of the keys this plugin holds, for `WscdManager::bind_keys`
    /// after a restore from [`Self::from_container`] - without it the
    /// manager routes these kids to the default plugin, which does not
    /// know them. Mirrors
    /// [`crate::plugins::preview_sign::PreviewSignPlugin::key_ids`].
    pub fn key_ids(&self) -> Vec<KeyId> {
        let state = self.lock_state();
        state.keys.keys().map(|k| KeyId(k.clone())).collect()
    }

    fn public_key_jwk(x: &[u8], y: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": Base64UrlUnpadded::encode_string(x),
            "y": Base64UrlUnpadded::encode_string(y),
        })
    }

    /// Generate a fresh random Keychain tag. Unlike `kid` (an RFC 7638 JWK
    /// thumbprint, see `crate::plugins::jwk_thumbprint`), this identifies
    /// the Keychain item *before* the public key exists yet, so it can't be
    /// derived from the key - 128 random bits, same approach
    /// `PreviewSignPlugin` uses for its own internal nonces.
    fn random_key_tag() -> String {
        let mut bytes = [0u8; 16];
        rand::fill(&mut bytes);
        let mut out = String::with_capacity("apple-se-tag-".len() + 32);
        out.push_str("apple-se-tag-");
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(out, "{b:02x}");
        }
        out
    }
}

#[async_trait]
impl WscdPlugin for AppleSecureEnclavePlugin {
    fn id(&self) -> &str {
        "apple-se"
    }

    fn display_name(&self) -> &str {
        "Apple Secure Enclave"
    }

    fn auth_method(&self) -> AuthMethod {
        // No PIN/WebAuthn ceremony from this crate's point of view - any
        // biometric gate on key use is baked into the key's own
        // SecAccessControl at creation and enforced transparently inside
        // the host's CryptoKit call, the same way a softkey needs none.
        AuthMethod::None
    }

    async fn generate_key(
        &self,
        algorithm: Algorithm,
        _auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<GeneratedKey> {
        if algorithm != Algorithm::ES256 {
            return Err(WscdError::Unsupported {
                plugin: self.id().to_string(),
                op: format!("generate_key({algorithm})"),
            });
        }

        progress
            .on_progress(OperationProgress::Started {
                operation: "generate_key".to_string(),
            })
            .await;

        let key_tag = Self::random_key_tag();
        let public_key = self.callback.generate_key(&key_tag).await?;
        let jwk = Self::public_key_jwk(&public_key.x, &public_key.y);
        let kid = crate::plugins::jwk_thumbprint(&jwk)?;
        {
            let mut state = self.lock_state();
            state.keys.insert(
                kid.clone(),
                StoredKey {
                    key_tag,
                    pub_x: public_key.x,
                    pub_y: public_key.y,
                    created_at: crate::timeutil::now_unix(),
                },
            );
        }

        progress.on_progress(OperationProgress::Complete).await;

        Ok(GeneratedKey {
            kid: KeyId(kid),
            public_key_jwk: jwk,
        })
    }

    async fn sign(
        &self,
        kid: &KeyId,
        data: &[u8],
        algorithm: Algorithm,
        _auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<Signature> {
        if algorithm != Algorithm::ES256 {
            return Err(WscdError::Unsupported {
                plugin: self.id().to_string(),
                op: format!("sign({algorithm})"),
            });
        }

        progress
            .on_progress(OperationProgress::Started {
                operation: "sign".to_string(),
            })
            .await;

        let key_tag = {
            let state = self.lock_state();
            state
                .keys
                .get(kid.as_str())
                .map(|k| k.key_tag.clone())
                .ok_or_else(|| WscdError::KeyNotFound {
                    kid: kid.to_string(),
                })?
        };

        let sig_bytes = self.callback.sign(&key_tag, data).await?;

        progress.on_progress(OperationProgress::Complete).await;

        Ok(Signature(sig_bytes))
    }

    async fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        let state = self.lock_state();
        Ok(state
            .keys
            .iter()
            .map(|(kid, stored)| KeyInfo {
                kid: KeyId(kid.clone()),
                algorithm: Algorithm::ES256,
                plugin_id: self.id().to_string(),
                created_at: stored.created_at,
            })
            .collect())
    }

    /// Always `Ok(None)` in this staged release - see this plugin's and
    /// [`SecureEnclaveCallback`]'s doc comments for why a real per-key
    /// attestation chain isn't produced yet.
    async fn attestation_chain(&self, _kid: &KeyId) -> Result<Option<AttestationChain>> {
        Ok(None)
    }

    async fn delete_key(&self, kid: &KeyId) -> Result<()> {
        // Look up (don't remove) first, and only remove the registry entry
        // once the host confirms the Keychain item is actually gone. A
        // Copilot review finding on this PR: removing the entry up front
        // meant a failed `callback.delete_key` (host offline, Keychain
        // error) left the Secure Enclave key alive but unreachable - this
        // plugin would report `KeyNotFound` on every later retry without
        // ever calling the callback again, and the stale tag would also
        // vanish from `export_container`'s next snapshot.
        let key_tag = {
            let state = self.lock_state();
            state
                .keys
                .get(kid.as_str())
                .map(|k| k.key_tag.clone())
                .ok_or_else(|| WscdError::KeyNotFound {
                    kid: kid.to_string(),
                })?
        };
        match self.callback.delete_key(&key_tag).await {
            Ok(()) => {}
            // A second Copilot review finding on this PR: if the host's
            // Keychain delete succeeds but the process stops before the
            // caller persists this plugin's updated `export_container`
            // snapshot (crash, force-quit, killed in the background), a
            // restart restores the OLD state - this registry entry, for a
            // key the Keychain no longer has. Without this arm, the next
            // delete attempt reaches the callback, which correctly reports
            // `KeyNotFound` for the already-gone Keychain item, and the `?`
            // this replaced would propagate that as a failure - leaving a
            // permanently stuck registry entry that can never be cleaned up
            // (every retry hits this exact same callback failure forever).
            // Treat "the host says it's already gone" as "deleted", not as
            // a stuck failure.
            Err(WscdError::KeyNotFound { .. }) => {}
            Err(e) => return Err(e),
        }
        self.lock_state().keys.remove(kid.as_str());
        Ok(())
    }

    async fn export_public_key(&self, kid: &KeyId) -> Result<serde_json::Value> {
        let state = self.lock_state();
        let stored = state
            .keys
            .get(kid.as_str())
            .ok_or_else(|| WscdError::KeyNotFound {
                kid: kid.to_string(),
            })?;
        Ok(Self::public_key_jwk(&stored.pub_x, &stored.pub_y))
    }

    fn supports_import(&self) -> bool {
        false
    }

    async fn import_key(
        &self,
        _algorithm: Algorithm,
        _auth: &dyn AuthCallback,
        _progress: &dyn ProgressCallback,
    ) -> Result<MigrationResult> {
        Err(WscdError::Unsupported {
            plugin: self.id().to_string(),
            op: "import_key".to_string(),
        })
    }

    fn security_properties(&self, kid: &KeyId) -> Result<SecurityProperties> {
        let state = self.lock_state();
        if !state.keys.contains_key(kid.as_str()) {
            return Err(WscdError::KeyNotFound {
                kid: kid.to_string(),
            });
        }
        Ok(SecurityProperties {
            // Honest about the mechanism (the OS API only ever returns a
            // Secure-Enclave-resident key) without over-claiming a
            // certification level nothing here can prove - see the
            // module/trait doc comments.
            key_storage: KeyStorageType::Hardware,
            user_authentication: vec![],
            certification: CertificationLevel::None,
            // RFC 8176 "hwk" - hardware-secured key.
            amr: vec!["hwk".to_string()],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FakeAuth;
    #[async_trait]
    impl AuthCallback for FakeAuth {
        async fn request_pin(&self, _plugin_id: &str) -> Result<crate::types::Secret> {
            unreachable!("apple-se never requests a PIN")
        }
        async fn request_webauthn_assertion(
            &self,
            _plugin_id: &str,
            _challenge: &[u8],
            _rp_id: &str,
            _allowed_credentials: &[Vec<u8>],
        ) -> Result<Vec<u8>> {
            unreachable!("apple-se never requests a WebAuthn assertion")
        }
    }

    struct NoopProgress;
    #[async_trait]
    impl ProgressCallback for NoopProgress {
        async fn on_progress(&self, _progress: OperationProgress) {}
    }

    /// A fake [`SecureEnclaveCallback`] that behaves like a real Secure
    /// Enclave for the purposes a Linux test host can exercise: it hands
    /// back deterministic-but-distinct "public keys" per tag and tracks
    /// live tags so `sign`/`delete_key` on an unknown tag fail the way the
    /// real Keychain lookup would. It cannot and does not stand in for a
    /// real Secure Enclave signature - that part only Mac-mini hardware
    /// verification on the Swift side can confirm.
    struct FakeSecureEnclave {
        next: AtomicU64,
        live_tags: Mutex<std::collections::HashSet<String>>,
    }

    impl FakeSecureEnclave {
        fn new() -> Self {
            Self {
                next: AtomicU64::new(0),
                live_tags: Mutex::new(std::collections::HashSet::new()),
            }
        }
    }

    #[async_trait]
    impl SecureEnclaveCallback for FakeSecureEnclave {
        async fn generate_key(
            &self,
            key_tag: &str,
        ) -> Result<crate::callbacks::SecureEnclavePublicKey> {
            let n = self.next.fetch_add(1, Ordering::SeqCst);
            self.live_tags.lock().unwrap().insert(key_tag.to_string());
            Ok(crate::callbacks::SecureEnclavePublicKey {
                x: vec![n as u8; 32],
                y: vec![(n + 1) as u8; 32],
            })
        }

        async fn sign(&self, key_tag: &str, data: &[u8]) -> Result<Vec<u8>> {
            if !self.live_tags.lock().unwrap().contains(key_tag) {
                return Err(WscdError::KeyNotFound {
                    kid: key_tag.to_string(),
                });
            }
            // Not a real signature - just proves the right tag/data made it
            // through the plugin to the callback.
            let mut out = vec![0u8; 64];
            out[..data.len().min(64)].copy_from_slice(&data[..data.len().min(64)]);
            Ok(out)
        }

        async fn delete_key(&self, key_tag: &str) -> Result<()> {
            if !self.live_tags.lock().unwrap().remove(key_tag) {
                return Err(WscdError::KeyNotFound {
                    kid: key_tag.to_string(),
                });
            }
            Ok(())
        }
    }

    fn plugin() -> AppleSecureEnclavePlugin {
        AppleSecureEnclavePlugin::new(Box::new(FakeSecureEnclave::new()))
    }

    // Implemented for `Arc<FakeSecureEnclave>` too (alongside the plain
    // `FakeSecureEnclave` impl above) so a test can keep its own `Arc`
    // clone and directly manipulate `live_tags` AFTER handing a
    // `Box::new(enclave.clone())` to the plugin - needed to simulate a
    // Keychain item disappearing "out of band" (from the plugin's point of
    // view) without going through `AppleSecureEnclavePlugin::delete_key`.
    #[async_trait]
    impl SecureEnclaveCallback for std::sync::Arc<FakeSecureEnclave> {
        async fn generate_key(
            &self,
            key_tag: &str,
        ) -> Result<crate::callbacks::SecureEnclavePublicKey> {
            (**self).generate_key(key_tag).await
        }
        async fn sign(&self, key_tag: &str, data: &[u8]) -> Result<Vec<u8>> {
            (**self).sign(key_tag, data).await
        }
        async fn delete_key(&self, key_tag: &str) -> Result<()> {
            (**self).delete_key(key_tag).await
        }
    }

    #[tokio::test]
    async fn generates_a_key_and_reports_its_security_properties_honestly() {
        let plugin = plugin();
        let key = plugin
            .generate_key(Algorithm::ES256, &FakeAuth, &NoopProgress)
            .await
            .expect("generate_key should succeed");

        let props = plugin
            .security_properties(&key.kid)
            .expect("security_properties should find the key");
        assert_eq!(props.key_storage, KeyStorageType::Hardware);
        // The one property this whole plugin exists to get right: no
        // fabricated certification claim without a real attestation chain.
        assert_eq!(props.certification, CertificationLevel::None);

        let chain = plugin
            .attestation_chain(&key.kid)
            .await
            .expect("attestation_chain should not error");
        assert!(chain.is_none(), "staged release must not fabricate a chain");
    }

    #[tokio::test]
    async fn rejects_non_es256_algorithms() {
        let plugin = plugin();
        let err = plugin
            .generate_key(Algorithm::EdDSA, &FakeAuth, &NoopProgress)
            .await
            .expect_err("EdDSA has no Secure Enclave support");
        assert!(matches!(err, WscdError::Unsupported { .. }));

        let err = plugin
            .generate_key(Algorithm::Bls12381G1Schnorr, &FakeAuth, &NoopProgress)
            .await
            .expect_err("BLS12-381 has no Secure Enclave support");
        assert!(matches!(err, WscdError::Unsupported { .. }));
    }

    #[tokio::test]
    async fn sign_routes_the_right_tag_to_the_callback() {
        let plugin = plugin();
        let key = plugin
            .generate_key(Algorithm::ES256, &FakeAuth, &NoopProgress)
            .await
            .unwrap();

        let sig = plugin
            .sign(
                &key.kid,
                b"hello",
                Algorithm::ES256,
                &FakeAuth,
                &NoopProgress,
            )
            .await
            .expect("sign should succeed for a live key");
        assert_eq!(&sig.0[..5], b"hello");

        let unknown = KeyId("apple-se-does-not-exist".to_string());
        let err = plugin
            .sign(
                &unknown,
                b"hello",
                Algorithm::ES256,
                &FakeAuth,
                &NoopProgress,
            )
            .await
            .expect_err("signing an unknown kid must fail, not silently succeed");
        assert!(matches!(err, WscdError::KeyNotFound { .. }));
    }

    #[tokio::test]
    async fn delete_key_forgets_the_key_and_tells_the_enclave() {
        // A Copilot review finding on this PR: with the idempotent-delete
        // fix (treating the callback's `KeyNotFound` as "already deleted"),
        // checking only the plugin's OWN registry after a delete no longer
        // proves the real platform key is gone - a bug that passed the
        // wrong identifier (e.g. the `kid` instead of the real `key_tag`)
        // to `self.callback.delete_key` would get `KeyNotFound` back from
        // the fake enclave too (wrong identifier, not found), which the
        // idempotent-delete fix would now treat as success, removing the
        // registry entry anyway while the real tag stays alive underneath.
        // Keeping our own `Arc<FakeSecureEnclave>` handle lets this test
        // check the ACTUAL backend state directly, not just the plugin's
        // self-consistent view of it.
        let enclave = std::sync::Arc::new(FakeSecureEnclave::new());
        let plugin = AppleSecureEnclavePlugin::new(Box::new(enclave.clone()));
        let key = plugin
            .generate_key(Algorithm::ES256, &FakeAuth, &NoopProgress)
            .await
            .unwrap();
        let key_tag = plugin
            .lock_state()
            .keys
            .get(key.kid.as_str())
            .unwrap()
            .key_tag
            .clone();
        assert!(
            enclave.live_tags.lock().unwrap().contains(&key_tag),
            "sanity: the real tag must be live in the enclave before delete"
        );

        plugin
            .delete_key(&key.kid)
            .await
            .expect("delete should succeed once");

        assert!(
            !enclave.live_tags.lock().unwrap().contains(&key_tag),
            "the real enclave tag must be gone after a successful delete, \
             not just the plugin's own registry entry"
        );
        let err = plugin
            .export_public_key(&key.kid)
            .await
            .expect_err("key should be gone from the registry after delete");
        assert!(matches!(err, WscdError::KeyNotFound { .. }));
    }

    /// Copilot review finding on this PR: if the host's Keychain delete
    /// succeeds but the process stops before the caller persists this
    /// plugin's updated `export_container` snapshot, a restart restores a
    /// registry entry for a key the Keychain no longer has. Simulated here
    /// by removing the tag directly from the fake enclave (bypassing
    /// `plugin.delete_key` entirely) so the plugin's own registry still
    /// believes the key is live - exactly the state a restored-but-stale
    /// `export_container` snapshot would produce.
    #[tokio::test]
    async fn a_delete_whose_registry_update_never_persisted_is_not_stuck_forever() {
        let enclave = std::sync::Arc::new(FakeSecureEnclave::new());
        let plugin = AppleSecureEnclavePlugin::new(Box::new(enclave.clone()));
        let key = plugin
            .generate_key(Algorithm::ES256, &FakeAuth, &NoopProgress)
            .await
            .unwrap();

        // The host's Keychain item is already gone, but the plugin's
        // registry (as if just restored from a stale snapshot) still has
        // the entry. `lock_state()`/`StoredKey` are private to this module,
        // reachable here because `tests` is a child module of it.
        let key_tag = plugin
            .lock_state()
            .keys
            .get(key.kid.as_str())
            .unwrap()
            .key_tag
            .clone();
        enclave.delete_key(&key_tag).await.unwrap();

        // Without the fix, this would propagate the callback's KeyNotFound
        // and leave the entry stuck forever - every retry hitting the same
        // failure. With the fix, "already gone" is treated as "deleted".
        plugin
            .delete_key(&key.kid)
            .await
            .expect("a delete for an already-host-deleted key must succeed, not get stuck");
        let err = plugin
            .export_public_key(&key.kid)
            .await
            .expect_err("the stale registry entry must actually be gone now");
        assert!(matches!(err, WscdError::KeyNotFound { .. }));
    }

    #[tokio::test]
    async fn export_and_restore_container_round_trips_the_registry() {
        let plugin = plugin();
        let key = plugin
            .generate_key(Algorithm::ES256, &FakeAuth, &NoopProgress)
            .await
            .unwrap();
        let container = plugin.export_container().unwrap();

        // A fresh callback (simulating process restart) that already knows
        // about the tag the first plugin generated - mirrors how a real
        // Secure Enclave key tag survives process restart (it's in the
        // Keychain) even though this fake's live_tags map doesn't persist
        // on its own.
        let restored = AppleSecureEnclavePlugin::from_container(
            Box::new(FakeSecureEnclave::new()),
            &container,
        )
        .expect("restoring from an exported container should succeed");

        let jwk = restored
            .export_public_key(&key.kid)
            .await
            .expect("the restored plugin should still know this key's public JWK");
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
    }
}
