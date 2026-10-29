use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::callbacks::{AndroidKeystoreCallback, AuthCallback, ProgressCallback};
use crate::error::{Result, WscdError};
use crate::traits::WscdPlugin;
use crate::types::{
    Algorithm, AndroidKeystoreSecurityLevel, AttestationChain, AttestationFormat, AuthMethod,
    GeneratedKey, KeyId, KeyInfo, OperationProgress, SecurityProperties, Signature,
};

/// This plugin's fixed id — the one WIA's instance-key provisioning must
/// name directly via `WscdManager::get_plugin_by_id`/`generate_key_with_plugin`,
/// per this crate's existing "forced plugin" convention (see that method's
/// doc comment in `manager.rs`). Never routed through
/// `resolve_for_generate`/`WscdSelectionPolicy` for WIA.
pub const PLUGIN_ID: &str = "android-keystore";

/// Android Keystore WSCD plugin: EC P-256 keys that never leave the
/// device's TEE or StrongBox.
///
/// **One plugin instance, two callers** (mirrors how [`crate::plugins::fido2_sign::Fido2SignPlugin`]
/// already serves both roles — see that type's doc comment):
/// - WIA's instance-key provisioning calls `generate_key` directly via
///   `WscdManager::generate_key_with_plugin("android-keystore", ...)`
///   (never through `resolve_for_generate`/a selection policy — WIA's
///   hardware root is fixed, not chosen).
/// - KA/credential-issuance key generation reaches the SAME instance
///   through `WscdManager::generate_key_for_level`, which tries it (and
///   any other registered candidate plugin) and keeps the result only if
///   `security_properties()` afterward actually meets the credential
///   type's required tier — see that method's doc comment for the
///   generate → confirm → delete-and-retry-next-candidate pattern.
///
/// Key generation is **always best-effort** (StrongBox first, the TEE if
/// this device has none, never refused on the hardware level alone) —
/// this is what both callers above need: WIA's instance key must be
/// provisionable on every Android device, and KA's required-tier
/// enforcement lives one layer up, in `generate_key_for_level`'s
/// confirm-or-retry-the-next-candidate-plugin loop, not inside this
/// plugin. A future phase that wants an explicit "StrongBox or refuse"
/// policy *within* this one plugin (mirroring `AndroidKeystoreSigner.createKey`'s
/// own hardware-requirement refusal) is a deliberate non-goal of this PR —
/// see this crate's PR description for why duplicating that decision tree
/// in Rust was deferred rather than silently chosen.
///
/// Every key is generated with Android Key Attestation (a fresh random
/// 32-byte challenge per key, exactly like [`crate::plugins::fido2_sign::Fido2SignPlugin`]'s
/// own random `client_data_hash` per key) — there is no "unattested" path,
/// since both WIA and KA always want the attestation chain.
pub struct AndroidKeystorePlugin {
    callback: Box<dyn AndroidKeystoreCallback>,
    state: Mutex<PluginState>,
}

#[derive(Default)]
struct PluginState {
    keys: HashMap<String, StoredAndroidKey>,
}

/// Wire shape for [`AndroidKeystorePlugin::export_state`]/[`AndroidKeystorePlugin::from_state`] —
/// same "persist what generate_key already learned, never re-query the
/// device to restore" shape as previewSign's `ExportedPluginState`: this
/// plugin's `security_properties()` is synchronous (the `WscdPlugin` trait
/// requires it), so it can only ever report what was captured at
/// generation time, not a live Keystore query.
#[derive(Serialize, Deserialize)]
struct ExportedPluginState {
    keys: Vec<StoredAndroidKey>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredAndroidKey {
    /// RFC 7638 JWK thumbprint — see `crate::plugins::jwk_thumbprint`'s doc
    /// comment for why every plugin in this crate keys its store this way.
    kid: String,
    /// The real Android Keystore alias this key is held under — an
    /// internal identifier never exposed outside this plugin (the `kid`
    /// above is what the rest of the stack, and the host app, sees).
    alias: String,
    public_key_jwk: serde_json::Value,
    /// DER chain, leaf first, from `AndroidKeystoreCallback::certificate_chain`
    /// at generation time.
    certificates: Vec<Vec<u8>>,
    /// The random attestation challenge this key was generated with — see
    /// `AttestationChain::client_data_hash`'s doc comment for why it must
    /// travel with the chain.
    client_data_hash: Vec<u8>,
    /// Where `AndroidKeystoreCallback::generate` confirmed this key landed.
    security_level: AndroidKeystoreSecurityLevel,
    /// Per-use authentication methods this key was created with (always
    /// empty today — see this type's class doc comment on why this plugin
    /// only ever does best-effort generation — kept as a field so a future
    /// `createKey`-style policy path has somewhere to record it without a
    /// wire-shape change).
    user_authentication_methods: Vec<String>,
    created_at: i64,
}

impl AndroidKeystorePlugin {
    pub fn new(callback: Box<dyn AndroidKeystoreCallback>) -> Self {
        Self {
            callback,
            state: Mutex::new(PluginState::default()),
        }
    }

    /// Restore from a previously [`Self::export_state`]-exported blob — the
    /// kid→alias mapping, attestation chains and confirmed security levels
    /// this plugin learned at generation time. No private key material
    /// (that never leaves the Keystore); like previewSign's restore, the
    /// host app must still protect this blob (the aliases are meaningful
    /// identifiers, and the attestation chains are PII-adjacent device
    /// identity evidence).
    pub fn from_state(
        callback: Box<dyn AndroidKeystoreCallback>,
        state_bytes: &[u8],
    ) -> Result<Self> {
        let exported: ExportedPluginState = serde_json::from_slice(state_bytes)
            .map_err(|e| WscdError::Serialization(e.to_string()))?;
        let mut keys = HashMap::with_capacity(exported.keys.len());
        for k in exported.keys {
            keys.entry(k.kid.clone()).or_insert(k);
        }
        Ok(Self {
            callback,
            state: Mutex::new(PluginState { keys }),
        })
    }

    /// Export this plugin's key state for the host app to persist and
    /// later restore via [`Self::from_state`]. Without this, every key
    /// becomes unreachable after a process restart — see
    /// `WscdManager::bind_keys`'s doc comment.
    pub fn export_state(&self) -> Result<Vec<u8>> {
        let state = self.lock_state();
        let mut keys: Vec<StoredAndroidKey> = state.keys.values().cloned().collect();
        // Deterministic wire order, like previewSign's export_state.
        keys.sort_by(|a, b| (a.created_at, &a.kid).cmp(&(b.created_at, &b.kid)));
        serde_json::to_vec(&ExportedPluginState { keys })
            .map_err(|e| WscdError::Serialization(e.to_string()))
    }

    /// Ids of the keys this plugin holds, for `WscdManager::bind_keys` after
    /// a restore — synchronous, unlike `WscdPlugin::list_keys`.
    pub fn key_ids(&self) -> Vec<KeyId> {
        let state = self.lock_state();
        state.keys.keys().map(|k| KeyId(k.clone())).collect()
    }

    /// Lock `state`, recovering from poison instead of propagating it —
    /// same rationale as `Fido2SignPlugin::lock_state`: a panic elsewhere
    /// while this lock is held must not permanently brick every later call.
    fn lock_state(&self) -> std::sync::MutexGuard<'_, PluginState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn find_key<'a>(state: &'a PluginState, kid: &KeyId) -> Result<&'a StoredAndroidKey> {
        state
            .keys
            .get(kid.as_str())
            .ok_or_else(|| WscdError::KeyNotFound {
                kid: kid.to_string(),
            })
    }

    fn now_unix() -> i64 {
        crate::timeutil::now_unix()
    }

    /// A fresh, unpredictable Android Keystore alias — never the `kid` a
    /// caller sees (that is the key's own JWK thumbprint, computed only
    /// once the public key is known back from `generate`). 16 random
    /// bytes, base64url-encoded, under a fixed prefix so a human scanning
    /// `keytool -list`-style Keystore output can tell these apart from
    /// aliases some other code on the device minted.
    fn new_alias() -> String {
        let mut buf = [0u8; 16];
        rand::fill(&mut buf);
        format!(
            "org.siros.wscd.android-keystore.{}",
            Base64UrlUnpadded::encode_string(&buf)
        )
    }

    /// StrongBox first, the TEE if this device has none — never refused on
    /// the hardware level alone. Mirrors `AndroidKeystoreSigner.bestEffort()`
    /// (siros-sdk-kotlin) exactly, including `unlocked_device_required:
    /// false` (this plugin's keys are never gated on the phone being
    /// unlocked) and no per-use user-authentication methods.
    async fn best_effort_generate(
        &self,
        attestation_challenge: &[u8],
    ) -> Result<(String, AndroidKeystoreSecurityLevel)> {
        let alias = Self::new_alias();
        match self
            .callback
            .generate(&alias, Some(attestation_challenge), true, &[], false)
            .await
        {
            Ok(level) => Ok((alias, level)),
            Err(WscdError::StrongBoxUnavailable) => {
                // A half-made StrongBox key must not be reused - a fresh
                // alias, like the Kotlin original. The real
                // AndroidKeyStoreBackend.generate does not guarantee it
                // persists nothing before throwing this specific error, so
                // the cleanup attempt below is unconditional, not optional -
                // and if IT fails too, that must stop everything (see
                // `delete_after_failed_generate`'s doc comment), not be
                // swallowed in favor of trying the TEE anyway.
                if let Err(delete_err) = self.callback.delete(&alias).await {
                    return Err(WscdError::UnconfirmedCleanup {
                        plugin: PLUGIN_ID.to_string(),
                        reason: format!(
                            "StrongBox unavailable, and cleanup of the attempted alias also failed ({delete_err})"
                        ),
                    });
                }
                let tee_alias = Self::new_alias();
                match self
                    .callback
                    .generate(&tee_alias, Some(attestation_challenge), false, &[], false)
                    .await
                {
                    Ok(level) => Ok((tee_alias, level)),
                    Err(e) => Err(Self::delete_after_failed_generate(
                        self.callback.as_ref(),
                        &tee_alias,
                        e,
                    )
                    .await),
                }
            }
            Err(e) => {
                Err(Self::delete_after_failed_generate(self.callback.as_ref(), &alias, e).await)
            }
        }
    }

    /// On any failure after calling `generate` for `alias` - whether
    /// `generate` itself failed, or it succeeded and a LATER step (fetching
    /// the certificate chain/public key, deriving the kid) failed -
    /// best-effort delete whatever might have been left behind under
    /// `alias`. `AndroidKeystoreCallback::delete` is documented as a no-op
    /// for an alias that was never created, so this is always safe to
    /// attempt, even when `original_err` gives no reason to suspect
    /// anything was actually persisted (the real `AndroidKeyStoreBackend`
    /// does not guarantee atomicity between "key persisted" and "generate
    /// returned success"). Returns `original_err` unchanged if the cleanup
    /// succeeded (or had nothing to clean up), or
    /// [`WscdError::UnconfirmedCleanup`] (combining both messages) if the
    /// cleanup attempt itself also failed - see that variant's doc comment
    /// for why callers must treat it as a stop signal, not a reason to
    /// retry.
    async fn delete_after_failed_generate(
        callback: &dyn AndroidKeystoreCallback,
        alias: &str,
        original_err: WscdError,
    ) -> WscdError {
        match callback.delete(alias).await {
            Ok(()) => original_err,
            Err(delete_err) => WscdError::UnconfirmedCleanup {
                plugin: PLUGIN_ID.to_string(),
                reason: format!("{original_err}, and cleanup also failed ({delete_err})"),
            },
        }
    }

    /// Like the `WscdPlugin::generate_key` trait method, but with a
    /// caller-supplied attestation challenge instead of a random one.
    ///
    /// Wallet Instance Attestation's instance-key provisioning needs this:
    /// per siros-sdk-kotlin #312's `InstanceKeyEvidence`, the Android Key
    /// Attestation challenge for a WIA instance key MUST be
    /// `SHA-256("siros-instance-key-v1" || C)`, where `C` is the
    /// server-issued challenge exactly as issued (base64url, not decoded).
    /// A random challenge this plugin invents itself cannot satisfy that
    /// contract - the backend verifies the attestation against the exact
    /// formula, so a key attested under any other challenge is simply
    /// unverifiable. `generate_key` (the trait method, which the `KA`
    /// pluggable path uses via `generate_key_for_level` and which cannot
    /// take extra parameters - the trait is shared across every plugin)
    /// keeps generating a random challenge, since KA has no such external
    /// contract to satisfy; it now delegates here.
    pub async fn generate_key_with_challenge(
        &self,
        algorithm: Algorithm,
        attestation_challenge: &[u8],
        progress: &dyn ProgressCallback,
    ) -> Result<GeneratedKey> {
        if algorithm != Algorithm::ES256 {
            return Err(WscdError::Unsupported {
                plugin: PLUGIN_ID.to_string(),
                op: format!("generate_key({algorithm})"),
            });
        }
        if attestation_challenge.is_empty() {
            return Err(WscdError::Plugin(
                "attestation challenge must not be empty".to_string(),
            ));
        }
        progress
            .on_progress(OperationProgress::Started {
                operation: "generate_key".to_string(),
            })
            .await;

        let (alias, security_level) = self.best_effort_generate(attestation_challenge).await?;

        // From here on a real hardware key exists under `alias`. Any
        // failure below must delete it before returning - this plugin only
        // records a key in `state.keys` once every step below succeeds, so
        // an undeleted key here would be invisible to `list_keys`/exported
        // state and unreachable by any later `delete_key` call, accumulating
        // silently on every retry.
        match self
            .finish_generate_key(&alias, security_level, attestation_challenge)
            .await
        {
            Ok(result) => {
                progress.on_progress(OperationProgress::Complete).await;
                Ok(result)
            }
            Err(e) => {
                Err(Self::delete_after_failed_generate(self.callback.as_ref(), &alias, e).await)
            }
        }
    }

    /// The part of key generation after a real hardware key exists under
    /// `alias`: fetch its attestation chain and public key, derive the
    /// `kid`, and record it. Split out of [`Self::generate_key_with_challenge`]
    /// so that caller can delete `alias` on any error this returns, without
    /// duplicating that cleanup at each of the three fallible steps here.
    async fn finish_generate_key(
        &self,
        alias: &str,
        security_level: AndroidKeystoreSecurityLevel,
        attestation_challenge: &[u8],
    ) -> Result<GeneratedKey> {
        let certificates = self.callback.certificate_chain(alias).await?;
        let public_key_jwk = self.callback.public_key_jwk(alias).await?;
        let kid = crate::plugins::jwk_thumbprint(&public_key_jwk)?;

        let stored = StoredAndroidKey {
            kid: kid.clone(),
            alias: alias.to_string(),
            public_key_jwk: public_key_jwk.clone(),
            certificates,
            client_data_hash: attestation_challenge.to_vec(),
            security_level,
            user_authentication_methods: Vec::new(),
            created_at: Self::now_unix(),
        };
        {
            let mut state = self.lock_state();
            state.keys.insert(kid.clone(), stored);
        }

        Ok(GeneratedKey {
            kid: KeyId(kid),
            public_key_jwk,
        })
    }

    /// The TS12 `amr` entries for a key at `level` — `hwk`+`pop` for a real
    /// hardware-backed key (StrongBox/TEE), `swk` for a software one,
    /// matching this crate's existing convention (`Fido2SignPlugin`,
    /// `SoftkeyPlugin`). Never claims a hardware factor for a level this
    /// plugin couldn't actually confirm.
    fn amr_for(level: AndroidKeystoreSecurityLevel) -> Vec<String> {
        match level {
            AndroidKeystoreSecurityLevel::StrongBox
            | AndroidKeystoreSecurityLevel::TrustedExecution => {
                vec!["hwk".to_string(), "pop".to_string()]
            }
            AndroidKeystoreSecurityLevel::Software | AndroidKeystoreSecurityLevel::Unknown => {
                vec!["swk".to_string()]
            }
        }
    }
}

#[async_trait]
impl WscdPlugin for AndroidKeystorePlugin {
    fn id(&self) -> &str {
        PLUGIN_ID
    }

    fn display_name(&self) -> &str {
        "Android Keystore"
    }

    fn auth_method(&self) -> AuthMethod {
        // Per-use biometric/device-credential authentication, when a key
        // needs it, is handled entirely inside the host's `sign` callback
        // implementation (see `AndroidKeystoreCallback`'s doc comment) -
        // this plugin never itself drives a PIN or WebAuthn ceremony.
        AuthMethod::None
    }

    async fn generate_key(
        &self,
        algorithm: Algorithm,
        _auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<GeneratedKey> {
        // No external contract on this challenge (unlike WIA's forced path,
        // see `Self::generate_key_with_challenge`'s doc comment) - a fresh
        // random one per key, exactly like `Fido2SignPlugin`'s own random
        // `client_data_hash`.
        let mut challenge = [0u8; 32];
        rand::fill(&mut challenge);
        self.generate_key_with_challenge(algorithm, &challenge, progress)
            .await
    }

    async fn sign(
        &self,
        kid: &KeyId,
        data: &[u8],
        _algorithm: Algorithm,
        _auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<Signature> {
        let alias = {
            let state = self.lock_state();
            Self::find_key(&state, kid)?.alias.clone()
        };
        progress
            .on_progress(OperationProgress::Started {
                operation: "sign".to_string(),
            })
            .await;
        let sig = self.callback.sign(&alias, data).await?;
        progress.on_progress(OperationProgress::Complete).await;
        Ok(Signature(sig))
    }

    async fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        let state = self.lock_state();
        Ok(state
            .keys
            .values()
            .map(|k| KeyInfo {
                kid: KeyId(k.kid.clone()),
                algorithm: Algorithm::ES256,
                plugin_id: PLUGIN_ID.to_string(),
                created_at: k.created_at,
            })
            .collect())
    }

    async fn attestation_chain(&self, kid: &KeyId) -> Result<Option<AttestationChain>> {
        let state = self.lock_state();
        let key = Self::find_key(&state, kid)?;
        // Mirrors `AndroidKeystoreSigner.attestationChain`: fewer than two
        // certificates means Android Key Attestation was not actually
        // available when the key was made (a bare self-signed leaf, no real
        // chain to a root) - report "no attestation" rather than a
        // one-element chain nothing can verify.
        if key.certificates.len() < 2 {
            return Ok(None);
        }
        Ok(Some(AttestationChain {
            format: AttestationFormat::X509Chain,
            certificates: key.certificates.clone(),
            client_data_hash: key.client_data_hash.clone(),
            opaque_attestation: Vec::new(),
        }))
    }

    async fn delete_key(&self, kid: &KeyId) -> Result<()> {
        // Look up without removing, delete via the callback FIRST, and only
        // then remove the record. The reverse order - removing the record
        // before the fallible callback delete - would, on a callback
        // failure, leave the real hardware key alive but its kid→alias
        // mapping gone: a retry would see `KeyNotFound` (nothing left to
        // retry), and exported state would permanently lose the alias
        // needed to ever clean it up.
        let alias = {
            let state = self.lock_state();
            Self::find_key(&state, kid)?.alias.clone()
        };
        self.callback.delete(&alias).await?;
        let mut state = self.lock_state();
        state.keys.remove(kid.as_str());
        Ok(())
    }

    async fn export_public_key(&self, kid: &KeyId) -> Result<serde_json::Value> {
        let state = self.lock_state();
        Ok(Self::find_key(&state, kid)?.public_key_jwk.clone())
    }

    fn security_properties(&self, kid: &KeyId) -> Result<SecurityProperties> {
        let state = self.lock_state();
        let key = Self::find_key(&state, kid)?;
        Ok(SecurityProperties {
            key_storage: key.security_level.as_key_storage_type(),
            user_authentication: key.user_authentication_methods.clone(),
            certification: key.security_level.as_certification_level(),
            amr: Self::amr_for(key.security_level),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callbacks::NoopProgress;
    use crate::types::Secret;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;

    struct NoAuth;
    #[async_trait]
    impl AuthCallback for NoAuth {
        async fn request_pin(&self, _: &str) -> Result<Secret> {
            unreachable!()
        }
        async fn request_webauthn_assertion(
            &self,
            _: &str,
            _: &[u8],
            _: &str,
            _: &[Vec<u8>],
        ) -> Result<Vec<u8>> {
            unreachable!()
        }
    }

    /// An in-memory fake of [`AndroidKeystoreCallback`], parameterized by
    /// whether StrongBox is "available" on this fake device - lets the
    /// best-effort StrongBox→TEE fallback be exercised without any real
    /// Android Keystore.
    struct FakeCallback {
        strongbox_available: bool,
        strongbox_attempts: AtomicUsize,
        keys: StdMutex<HashMap<String, FakeKey>>,
        /// When true, `delete` always fails - for proving a cleanup-failure
        /// path actually surfaces rather than being swallowed.
        delete_fails: std::sync::atomic::AtomicBool,
        /// Succeed the first N `delete` calls, then fail every one after -
        /// for a test that needs the FIRST cleanup (StrongBox-unavailable)
        /// to succeed but a LATER one (the TEE retry's own failure) to fail.
        delete_fails_after_call: AtomicUsize,
        delete_calls: AtomicUsize,
        /// When true, `public_key_jwk` always fails - stands in for ANY
        /// post-generation metadata failure (certificate_chain,
        /// public_key_jwk, or jwk_thumbprint all get the same treatment in
        /// `finish_generate_key`).
        public_key_jwk_fails: std::sync::atomic::AtomicBool,
        /// When true, a non-StrongBox (TEE) `generate` call always fails -
        /// for proving the best-effort TEE retry's own cleanup path.
        tee_generate_fails: std::sync::atomic::AtomicBool,
    }

    struct FakeKey {
        level: AndroidKeystoreSecurityLevel,
        jwk: serde_json::Value,
    }

    impl FakeCallback {
        fn new(strongbox_available: bool) -> Self {
            Self {
                strongbox_available,
                strongbox_attempts: AtomicUsize::new(0),
                keys: StdMutex::new(HashMap::new()),
                delete_fails: std::sync::atomic::AtomicBool::new(false),
                delete_fails_after_call: AtomicUsize::new(usize::MAX),
                delete_calls: AtomicUsize::new(0),
                public_key_jwk_fails: std::sync::atomic::AtomicBool::new(false),
                tee_generate_fails: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl AndroidKeystoreCallback for FakeCallback {
        async fn generate(
            &self,
            alias: &str,
            _attestation_challenge: Option<&[u8]>,
            strong_box: bool,
            _user_authentication_methods: &[String],
            _unlocked_device_required: bool,
        ) -> Result<AndroidKeystoreSecurityLevel> {
            if strong_box {
                self.strongbox_attempts.fetch_add(1, Ordering::SeqCst);
                if !self.strongbox_available {
                    return Err(WscdError::StrongBoxUnavailable);
                }
            } else if self.tee_generate_fails.load(Ordering::SeqCst) {
                return Err(WscdError::Plugin("TEE generate failed (fake)".to_string()));
            }
            let level = if strong_box {
                AndroidKeystoreSecurityLevel::StrongBox
            } else {
                AndroidKeystoreSecurityLevel::TrustedExecution
            };
            // A distinct-enough fake EC JWK per alias so two generated keys
            // never collide on kid (the thumbprint is over x/y).
            let jwk = serde_json::json!({
                "kty": "EC", "crv": "P-256",
                "x": Base64UrlUnpadded::encode_string(alias.as_bytes()),
                "y": Base64UrlUnpadded::encode_string(&[7u8; 32]),
            });
            self.keys
                .lock()
                .unwrap()
                .insert(alias.to_string(), FakeKey { level, jwk });
            Ok(level)
        }

        async fn certificate_chain(&self, _alias: &str) -> Result<Vec<Vec<u8>>> {
            Ok(vec![vec![1, 2, 3], vec![4, 5, 6]])
        }

        async fn public_key_jwk(&self, alias: &str) -> Result<serde_json::Value> {
            if self.public_key_jwk_fails.load(Ordering::SeqCst) {
                return Err(WscdError::Plugin(
                    "public_key_jwk failed (fake)".to_string(),
                ));
            }
            Ok(self.keys.lock().unwrap().get(alias).unwrap().jwk.clone())
        }

        async fn security_level(&self, alias: &str) -> Result<AndroidKeystoreSecurityLevel> {
            Ok(self.keys.lock().unwrap().get(alias).unwrap().level)
        }

        async fn user_authentication_methods(&self, _alias: &str) -> Result<Vec<String>> {
            Ok(vec![])
        }

        async fn sign(&self, _alias: &str, data: &[u8]) -> Result<Vec<u8>> {
            Ok(data.to_vec())
        }

        async fn aliases(&self) -> Result<Vec<String>> {
            Ok(self.keys.lock().unwrap().keys().cloned().collect())
        }

        async fn delete(&self, alias: &str) -> Result<()> {
            let call_index = self.delete_calls.fetch_add(1, Ordering::SeqCst);
            if self.delete_fails.load(Ordering::SeqCst)
                || call_index >= self.delete_fails_after_call.load(Ordering::SeqCst)
            {
                return Err(WscdError::Plugin("delete failed (fake)".to_string()));
            }
            self.keys.lock().unwrap().remove(alias);
            Ok(())
        }
    }

    /// With StrongBox available, generate_key lands the key there on the
    /// first attempt - no fallback, and `security_properties` reports it.
    #[tokio::test]
    async fn generate_key_uses_strongbox_when_available() {
        let plugin = AndroidKeystorePlugin::new(Box::new(FakeCallback::new(true)));
        let key = plugin
            .generate_key(Algorithm::ES256, &NoAuth, &NoopProgress)
            .await
            .unwrap();
        let props = plugin.security_properties(&key.kid).unwrap();
        assert_eq!(props.key_storage, crate::types::KeyStorageType::Hardware);
    }

    /// With no StrongBox, generate_key still succeeds (best-effort - WIA's
    /// instance-key provisioning must never fail here) by falling back to
    /// the TEE on a fresh alias, and reports that honestly rather than
    /// claiming StrongBox.
    ///
    /// Confirmed non-vacuous: without the `Err(WscdError::StrongBoxUnavailable)`
    /// fallback arm in `best_effort_generate` (reverted to `Err(e) => Err(e)`
    /// unconditionally), this test fails with `StrongBoxUnavailable`
    /// propagated instead of a generated key - checked, then restored.
    #[tokio::test]
    async fn generate_key_falls_back_to_tee_when_strongbox_unavailable() {
        let callback = FakeCallback::new(false);
        let plugin = AndroidKeystorePlugin::new(Box::new(callback));
        let key = plugin
            .generate_key(Algorithm::ES256, &NoAuth, &NoopProgress)
            .await
            .expect("best-effort generation must never refuse");
        let props = plugin.security_properties(&key.kid).unwrap();
        assert_eq!(
            props.key_storage,
            crate::types::KeyStorageType::TrustedExecution
        );
    }

    /// `attestation_chain` round-trips the certificate chain and the exact
    /// challenge bytes `generate_key` used - required to verify the chain's
    /// attestation signature later.
    #[tokio::test]
    async fn attestation_chain_carries_the_generation_challenge() {
        let plugin = AndroidKeystorePlugin::new(Box::new(FakeCallback::new(true)));
        let key = plugin
            .generate_key(Algorithm::ES256, &NoAuth, &NoopProgress)
            .await
            .unwrap();
        let chain = plugin
            .attestation_chain(&key.kid)
            .await
            .unwrap()
            .expect("two fake certificates were returned");
        assert_eq!(chain.format, AttestationFormat::X509Chain);
        assert_eq!(chain.certificates.len(), 2);
        assert_eq!(chain.client_data_hash.len(), 32);
    }

    /// Exported/restored state keeps `security_properties`/`sign` working
    /// without any further callback I/O beyond what `sign` itself needs -
    /// a restored plugin instance must not need to re-query the device for
    /// facts `generate_key` already learned.
    #[tokio::test]
    async fn export_and_restore_round_trips_security_properties() {
        let plugin = AndroidKeystorePlugin::new(Box::new(FakeCallback::new(true)));
        let key = plugin
            .generate_key(Algorithm::ES256, &NoAuth, &NoopProgress)
            .await
            .unwrap();
        let exported = plugin.export_state().unwrap();

        let restored =
            AndroidKeystorePlugin::from_state(Box::new(FakeCallback::new(true)), &exported)
                .unwrap();
        let props = restored.security_properties(&key.kid).unwrap();
        assert_eq!(props.key_storage, crate::types::KeyStorageType::Hardware);
        assert_eq!(restored.key_ids(), vec![key.kid]);
    }

    /// `delete_key` removes the plugin's own record AND asks the callback
    /// to delete the underlying alias - deleting only one side would either
    /// leak the Keystore entry (if only the record is dropped) or make a
    /// later `sign` on a still-tracked kid fail confusingly (if only the
    /// alias is dropped).
    #[tokio::test]
    async fn delete_key_removes_both_the_record_and_the_alias() {
        let callback = std::sync::Arc::new(FakeCallback::new(true));
        let plugin = AndroidKeystorePlugin::new(Box::new(ArcCallback(callback.clone())));
        let key = plugin
            .generate_key(Algorithm::ES256, &NoAuth, &NoopProgress)
            .await
            .unwrap();
        assert_eq!(callback.aliases().await.unwrap().len(), 1);

        plugin.delete_key(&key.kid).await.unwrap();

        assert!(callback.aliases().await.unwrap().is_empty());
        assert!(plugin.security_properties(&key.kid).is_err());
    }

    /// `delete_key` must call the callback's `delete` BEFORE removing its
    /// own record: if the callback fails, the record must survive (so a
    /// retry - or a later `delete_key` call - can still find the alias and
    /// try again), not be dropped first and leave the real key orphaned.
    ///
    /// Confirmed non-vacuous: with the order reversed (record removed
    /// before the callback call, this plugin's original shape), this test
    /// fails because `security_properties` can no longer find the key after
    /// the failed delete - checked, then restored.
    #[tokio::test]
    async fn delete_key_keeps_its_record_when_the_callback_delete_fails() {
        let callback = std::sync::Arc::new(FakeCallback::new(true));
        let plugin = AndroidKeystorePlugin::new(Box::new(ArcCallback(callback.clone())));
        let key = plugin
            .generate_key(Algorithm::ES256, &NoAuth, &NoopProgress)
            .await
            .unwrap();

        callback.delete_fails.store(true, Ordering::SeqCst);
        let err = plugin
            .delete_key(&key.kid)
            .await
            .expect_err("the callback's delete failure must propagate");
        assert!(err.to_string().contains("delete failed"), "{err}");

        assert!(
            plugin.security_properties(&key.kid).is_ok(),
            "the record must survive a failed callback delete, not be removed anyway"
        );
    }

    /// A StrongBox-unavailable fallback that also fails to delete the
    /// half-made StrongBox alias must propagate that failure, not silently
    /// retry in the TEE anyway - a stale StrongBox alias this plugin never
    /// recorded would otherwise leak forever (unreachable by `delete_key`,
    /// invisible to `list_keys`/exported state).
    ///
    /// Confirmed non-vacuous: with the delete error swallowed
    /// (`let _ = self.callback.delete(&alias).await;`, this plugin's
    /// original shape), this test fails because generation succeeds in the
    /// TEE instead of surfacing the cleanup failure - checked, then
    /// restored.
    #[tokio::test]
    async fn strongbox_cleanup_failure_is_surfaced_not_swallowed() {
        let callback = FakeCallback::new(false); // no StrongBox on this fake device
        callback.delete_fails.store(true, Ordering::SeqCst);
        let plugin = AndroidKeystorePlugin::new(Box::new(callback));

        let err = plugin
            .generate_key(Algorithm::ES256, &NoAuth, &NoopProgress)
            .await
            .expect_err("a failed cleanup of the half-made StrongBox key must propagate");
        assert!(err.to_string().contains("delete"), "{err}");
    }

    /// A post-generation metadata failure (certificate_chain,
    /// public_key_jwk, or - as here - the jwk_thumbprint derived from it)
    /// must delete the already-created hardware key before returning,
    /// rather than leaking it: this plugin only records a key once every
    /// step succeeds, so an undeleted key here would be invisible to
    /// `list_keys`/exported state and unreachable by any later
    /// `delete_key` call, accumulating silently on every retry.
    ///
    /// Confirmed non-vacuous: without the cleanup call in
    /// `generate_key_with_challenge`'s error path (returning the metadata
    /// error directly via `?`), this test fails because the orphaned alias
    /// is still present in the fake Keystore afterward - checked, then
    /// restored.
    #[tokio::test]
    async fn post_generation_metadata_failure_deletes_the_orphaned_key() {
        let callback = std::sync::Arc::new(FakeCallback::new(true));
        callback.public_key_jwk_fails.store(true, Ordering::SeqCst);
        let plugin = AndroidKeystorePlugin::new(Box::new(ArcCallback(callback.clone())));

        let err = plugin
            .generate_key(Algorithm::ES256, &NoAuth, &NoopProgress)
            .await
            .expect_err("a metadata failure after generation must propagate");
        assert!(err.to_string().contains("public_key_jwk"), "{err}");

        assert!(
            callback.aliases().await.unwrap().is_empty(),
            "the orphaned alias must be deleted, not left behind in the Keystore"
        );
    }

    /// If the TEE retry (after a StrongBox-unavailable fallback) itself
    /// fails, and cleaning up ITS attempted alias also fails, the result
    /// must be the typed `UnconfirmedCleanup` error - not the TEE's bare
    /// generation error, and not a success. This is a path that previously
    /// did zero cleanup at all (a bare `?` on the TEE attempt).
    ///
    /// Confirmed non-vacuous: with `delete_after_failed_generate`'s call on
    /// the TEE-retry branch replaced by a bare `?` (this plugin's original
    /// shape), this test fails because the returned error is the plain TEE
    /// generation error, not `UnconfirmedCleanup` - checked, then restored.
    #[tokio::test]
    async fn tee_retry_failure_with_failed_cleanup_is_unconfirmed_cleanup() {
        let callback = FakeCallback::new(false); // no StrongBox
        callback.tee_generate_fails.store(true, Ordering::SeqCst);
        // The FIRST delete (StrongBox-unavailable cleanup) must succeed, or
        // this test would never even reach the TEE retry; only the SECOND
        // (the TEE retry's own cleanup) fails.
        callback.delete_fails_after_call.store(1, Ordering::SeqCst);
        let plugin = AndroidKeystorePlugin::new(Box::new(callback));

        let err = plugin
            .generate_key(Algorithm::ES256, &NoAuth, &NoopProgress)
            .await
            .expect_err("a failed TEE retry with failed cleanup must propagate");
        assert!(
            matches!(err, WscdError::UnconfirmedCleanup { .. }),
            "expected UnconfirmedCleanup, got {err}"
        );
    }

    /// WIA's forced path needs a caller-supplied attestation challenge
    /// (per siros-sdk-kotlin #312's fixed SHA-256("siros-instance-key-v1" ||
    /// C) formula) - `generate_key_with_challenge` must use EXACTLY the
    /// bytes it is given, never substitute a random one.
    #[tokio::test]
    async fn generate_key_with_challenge_uses_the_exact_caller_supplied_bytes() {
        let plugin = AndroidKeystorePlugin::new(Box::new(FakeCallback::new(true)));
        let challenge = vec![0xAAu8; 32];

        let key = plugin
            .generate_key_with_challenge(Algorithm::ES256, &challenge, &NoopProgress)
            .await
            .unwrap();

        let chain = plugin
            .attestation_chain(&key.kid)
            .await
            .unwrap()
            .expect("two fake certificates were returned");
        assert_eq!(chain.client_data_hash, challenge);
    }

    /// An empty attestation challenge is refused up front, never silently
    /// sent to the Keystore as a zero-length (effectively unattested)
    /// request.
    #[tokio::test]
    async fn generate_key_with_challenge_refuses_an_empty_challenge() {
        let plugin = AndroidKeystorePlugin::new(Box::new(FakeCallback::new(true)));
        let err = plugin
            .generate_key_with_challenge(Algorithm::ES256, &[], &NoopProgress)
            .await
            .expect_err("an empty challenge must be refused");
        assert!(err.to_string().contains("empty"), "{err}");
    }

    /// Thin `Arc` forwarder so a test can keep its own handle to a
    /// [`FakeCallback`] (to assert on its state) while also handing the
    /// plugin a `Box<dyn AndroidKeystoreCallback>` it owns.
    struct ArcCallback(std::sync::Arc<FakeCallback>);
    #[async_trait]
    impl AndroidKeystoreCallback for ArcCallback {
        async fn generate(
            &self,
            alias: &str,
            attestation_challenge: Option<&[u8]>,
            strong_box: bool,
            user_authentication_methods: &[String],
            unlocked_device_required: bool,
        ) -> Result<AndroidKeystoreSecurityLevel> {
            self.0
                .generate(
                    alias,
                    attestation_challenge,
                    strong_box,
                    user_authentication_methods,
                    unlocked_device_required,
                )
                .await
        }
        async fn certificate_chain(&self, alias: &str) -> Result<Vec<Vec<u8>>> {
            self.0.certificate_chain(alias).await
        }
        async fn public_key_jwk(&self, alias: &str) -> Result<serde_json::Value> {
            self.0.public_key_jwk(alias).await
        }
        async fn security_level(&self, alias: &str) -> Result<AndroidKeystoreSecurityLevel> {
            self.0.security_level(alias).await
        }
        async fn user_authentication_methods(&self, alias: &str) -> Result<Vec<String>> {
            self.0.user_authentication_methods(alias).await
        }
        async fn sign(&self, alias: &str, data: &[u8]) -> Result<Vec<u8>> {
            self.0.sign(alias, data).await
        }
        async fn aliases(&self) -> Result<Vec<String>> {
            self.0.aliases().await
        }
        async fn delete(&self, alias: &str) -> Result<()> {
            self.0.delete(alias).await
        }
    }
}
