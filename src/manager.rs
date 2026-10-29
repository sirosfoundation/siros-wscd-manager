use std::collections::HashMap;
use std::sync::Arc;

use crate::callbacks::{AuthCallback, NoopProgress, ProgressCallback};
use crate::config::WscdConfig;
use crate::error::{Result, WscdError};
use crate::factors::{FactorCapability, SignOptions, SignOutcome};
use crate::traits::WscdPlugin;
use crate::types::{
    ActivateLifecycleRequest, ActivationOutcome, Algorithm, AttestationChain, CertificationLevel,
    DestroyLifecycleRequest, DestructionOutcome, GeneratedKey, KeyId, KeyInfo, LifecycleStatus,
    MigrationResult, RegisterLifecycleRequest, RegistrationOutcome, RotateLifecycleRequest,
    RotationOutcome, SecurityProperties, Signature,
};

/// Central manager that routes key operations to the appropriate plugin.
///
/// Resolution order for finding the plugin for an operation:
/// 1. Per-key binding (config `key_bindings`)
/// 2. Per-operation default (config `operation_defaults`)
/// 3. Global default plugin (config `default_plugin`)
pub struct WscdManager {
    config: WscdConfig,
    plugins: HashMap<String, Arc<dyn WscdPlugin>>,
}

impl WscdManager {
    pub fn new(config: WscdConfig) -> Self {
        Self {
            config,
            plugins: HashMap::new(),
        }
    }

    /// Register a plugin. Replaces any existing plugin with the same ID.
    pub fn register_plugin(&mut self, plugin: Arc<dyn WscdPlugin>) {
        self.plugins.insert(plugin.id().to_string(), plugin);
    }

    /// Resolve the plugin for a given key, falling back through the
    /// resolution chain.
    fn resolve_for_key(&self, kid: &KeyId, op: &str) -> Result<Arc<dyn WscdPlugin>> {
        // 1. Per-key binding
        if let Some(plugin_id) = self.config.key_bindings.get(kid) {
            return self.get_plugin(plugin_id);
        }
        // 2. Per-operation default
        if let Some(plugin_id) = self.config.operation_defaults.get(op) {
            return self.get_plugin(plugin_id);
        }
        // 3. Global default
        self.get_plugin(&self.config.default_plugin)
    }

    /// Resolve the plugin for a generate operation (no key yet).
    fn resolve_for_generate(&self) -> Result<Arc<dyn WscdPlugin>> {
        if let Some(plugin_id) = self.config.operation_defaults.get("generate_key") {
            return self.get_plugin(plugin_id);
        }
        self.get_plugin(&self.config.default_plugin)
    }

    fn get_plugin(&self, id: &str) -> Result<Arc<dyn WscdPlugin>> {
        self.plugins
            .get(id)
            .cloned()
            .ok_or_else(|| WscdError::NoPlugin {
                kid: id.to_string(),
            })
    }

    /// Get a plugin by its ID (public, for FFI/export use).
    pub fn get_plugin_by_id(&self, id: &str) -> Result<Arc<dyn WscdPlugin>> {
        self.get_plugin(id)
    }

    /// Bind existing keys to the plugin that holds them, so that operations
    /// on those kids route there rather than to the default plugin.
    ///
    /// Bindings are otherwise only recorded at `generate_key`; a plugin
    /// restored from persisted state (FIDO2 credential handles, a softkey
    /// container) brings its keys back without them, and every operation
    /// on a restored key would fall through to the default plugin and fail.
    /// Call this right after registering such a plugin. A kid already bound
    /// to a *different* plugin is a collision and an error.
    pub fn bind_keys(
        &mut self,
        plugin_id: &str,
        kids: impl IntoIterator<Item = KeyId>,
    ) -> Result<()> {
        for kid in kids {
            match self.config.key_bindings.get(&kid) {
                Some(existing) if existing != plugin_id => {
                    return Err(WscdError::Plugin(format!(
                        "key {} is already bound to plugin {existing}, cannot bind it to {plugin_id}",
                        kid.as_str()
                    )));
                }
                _ => {
                    self.config.key_bindings.insert(kid, plugin_id.to_string());
                }
            }
        }
        Ok(())
    }

    /// Ids of the registered plugins, in no particular order.
    pub fn plugin_ids(&self) -> Vec<&str> {
        self.plugins.keys().map(String::as_str).collect()
    }

    /// Generate a new key using the configured default plugin.
    pub async fn generate_key(
        &mut self,
        algorithm: Algorithm,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<GeneratedKey> {
        let plugin = self.resolve_for_generate()?;
        self.generate_key_on(plugin, algorithm, auth, progress)
            .await
    }

    /// Generate a new key using a specific registered plugin, bypassing the
    /// default-plugin resolution chain. For callers that manage more than
    /// one plugin at once (e.g. softkey + FIDO2 in the same WASM manager)
    /// and need to pick which one backs a given key, rather than relying
    /// on a single process-wide default.
    pub async fn generate_key_with_plugin(
        &mut self,
        plugin_id: &str,
        algorithm: Algorithm,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<GeneratedKey> {
        let plugin = self.get_plugin(plugin_id)?;
        self.generate_key_on(plugin, algorithm, auth, progress)
            .await
    }

    async fn generate_key_on(
        &mut self,
        plugin: Arc<dyn WscdPlugin>,
        algorithm: Algorithm,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<GeneratedKey> {
        let result = plugin.generate_key(algorithm, auth, progress).await?;
        // Record the key→plugin binding. A kid already bound to a different
        // plugin is a collision, not an update: overwriting would silently
        // re-route the existing key. Thumbprint kids make this unreachable
        // for two honest keys; an R2PS service handing out arbitrary kids is
        // the case this guards against.
        if let Some(existing) = self.config.key_bindings.get(&result.kid) {
            if existing != plugin.id() {
                return Err(WscdError::Plugin(format!(
                    "plugin {} generated key {} which is already bound to plugin {existing}",
                    plugin.id(),
                    result.kid.as_str()
                )));
            }
        }
        self.config
            .key_bindings
            .insert(result.kid.clone(), plugin.id().to_string());
        Ok(result)
    }

    /// Generate a key that actually meets `required_level`, trying each of
    /// `candidate_plugin_ids` in order and confirming the result rather than
    /// trusting any plugin's self-reported capability.
    ///
    /// **This method is plugin-agnostic** — it has no Android (or any other
    /// backend) specific logic. The caller (the SDK's own
    /// `WscdSelectionPolicy`, for the credential-issuance key-generation
    /// path) does the ordering/preference work — which plugin to try
    /// first, TOFU, user overrides, the host-app choice prompt for genuine
    /// ambiguity — all of that policy stays on the SDK side, unchanged; this
    /// method only consumes the resulting ordered list. Keeping the
    /// confirm-and-retry loop here, generically, is what lets a future
    /// plugin (a second hardware-backed one, say) participate in KA's
    /// required-tier enforcement with zero changes to this method.
    ///
    /// For each `plugin_id` in order:
    /// 1. `generate_key_with_plugin(plugin_id, ...)`.
    /// 2. `security_properties(generated.kid).certification` — the level
    ///    the plugin's OWN record says it actually achieved, not a nominal
    ///    table lookup. (For the Android Keystore plugin specifically, this
    ///    is the real, Keystore-confirmed StrongBox/TEE/software tier from
    ///    `AndroidKeystoreCallback::generate`'s return value, captured at
    ///    generation time — never re-derived from what was merely
    ///    *requested*.)
    /// 3. If that level is at or above `required_level` (ordered
    ///    `None < Baseline < Substantial < High`): keep the key, return it.
    /// 4. Otherwise: delete the just-generated key (mirrors
    ///    `AndroidKeystoreSigner.createKey`'s own refuse-and-delete pattern,
    ///    siros-sdk-kotlin #366 — a key this method is about to reject must
    ///    not linger in the backend as an orphan) and try the next
    ///    candidate.
    ///
    /// A candidate that fails to even resolve/generate (`get_plugin`/
    /// `generate_key_with_plugin` erroring) is treated the same as a
    /// confirmed shortfall: skip it and try the next one, remembering its
    /// error. Returns the first candidate's key that met the requirement,
    /// or — if none did — the most recent candidate's own error/shortfall,
    /// so a caller's error message describes a real attempt rather than
    /// "no candidates were offered" when candidates *were* offered and all
    /// fell short.
    pub async fn generate_key_for_level(
        &mut self,
        required_level: CertificationLevel,
        candidate_plugin_ids: &[String],
        algorithm: Algorithm,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<GeneratedKey> {
        if candidate_plugin_ids.is_empty() {
            return Err(WscdError::NoPlugin {
                kid: "generate_key_for_level: no candidate plugins were offered".to_string(),
            });
        }
        let required_rank = Self::certification_rank(required_level);
        let mut last_err: Option<WscdError> = None;

        for plugin_id in candidate_plugin_ids {
            let plugin = match self.get_plugin(plugin_id) {
                Ok(p) => p,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            let generated = match self
                .generate_key_on(plugin, algorithm, auth, progress)
                .await
            {
                Ok(g) => g,
                // Three kinds of candidate failure must stop the WHOLE
                // operation rather than silently moving to the next
                // candidate:
                // - `UnconfirmedCleanup`: this candidate's plugin may have
                //   left a real, orphaned key behind that a later
                //   candidate's success would then mask - see that
                //   variant's doc comment.
                // - `AuthCancelled`: the user explicitly said no to THIS
                //   candidate's auth ceremony (e.g. a FIDO2 PIN prompt).
                //   Silently trying a different plugin after that is a
                //   worse UX bug than refusing outright: it generates a key
                //   via a mechanism the user never agreed to, right after
                //   they declined the one they were actually asked about.
                // - `Pin`: the host's PIN ceremony for THIS candidate is not
                //   over - it is asking to be retried (wrong PIN, PIN too
                //   short, authenticator has none yet, ...), which only the
                //   host's own PIN-prompt retry loop (e.g.
                //   siros-sdk-kotlin's `PinPrompter`) can resolve by calling
                //   this whole method again with the SAME `auth` ceremony
                //   state. Treating it as an ordinary candidate failure and
                //   moving on single-handedly resolves it here instead: a
                //   user who mistypes their FIDO2 PIN would silently end up
                //   with a DIFFERENT candidate's key (e.g. Android Keystore)
                //   rather than ever being asked to correct the PIN on the
                //   authenticator they were actually trying to use.
                Err(
                    e @ (WscdError::UnconfirmedCleanup { .. }
                    | WscdError::AuthCancelled
                    | WscdError::Pin(_)),
                ) => {
                    return Err(e);
                }
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            let achieved = match self.security_properties(&generated.kid) {
                Ok(props) => props.certification,
                Err(e) => {
                    // Cannot even confirm what was achieved: fail closed,
                    // same as a confirmed shortfall - never keep a key this
                    // method cannot vouch for. A deletion failure here is
                    // NOT swallowed: silently falling through to the next
                    // candidate could then return success while this
                    // rejected key is still live and its cleanup failure
                    // hidden - stop and surface both errors instead.
                    if let Err(delete_err) = self.delete_key(&generated.kid).await {
                        return Err(WscdError::Plugin(format!(
                            "generate_key_for_level: could not confirm the level {plugin_id} reached ({e}), and deleting its key also failed ({delete_err})"
                        )));
                    }
                    last_err = Some(e);
                    continue;
                }
            };

            if Self::certification_rank(achieved) >= required_rank {
                return Ok(generated);
            }

            let shortfall = WscdError::Unsupported {
                plugin: plugin_id.clone(),
                op: format!(
                    "generate_key_for_level: reached {achieved:?}, required {required_level:?}"
                ),
            };
            // Same rationale as above: a failed deletion here must stop the
            // loop, not be swallowed in favor of trying the next candidate.
            if let Err(delete_err) = self.delete_key(&generated.kid).await {
                return Err(WscdError::Plugin(format!(
                    "{shortfall}, and deleting the insufficient key also failed ({delete_err})"
                )));
            }
            last_err = Some(shortfall);
        }

        Err(last_err.unwrap_or(WscdError::NoPlugin {
            kid: "generate_key_for_level: no candidate plugin satisfied the required level"
                .to_string(),
        }))
    }

    /// Ordinal rank of a [`CertificationLevel`], for the >= comparison
    /// [`Self::generate_key_for_level`] needs - `CertificationLevel` itself
    /// deliberately has no `Ord` impl (its variant declaration order being
    /// meaningful is easy to break silently by reordering/inserting a
    /// variant; this keeps that assumption in exactly one place).
    fn certification_rank(level: CertificationLevel) -> u8 {
        match level {
            CertificationLevel::None => 0,
            CertificationLevel::Baseline => 1,
            CertificationLevel::Substantial => 2,
            CertificationLevel::High => 3,
        }
    }

    /// Sign data with the given key.
    pub async fn sign(
        &self,
        kid: &KeyId,
        data: &[u8],
        algorithm: Algorithm,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<Signature> {
        let plugin = self.resolve_for_key(kid, "sign")?;
        plugin.sign(kid, data, algorithm, auth, progress).await
    }

    /// Sign data with the given key and report the TS12 authentication
    /// factors applied to this sign. See [`WscdPlugin::sign_with_factors`].
    pub async fn sign_with_factors(
        &self,
        kid: &KeyId,
        data: &[u8],
        algorithm: Algorithm,
        options: &SignOptions,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<SignOutcome> {
        let plugin = self.resolve_for_key(kid, "sign")?;
        plugin
            .sign_with_factors(kid, data, algorithm, options, auth, progress)
            .await
    }

    /// Whether a sign with this key could reach two TS12 categories; asked
    /// before consent, never prompts.
    pub fn authentication_capability(&self, kid: &KeyId) -> Result<FactorCapability> {
        let plugin = self.resolve_for_key(kid, "sign")?;
        plugin.authentication_capability(kid)
    }

    /// List all keys across all registered plugins.
    pub async fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        let mut all = Vec::new();
        for plugin in self.plugins.values() {
            let keys = plugin.list_keys().await?;
            all.extend(keys);
        }
        Ok(all)
    }

    /// Get the attestation chain for a key.
    pub async fn attestation_chain(&self, kid: &KeyId) -> Result<Option<AttestationChain>> {
        let plugin = self.resolve_for_key(kid, "attestation")?;
        plugin.attestation_chain(kid).await
    }

    /// Export the public key (JWK) for a key.
    pub async fn export_public_key(&self, kid: &KeyId) -> Result<serde_json::Value> {
        let plugin = self.resolve_for_key(kid, "export_public_key")?;
        plugin.export_public_key(kid).await
    }

    /// Delete a key.
    pub async fn delete_key(&mut self, kid: &KeyId) -> Result<()> {
        let plugin = self.resolve_for_key(kid, "delete")?;
        plugin.delete_key(kid).await?;
        self.config.key_bindings.remove(kid);
        Ok(())
    }

    /// Migrate a key from its current plugin to a target plugin.
    ///
    /// This generates a new key in the target plugin. The old key
    /// remains until explicitly deleted. Some migrations (e.g., softkey
    /// → R2PS) may require full re-enrollment with the credential issuer.
    pub async fn migrate_key(
        &mut self,
        kid: &KeyId,
        target_plugin_id: &str,
        auth: &dyn AuthCallback,
    ) -> Result<MigrationResult> {
        let target = self.get_plugin(target_plugin_id)?;
        if !target.supports_import() {
            return Ok(MigrationResult::ReEnrollmentRequired {
                old_kid: kid.clone(),
            });
        }

        let source = self.resolve_for_key(kid, "migrate")?;
        let _pub_jwk = source.export_public_key(kid).await?;

        // Get the algorithm from the source key
        let keys = source.list_keys().await?;
        let key_info =
            keys.iter()
                .find(|k| k.kid == *kid)
                .ok_or_else(|| WscdError::KeyNotFound {
                    kid: kid.to_string(),
                })?;

        let progress = NoopProgress;
        let result = target
            .import_key(key_info.algorithm, auth, &progress)
            .await?;

        // Update binding if migration succeeded
        if let MigrationResult::Migrated { ref new_kid } = result {
            self.config
                .key_bindings
                .insert(new_kid.clone(), target_plugin_id.to_string());
        }

        Ok(result)
    }

    /// Get the current config (for serialization/persistence).
    pub fn config(&self) -> &WscdConfig {
        &self.config
    }

    /// Get the security properties for a key (CS-04 §7.1.3).
    pub fn security_properties(&self, kid: &KeyId) -> Result<SecurityProperties> {
        let plugin = self.resolve_for_key(kid, "security_properties")?;
        plugin.security_properties(kid)
    }

    /// Return lifecycle status for a plugin context.
    pub async fn lifecycle_status(
        &self,
        plugin_id: &str,
        context_id: &str,
    ) -> Result<LifecycleStatus> {
        let plugin = self.get_plugin(plugin_id)?;
        plugin.lifecycle_status(context_id).await
    }

    /// Register lifecycle material and bindings for a plugin context.
    pub async fn register_lifecycle(
        &self,
        request: &RegisterLifecycleRequest,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<RegistrationOutcome> {
        let plugin = self.get_plugin(&request.plugin_id)?;
        plugin.register_lifecycle(request, auth, progress).await
    }

    /// Activate an existing lifecycle context.
    pub async fn activate_lifecycle(
        &self,
        request: &ActivateLifecycleRequest,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<ActivationOutcome> {
        let plugin = self.get_plugin(&request.plugin_id)?;
        plugin.activate_lifecycle(request, auth, progress).await
    }

    /// Rotate lifecycle material for a context.
    pub async fn rotate_lifecycle(
        &self,
        request: &RotateLifecycleRequest,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<RotationOutcome> {
        let plugin = self.get_plugin(&request.plugin_id)?;
        plugin.rotate_lifecycle(request, auth, progress).await
    }

    /// Destroy lifecycle material and bindings for a context.
    pub async fn destroy_lifecycle(
        &self,
        request: &DestroyLifecycleRequest,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<DestructionOutcome> {
        let plugin = self.get_plugin(&request.plugin_id)?;
        plugin.destroy_lifecycle(request, auth, progress).await
    }
}

#[cfg(test)]
mod kid_collision_tests {
    use super::*;
    use crate::callbacks::{AuthCallback, NoopProgress, ProgressCallback};
    use crate::types::*;
    use async_trait::async_trait;

    /// A plugin that hands out whatever kid it is told to - what a remote
    /// R2PS service could do.
    struct FixedKidPlugin {
        id: &'static str,
        kid: &'static str,
    }

    #[async_trait]
    impl WscdPlugin for FixedKidPlugin {
        fn id(&self) -> &str {
            self.id
        }
        fn display_name(&self) -> &str {
            self.id
        }
        fn auth_method(&self) -> AuthMethod {
            AuthMethod::None
        }
        async fn generate_key(
            &self,
            _: Algorithm,
            _: &dyn AuthCallback,
            _: &dyn ProgressCallback,
        ) -> Result<GeneratedKey> {
            Ok(GeneratedKey {
                kid: KeyId(self.kid.to_string()),
                public_key_jwk: serde_json::json!({"kty": "EC"}),
            })
        }
        async fn sign(
            &self,
            _: &KeyId,
            _: &[u8],
            _: Algorithm,
            _: &dyn AuthCallback,
            _: &dyn ProgressCallback,
        ) -> Result<Signature> {
            unreachable!()
        }
        async fn list_keys(&self) -> Result<Vec<KeyInfo>> {
            Ok(vec![])
        }
        async fn attestation_chain(&self, _: &KeyId) -> Result<Option<AttestationChain>> {
            Ok(None)
        }
        async fn delete_key(&self, _: &KeyId) -> Result<()> {
            Ok(())
        }
        async fn export_public_key(&self, _: &KeyId) -> Result<serde_json::Value> {
            unreachable!()
        }
        fn security_properties(&self, _: &KeyId) -> Result<SecurityProperties> {
            unreachable!()
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

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

    /// Two plugins claiming one kid: the second generate is refused rather
    /// than silently re-routing the first key.
    #[tokio::test]
    async fn a_kid_already_bound_to_another_plugin_is_a_collision() {
        let mut manager = WscdManager::new(WscdConfig {
            default_plugin: "a".to_string(),
            ..Default::default()
        });
        manager.register_plugin(Arc::new(FixedKidPlugin {
            id: "a",
            kid: "same",
        }));
        manager.register_plugin(Arc::new(FixedKidPlugin {
            id: "b",
            kid: "same",
        }));

        manager
            .generate_key_with_plugin("a", Algorithm::ES256, &NoAuth, &NoopProgress)
            .await
            .unwrap();
        let err = manager
            .generate_key_with_plugin("b", Algorithm::ES256, &NoAuth, &NoopProgress)
            .await
            .expect_err("kid collision across plugins must be refused");
        assert!(
            err.to_string().contains("already bound to plugin a"),
            "{err}"
        );
        // The original binding is intact.
        assert_eq!(manager.config().key_bindings[&KeyId("same".into())], "a");
        // Same plugin again is fine (same key, same owner).
        manager
            .generate_key_with_plugin("a", Algorithm::ES256, &NoAuth, &NoopProgress)
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod generate_key_for_level_tests {
    use super::*;
    use crate::callbacks::{AuthCallback, NoopProgress, ProgressCallback};
    use crate::types::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// A plugin whose `security_properties` always reports a fixed,
    /// configured [`CertificationLevel`] - standing in for a real plugin
    /// whose confirmed tier can only be known after generation (the
    /// Android Keystore plugin's StrongBox/TEE outcome, say). Counts
    /// generate/delete calls so a test can assert the shortfall-and-retry
    /// loop actually deletes what it rejects, and never leaves an orphaned
    /// key behind.
    struct LeveledPlugin {
        id: &'static str,
        level: CertificationLevel,
        generated: AtomicU32,
        deleted: AtomicU32,
        delete_fails: AtomicBool,
        /// When set, `generate_key` fails with this instead of succeeding -
        /// for simulating a candidate whose OWN generate_key call already
        /// reports `UnconfirmedCleanup`/`AuthCancelled` (as a real plugin's
        /// would after its own failed-and-unrecoverable cleanup, or a
        /// cancelled auth ceremony), independent of this fake's own
        /// `delete_key`/`delete_fails`.
        generate_fails_with: std::sync::Mutex<Option<WscdError>>,
    }

    impl LeveledPlugin {
        fn new(id: &'static str, level: CertificationLevel) -> Self {
            Self {
                id,
                level,
                generated: AtomicU32::new(0),
                deleted: AtomicU32::new(0),
                delete_fails: AtomicBool::new(false),
                generate_fails_with: std::sync::Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl WscdPlugin for LeveledPlugin {
        fn id(&self) -> &str {
            self.id
        }
        fn display_name(&self) -> &str {
            self.id
        }
        fn auth_method(&self) -> AuthMethod {
            AuthMethod::None
        }
        async fn generate_key(
            &self,
            _: Algorithm,
            _: &dyn AuthCallback,
            _: &dyn ProgressCallback,
        ) -> Result<GeneratedKey> {
            if let Some(e) = self.generate_fails_with.lock().unwrap().take() {
                return Err(e);
            }
            let n = self.generated.fetch_add(1, Ordering::SeqCst);
            Ok(GeneratedKey {
                kid: KeyId(format!("{}-{n}", self.id)),
                public_key_jwk: serde_json::json!({"kty": "EC"}),
            })
        }
        async fn sign(
            &self,
            _: &KeyId,
            _: &[u8],
            _: Algorithm,
            _: &dyn AuthCallback,
            _: &dyn ProgressCallback,
        ) -> Result<Signature> {
            unreachable!()
        }
        async fn list_keys(&self) -> Result<Vec<KeyInfo>> {
            Ok(vec![])
        }
        async fn attestation_chain(&self, _: &KeyId) -> Result<Option<AttestationChain>> {
            Ok(None)
        }
        async fn delete_key(&self, _: &KeyId) -> Result<()> {
            if self.delete_fails.load(Ordering::SeqCst) {
                return Err(WscdError::Plugin("delete failed".into()));
            }
            self.deleted.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn export_public_key(&self, _: &KeyId) -> Result<serde_json::Value> {
            unreachable!()
        }
        fn security_properties(&self, _: &KeyId) -> Result<SecurityProperties> {
            Ok(SecurityProperties {
                key_storage: KeyStorageType::Hardware,
                user_authentication: vec![],
                certification: self.level,
                amr: vec![],
            })
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

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

    /// The first candidate that actually meets the required level wins,
    /// with no fallback to a later (even stronger) one.
    #[tokio::test]
    async fn first_sufficient_candidate_wins() {
        let mut manager = WscdManager::new(WscdConfig {
            default_plugin: "weak".to_string(),
            ..Default::default()
        });
        manager.register_plugin(Arc::new(LeveledPlugin::new(
            "weak",
            CertificationLevel::Baseline,
        )));
        manager.register_plugin(Arc::new(LeveledPlugin::new(
            "strong",
            CertificationLevel::High,
        )));

        let result = manager
            .generate_key_for_level(
                CertificationLevel::Baseline,
                &["weak".to_string(), "strong".to_string()],
                Algorithm::ES256,
                &NoAuth,
                &NoopProgress,
            )
            .await
            .unwrap();
        assert_eq!(result.kid.as_str(), "weak-0");
    }

    /// A candidate that falls short of the required level is deleted (never
    /// left behind as an orphan) and the next candidate is tried.
    ///
    /// Confirmed non-vacuous: with the `certification_rank` comparison
    /// inverted (`<=` instead of `>=`), this test fails because the first
    /// (insufficient) candidate's key is wrongly kept - checked, then
    /// restored.
    #[tokio::test]
    async fn insufficient_candidate_is_deleted_and_the_next_one_is_tried() {
        let mut manager = WscdManager::new(WscdConfig {
            default_plugin: "weak".to_string(),
            ..Default::default()
        });
        let weak = Arc::new(LeveledPlugin::new("weak", CertificationLevel::Baseline));
        let strong = Arc::new(LeveledPlugin::new("strong", CertificationLevel::High));
        manager.register_plugin(weak.clone());
        manager.register_plugin(strong.clone());

        let result = manager
            .generate_key_for_level(
                CertificationLevel::High,
                &["weak".to_string(), "strong".to_string()],
                Algorithm::ES256,
                &NoAuth,
                &NoopProgress,
            )
            .await
            .unwrap();

        assert_eq!(result.kid.as_str(), "strong-0");
        assert_eq!(weak.generated.load(Ordering::SeqCst), 1);
        assert_eq!(
            weak.deleted.load(Ordering::SeqCst),
            1,
            "the insufficient 'weak' key must be deleted, not left behind"
        );
        assert_eq!(strong.deleted.load(Ordering::SeqCst), 0);
    }

    /// No candidate meets the requirement: every one is tried (and
    /// deleted), and the error describes a real attempt.
    #[tokio::test]
    async fn no_sufficient_candidate_deletes_every_attempt_and_errors() {
        let mut manager = WscdManager::new(WscdConfig {
            default_plugin: "a".to_string(),
            ..Default::default()
        });
        let a = Arc::new(LeveledPlugin::new("a", CertificationLevel::Baseline));
        let b = Arc::new(LeveledPlugin::new("b", CertificationLevel::Substantial));
        manager.register_plugin(a.clone());
        manager.register_plugin(b.clone());

        let err = manager
            .generate_key_for_level(
                CertificationLevel::High,
                &["a".to_string(), "b".to_string()],
                Algorithm::ES256,
                &NoAuth,
                &NoopProgress,
            )
            .await
            .expect_err("no candidate reaches High");
        assert!(err.to_string().contains('b'), "{err}");
        assert_eq!(a.deleted.load(Ordering::SeqCst), 1);
        assert_eq!(b.deleted.load(Ordering::SeqCst), 1);
    }

    /// An empty candidate list is refused up front - never silently falls
    /// back to the manager's own default plugin, which would defeat the
    /// whole point of the caller having computed an eligible candidate list.
    #[tokio::test]
    async fn empty_candidate_list_is_refused() {
        let mut manager = WscdManager::new(WscdConfig {
            default_plugin: "a".to_string(),
            ..Default::default()
        });
        manager.register_plugin(Arc::new(LeveledPlugin::new("a", CertificationLevel::High)));

        let err = manager
            .generate_key_for_level(
                CertificationLevel::Baseline,
                &[],
                Algorithm::ES256,
                &NoAuth,
                &NoopProgress,
            )
            .await
            .expect_err("an empty candidate list must be refused");
        assert!(err.to_string().contains("no candidate"), "{err}");
    }

    /// A deletion failure on an insufficient candidate must stop the loop
    /// and surface the cleanup failure - NOT be swallowed in favor of
    /// silently trying (and possibly succeeding on) the next candidate,
    /// which would return success while the rejected key is still live and
    /// hide that its cleanup failed.
    ///
    /// Confirmed non-vacuous: with the deletion-error check removed
    /// (`let _ = self.delete_key(...).await;`, swallowing the error as this
    /// method used to), this test fails because the loop falls through to
    /// "strong" and returns its key successfully - checked, then restored.
    #[tokio::test]
    async fn insufficient_candidate_delete_failure_stops_the_loop_and_is_surfaced() {
        let mut manager = WscdManager::new(WscdConfig {
            default_plugin: "weak".to_string(),
            ..Default::default()
        });
        let weak = Arc::new(LeveledPlugin::new("weak", CertificationLevel::Baseline));
        weak.delete_fails.store(true, Ordering::SeqCst);
        let strong = Arc::new(LeveledPlugin::new("strong", CertificationLevel::High));
        manager.register_plugin(weak.clone());
        manager.register_plugin(strong.clone());

        let err = manager
            .generate_key_for_level(
                CertificationLevel::High,
                &["weak".to_string(), "strong".to_string()],
                Algorithm::ES256,
                &NoAuth,
                &NoopProgress,
            )
            .await
            .expect_err("a deletion failure on the rejected 'weak' key must stop the loop");
        assert!(
            err.to_string().contains("delete"),
            "the error must mention the cleanup failure: {err}"
        );
        assert_eq!(
            strong.generated.load(Ordering::SeqCst),
            0,
            "the loop must stop before ever trying 'strong'"
        );
    }

    /// A candidate's own `generate_key` reporting `UnconfirmedCleanup`
    /// (e.g. the Android Keystore plugin's own StrongBox→TEE cleanup
    /// failing) must stop the whole operation immediately - a later
    /// candidate's success would otherwise mask a real, orphaned key this
    /// one left behind.
    ///
    /// Confirmed non-vacuous: with the stop-on-`UnconfirmedCleanup` arm
    /// removed (falling through to the generic "try the next candidate"
    /// arm), this test fails because the loop succeeds on "strong" instead
    /// - checked, then restored.
    #[tokio::test]
    async fn unconfirmed_cleanup_from_a_candidate_stops_the_loop_immediately() {
        let mut manager = WscdManager::new(WscdConfig {
            default_plugin: "weak".to_string(),
            ..Default::default()
        });
        let weak = Arc::new(LeveledPlugin::new("weak", CertificationLevel::High));
        *weak.generate_fails_with.lock().unwrap() = Some(WscdError::UnconfirmedCleanup {
            plugin: "weak".to_string(),
            reason: "simulated orphaned key".to_string(),
        });
        let strong = Arc::new(LeveledPlugin::new("strong", CertificationLevel::High));
        manager.register_plugin(weak);
        manager.register_plugin(strong.clone());

        let err = manager
            .generate_key_for_level(
                CertificationLevel::High,
                &["weak".to_string(), "strong".to_string()],
                Algorithm::ES256,
                &NoAuth,
                &NoopProgress,
            )
            .await
            .expect_err("UnconfirmedCleanup from a candidate must stop the whole operation");
        assert!(matches!(err, WscdError::UnconfirmedCleanup { .. }), "{err}");
        assert_eq!(
            strong.generated.load(Ordering::SeqCst),
            0,
            "the loop must stop before ever trying 'strong', or its success would mask weak's orphaned key"
        );
    }

    /// A candidate's own `generate_key` reporting `AuthCancelled` (the user
    /// declined that candidate's own auth ceremony, e.g. a FIDO2 PIN
    /// prompt) must stop the whole operation immediately - silently trying
    /// a different plugin after an explicit cancellation would generate a
    /// key via a mechanism the user never agreed to.
    #[tokio::test]
    async fn auth_cancelled_from_a_candidate_stops_the_loop_immediately() {
        let mut manager = WscdManager::new(WscdConfig {
            default_plugin: "fido2".to_string(),
            ..Default::default()
        });
        let fido2 = Arc::new(LeveledPlugin::new("fido2", CertificationLevel::High));
        *fido2.generate_fails_with.lock().unwrap() = Some(WscdError::AuthCancelled);
        let android = Arc::new(LeveledPlugin::new(
            "android-keystore",
            CertificationLevel::High,
        ));
        manager.register_plugin(fido2);
        manager.register_plugin(android.clone());

        let err = manager
            .generate_key_for_level(
                CertificationLevel::High,
                &["fido2".to_string(), "android-keystore".to_string()],
                Algorithm::ES256,
                &NoAuth,
                &NoopProgress,
            )
            .await
            .expect_err("a cancelled auth ceremony must stop the whole operation");
        assert!(matches!(err, WscdError::AuthCancelled), "{err}");
        assert_eq!(
            android.generated.load(Ordering::SeqCst),
            0,
            "must never silently fall back to android-keystore after the user cancelled fido2's prompt"
        );
    }

    /// A candidate's own `generate_key` reporting `Pin` (the PIN ceremony
    /// for THIS candidate is not over - wrong PIN, authenticator has none
    /// yet, etc.) must stop the whole operation immediately too, exactly
    /// like `AuthCancelled` - only the host's own PIN-prompt retry loop can
    /// resolve it by calling this method again with the same ceremony
    /// state. Silently trying a different candidate after a retriable PIN
    /// failure would generate a key on a DIFFERENT authenticator than the
    /// one whose PIN the user is actively correcting.
    #[tokio::test]
    async fn pin_failure_from_a_candidate_stops_the_loop_immediately() {
        let mut manager = WscdManager::new(WscdConfig {
            default_plugin: "fido2".to_string(),
            ..Default::default()
        });
        let fido2 = Arc::new(LeveledPlugin::new("fido2", CertificationLevel::High));
        *fido2.generate_fails_with.lock().unwrap() =
            Some(WscdError::Pin(crate::error::PinFailure::Invalid));
        let android = Arc::new(LeveledPlugin::new(
            "android-keystore",
            CertificationLevel::High,
        ));
        manager.register_plugin(fido2);
        manager.register_plugin(android.clone());

        let err = manager
            .generate_key_for_level(
                CertificationLevel::High,
                &["fido2".to_string(), "android-keystore".to_string()],
                Algorithm::ES256,
                &NoAuth,
                &NoopProgress,
            )
            .await
            .expect_err("a retriable PIN failure must stop the whole operation");
        assert!(matches!(err, WscdError::Pin(_)), "{err}");
        assert_eq!(
            android.generated.load(Ordering::SeqCst),
            0,
            "must never silently fall back to android-keystore while fido2's PIN ceremony is still being retried"
        );
    }
}
