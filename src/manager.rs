use std::collections::HashMap;
use std::sync::Arc;

use crate::callbacks::{AuthCallback, NoopProgress, ProgressCallback};
use crate::config::WscdConfig;
use crate::error::{Result, WscdError};
use crate::traits::WscdPlugin;
use crate::types::{
    ActivateLifecycleRequest, ActivationOutcome, Algorithm, AttestationChain,
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
