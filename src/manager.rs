use std::collections::HashMap;
use std::sync::Arc;

use crate::callbacks::{AuthCallback, NoopProgress, ProgressCallback};
use crate::config::WscdConfig;
use crate::error::{Result, WscdError};
use crate::traits::WscdPlugin;
use crate::types::{
    Algorithm, AttestationChain, GeneratedKey, KeyId, KeyInfo, MigrationResult, Signature,
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

    /// Generate a new key using the configured default plugin.
    pub async fn generate_key(
        &mut self,
        algorithm: Algorithm,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<GeneratedKey> {
        let plugin = self.resolve_for_generate()?;
        let result = plugin.generate_key(algorithm, auth, progress).await?;
        // Record the key→plugin binding
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
        let key_info = keys
            .iter()
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
}
