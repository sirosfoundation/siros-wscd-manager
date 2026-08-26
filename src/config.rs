use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::KeyId;

/// Top-level configuration for the WSCD manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WscdConfig {
    /// Default plugin ID for key generation.
    pub default_plugin: String,

    /// Per-operation default plugin overrides.
    /// Key: operation name ("generate_key", "sign"), Value: plugin ID.
    #[serde(default)]
    pub operation_defaults: HashMap<String, String>,

    /// Per-key plugin bindings (key ID → plugin ID).
    /// These override the default for operations on specific keys.
    #[serde(default)]
    pub key_bindings: HashMap<KeyId, String>,

    /// Plugin-specific configuration sections.
    #[serde(default)]
    pub plugins: HashMap<String, serde_json::Value>,
}

impl Default for WscdConfig {
    fn default() -> Self {
        Self {
            default_plugin: "softkey".to_string(),
            operation_defaults: HashMap::new(),
            key_bindings: HashMap::new(),
            plugins: HashMap::new(),
        }
    }
}

/// R2PS plugin configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2psConfig {
    /// R2PS server URL.
    pub server_url: String,
    /// Client ID registered with the R2PS server.
    pub client_id: String,
    /// Context string for service requests.
    pub context: String,
    /// Authentication mode: "opaque" or "webauthn".
    #[serde(default = "default_auth_mode")]
    pub auth_mode: String,
    /// Relying Party ID for WebAuthn ceremonies.
    #[serde(default)]
    pub rp_id: String,
    /// Allowed credential IDs for WebAuthn (base64url-encoded).
    #[serde(default)]
    pub allowed_credential_ids: Vec<String>,
}

fn default_auth_mode() -> String {
    "opaque".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Host apps persist this config and read it back after an upgrade, so
    /// the `#[serde(default)]` attributes are a compatibility contract, not
    /// decoration.
    ///
    /// A config saved before `operation_defaults`/`key_bindings`/`plugins`
    /// existed must still load. If any of them lost its default, deserialising
    /// an older blob would fail outright — and the caller's fallback for "the
    /// stored config is unreadable" is to start from scratch, which discards
    /// every recorded key→plugin binding and leaves enrolled keys routed to
    /// the wrong backend.
    #[test]
    fn a_config_from_before_the_optional_fields_existed_still_loads() {
        let legacy = r#"{"default_plugin":"softkey"}"#;
        let config: WscdConfig = serde_json::from_str(legacy).unwrap();
        assert_eq!(config.default_plugin, "softkey");
        assert!(config.operation_defaults.is_empty());
        assert!(config.key_bindings.is_empty());
        assert!(config.plugins.is_empty());

        // `default_plugin` itself has no default: a config without it is
        // genuinely unusable and must fail loudly rather than silently
        // resolve to some built-in.
        assert!(serde_json::from_str::<WscdConfig>("{}").is_err());
    }

    /// Key bindings must survive a save/load cycle keyed by the same `KeyId`.
    ///
    /// `KeyId` is a newtype over `String` used as a `HashMap` key; if its
    /// serialization ever stopped being a plain string the map would still
    /// round-trip through serde while no longer matching the `KeyId`s the
    /// manager looks up at runtime, silently losing every binding.
    #[test]
    fn key_bindings_round_trip_and_stay_lookupable() {
        let mut config = WscdConfig::default();
        config
            .key_bindings
            .insert(KeyId("fido-0".into()), "fido2".into());
        config
            .operation_defaults
            .insert("sign".into(), "fido2".into());

        let json = serde_json::to_string(&config).unwrap();
        assert!(
            json.contains("\"fido-0\":\"fido2\""),
            "a KeyId must serialize as a plain string key: {json}"
        );

        let restored: WscdConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.key_bindings.get(&KeyId("fido-0".into())),
            Some(&"fido2".to_string())
        );
        assert_eq!(
            restored.operation_defaults.get("sign"),
            Some(&"fido2".to_string())
        );
    }

    /// R2PS configs written before `auth_mode` existed must default to
    /// OPAQUE. Defaulting the other way, or to an empty string, would take
    /// the plugin's `match` down the "unknown mode" arm and break an existing
    /// deployment on upgrade.
    #[test]
    fn r2ps_auth_mode_defaults_to_opaque() {
        let json = r#"{"server_url":"https://example/r2ps","client_id":"c","context":"x"}"#;
        let config: R2psConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.auth_mode, "opaque");
        assert!(config.rp_id.is_empty());
        assert!(config.allowed_credential_ids.is_empty());
    }
}
