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
