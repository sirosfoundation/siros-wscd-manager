//! WASM bridge — exposes the WSCD manager to JavaScript via wasm-bindgen.
//!
//! Compile with: `wasm-pack build --target web --no-default-features --features wasm`

#![cfg(feature = "wasm")]

use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::*;

use crate::callbacks::{AuthCallback, NoopProgress};
use crate::config::WscdConfig;
use crate::error::Result as WscdResult;
use crate::manager::WscdManager;
use crate::plugins::softkey::SoftkeyPlugin;
use crate::types::{Algorithm, KeyId};

/// No-op auth callback for WASM.
/// In the browser, authentication (biometrics/PIN) is handled at the application
/// layer before calling into WSCD. The WSCD layer itself doesn't need to prompt.
struct WasmNoopAuth;

#[async_trait::async_trait]
impl AuthCallback for WasmNoopAuth {
    async fn request_pin(&self) -> WscdResult<Vec<u8>> {
        Err(crate::error::WscdError::AuthCancelled)
    }

    async fn request_webauthn_assertion(
        &self,
        _challenge: &[u8],
        _rp_id: &str,
        _allowed_credentials: &[Vec<u8>],
    ) -> WscdResult<Vec<u8>> {
        Err(crate::error::WscdError::AuthCancelled)
    }
}

/// JavaScript-facing WSCD Manager.
#[wasm_bindgen]
pub struct WscdManagerJs {
    manager: Mutex<WscdManager>,
}

#[wasm_bindgen]
impl WscdManagerJs {
    /// Create a new WSCD manager with the softkey plugin.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WscdManagerJs, JsError> {
        let config = WscdConfig::default();
        let mut manager = WscdManager::new(config);
        let softkey = SoftkeyPlugin::new();
        manager.register_plugin(Arc::new(softkey));
        Ok(WscdManagerJs {
            manager: Mutex::new(manager),
        })
    }

    /// Generate a new P-256 key pair. Returns the key ID.
    #[wasm_bindgen(js_name = "generateKey")]
    pub async fn generate_key(&self) -> Result<String, JsError> {
        let auth = WasmNoopAuth;
        let progress = NoopProgress;
        let mut mgr = self
            .manager
            .lock()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let result = mgr
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(result.kid.0)
    }

    /// Sign data with the specified key. Returns raw signature bytes.
    #[wasm_bindgen(js_name = "sign")]
    pub async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, JsError> {
        let auth = WasmNoopAuth;
        let progress = NoopProgress;
        let kid = KeyId(key_id.to_string());
        let mgr = self
            .manager
            .lock()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let sig = mgr
            .sign(&kid, data, Algorithm::ES256, &auth, &progress)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(sig.0)
    }

    /// List all key IDs.
    #[wasm_bindgen(js_name = "listKeys")]
    pub async fn list_keys(&self) -> Result<JsValue, JsError> {
        let mgr = self
            .manager
            .lock()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let keys = mgr
            .list_keys()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        let ids: Vec<String> = keys.into_iter().map(|k| k.kid.0).collect();
        serde_wasm_bindgen::to_value(&ids).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Delete a key by ID.
    #[wasm_bindgen(js_name = "deleteKey")]
    pub async fn delete_key(&self, key_id: &str) -> Result<(), JsError> {
        let kid = KeyId(key_id.to_string());
        let mut mgr = self
            .manager
            .lock()
            .map_err(|e| JsError::new(&e.to_string()))?;
        mgr.delete_key(&kid)
            .await
            .map_err(|e| JsError::new(&e.to_string()))
    }
}
