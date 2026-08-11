//! WASM bridge — exposes the WSCD manager to JavaScript via wasm-bindgen.
//!
//! Compile with: `wasm-pack build --target web --no-default-features --features wasm`
//!
//! Architecture: Uses RefCell (not Mutex) because WASM is single-threaded.
//! RefCell provides runtime borrow checking without the risk of blocking the
//! JS event loop. A panic on double-borrow is preferred over a deadlock.

#![cfg(feature = "wasm")]

use serde::Serialize;
use std::cell::RefCell;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

use crate::callbacks::{AuthCallback, NoopProgress};
use crate::config::WscdConfig;
use crate::error::Result as WscdResult;
use crate::manager::WscdManager;
use crate::plugins::softkey::SoftkeyPlugin;
use crate::types::{Algorithm, KeyId};

/// Serialize a value to a plain JS object (not an ES2015 `Map`) — the shape
/// a JS/TS caller actually wants for a JWK or SecurityProperties object
/// (`obj.kty`, `JSON.stringify(obj)`), matching `serde_wasm_bindgen::to_value`'s
/// default `Map`-producing behavior would silently break both.
fn to_plain_js_object<T: Serialize + ?Sized>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsError::new(&e.to_string()))
}

/// No-op auth callback for WASM.
/// In the browser, authentication (biometrics/PIN) is handled at the application
/// layer before calling into WSCD. The WSCD layer itself doesn\'t need to prompt.
struct WasmNoopAuth;

#[async_trait::async_trait]
impl AuthCallback for WasmNoopAuth {
    async fn request_pin(&self, _plugin_id: &str) -> WscdResult<Vec<u8>> {
        Err(crate::error::WscdError::AuthCancelled)
    }

    async fn request_webauthn_assertion(
        &self,
        _plugin_id: &str,
        _challenge: &[u8],
        _rp_id: &str,
        _allowed_credentials: &[Vec<u8>],
    ) -> WscdResult<Vec<u8>> {
        Err(crate::error::WscdError::AuthCancelled)
    }
}

/// JavaScript-facing WSCD Manager.
///
/// Uses `RefCell` for interior mutability (WASM is single-threaded).
/// wasm_bindgen requires `!Send` types to be used in a single-threaded context.
#[wasm_bindgen]
pub struct WscdManagerJs {
    manager: RefCell<WscdManager>,
}

#[wasm_bindgen]
#[allow(clippy::await_holding_refcell_ref)]
impl WscdManagerJs {
    /// Create a new WSCD manager with the softkey plugin.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WscdManagerJs, JsError> {
        let config = WscdConfig::default();
        let mut manager = WscdManager::new(config);
        let softkey = SoftkeyPlugin::new();
        manager.register_plugin(Arc::new(softkey));
        Ok(WscdManagerJs {
            manager: RefCell::new(manager),
        })
    }

    /// Generate a new P-256 key pair. Returns the key ID.
    #[wasm_bindgen(js_name = "generateKey")]
    pub async fn generate_key(&self) -> Result<String, JsError> {
        let auth = WasmNoopAuth;
        let progress = NoopProgress;
        let result = self
            .manager
            .borrow_mut()
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
        let sig = self
            .manager
            .borrow()
            .sign(&kid, data, Algorithm::ES256, &auth, &progress)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(sig.0)
    }

    /// List all key IDs.
    #[wasm_bindgen(js_name = "listKeys")]
    pub async fn list_keys(&self) -> Result<JsValue, JsError> {
        let keys = self
            .manager
            .borrow()
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
        self.manager
            .borrow_mut()
            .delete_key(&kid)
            .await
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Export the public key (JWK) for a key.
    #[wasm_bindgen(js_name = "exportPublicKey")]
    pub async fn export_public_key(&self, key_id: &str) -> Result<JsValue, JsError> {
        let kid = KeyId(key_id.to_string());
        let jwk = self
            .manager
            .borrow()
            .export_public_key(&kid)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        to_plain_js_object(&jwk)
    }

    /// Get the security properties for a key (CS-04 §7.1.3): key_storage,
    /// user_authentication, certification, amr. Values use the same
    /// lowercase snake_case vocabulary as the native SDKs
    /// (`"software"`/`"hardware"`/`"remote_hsm"`/`"trusted_execution"`),
    /// not the raw Rust enum variant names.
    #[wasm_bindgen(js_name = "securityProperties")]
    pub fn security_properties(&self, key_id: &str) -> Result<JsValue, JsError> {
        let kid = KeyId(key_id.to_string());
        let props = self
            .manager
            .borrow()
            .security_properties(&kid)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let json = serde_json::json!({
            "key_storage": props.key_storage.as_str(),
            "user_authentication": props.user_authentication,
            "certification": props.certification.as_str(),
            "amr": props.amr,
        });
        to_plain_js_object(&json)
    }

    /// Export the softkey plugin's container as JSON bytes (caller wraps in
    /// a JWE before persisting). Mirrors the native SDKs'
    /// `export_softkey_container` FFI method.
    #[wasm_bindgen(js_name = "exportContainer")]
    pub fn export_container(&self) -> Result<Vec<u8>, JsError> {
        let mgr = self.manager.borrow();
        let plugin = mgr
            .get_plugin_by_id("softkey")
            .map_err(|e| JsError::new(&e.to_string()))?;
        let softkey = plugin
            .as_any()
            .downcast_ref::<SoftkeyPlugin>()
            .ok_or_else(|| JsError::new("softkey plugin is not a SoftkeyPlugin"))?;
        softkey
            .export_container()
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Import a softkey container (JSON bytes previously produced by
    /// `exportContainer`), replacing the current softkey plugin state.
    /// Mirrors the native SDKs' `import_softkey_container` FFI method.
    #[wasm_bindgen(js_name = "importContainer")]
    pub fn import_container(&self, container: &[u8]) -> Result<(), JsError> {
        let plugin =
            SoftkeyPlugin::from_container(container).map_err(|e| JsError::new(&e.to_string()))?;
        self.manager.borrow_mut().register_plugin(Arc::new(plugin));
        Ok(())
    }
}
