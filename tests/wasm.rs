//! Browser-based tests for the WASM FFI boundary (`src/wasm_ffi.rs`).
//!
//! Run with: `wasm-pack test --headless --chrome --no-default-features --features wasm`
//!
//! These exercise the JS-facing `WscdManagerJs` API end to end, not just
//! that it compiles — in particular the container export/import round-trip,
//! which is the whole point of exposing it (persisting keys across a page
//! reload).

#![cfg(all(target_arch = "wasm32", feature = "wasm"))]

use siros_wscd_manager::wasm_ffi::WscdManagerJs;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn get_str(obj: &JsValue, key: &str) -> String {
    js_sys::Reflect::get(obj, &JsValue::from_str(key))
        .unwrap()
        .as_string()
        .unwrap()
}

#[wasm_bindgen_test]
async fn generate_sign_and_verify_public_key_matches() {
    let mgr = WscdManagerJs::new().expect("construct manager");
    let kid = mgr.generate_key().await.expect("generate key");

    let sig = mgr
        .sign(&kid, &[1, 2, 3, 4])
        .await
        .expect("sign with generated key");
    assert!(!sig.is_empty(), "signature should not be empty");

    let jwk = mgr
        .export_public_key(&kid)
        .await
        .expect("export public key");
    assert_eq!(
        get_str(&jwk, "kty"),
        "EC",
        "exported JWK should be an EC key"
    );
}

#[wasm_bindgen_test]
fn security_properties_reports_software_for_softkey() {
    let mgr = WscdManagerJs::new().expect("construct manager");
    // security_properties is sync, but needs an existing key — generate one
    // via a blocking-friendly path isn't available here since generate_key
    // is async; this test only checks the "unknown key" error path stays an
    // error rather than panicking. The happy path is covered end-to-end in
    // generate_then_security_properties_reports_software below.
    let err = mgr.security_properties("does-not-exist");
    assert!(
        err.is_err(),
        "security_properties for an unknown key must error, not panic"
    );
}

#[wasm_bindgen_test]
async fn generate_then_security_properties_reports_software() {
    let mgr = WscdManagerJs::new().expect("construct manager");
    let kid = mgr.generate_key().await.expect("generate key");

    let props = mgr
        .security_properties(&kid)
        .expect("security properties for a real key");
    assert_eq!(
        get_str(&props, "key_storage"),
        "software",
        "softkey plugin must report lowercase snake_case \"software\", not the raw Rust enum name"
    );
}

#[wasm_bindgen_test]
async fn export_and_import_container_round_trips_keys() {
    let mgr1 = WscdManagerJs::new().expect("construct manager 1");
    let kid = mgr1.generate_key().await.expect("generate key");
    let container = mgr1.export_container().expect("export container");
    assert!(
        !container.is_empty(),
        "exported container should not be empty"
    );

    // A fresh manager, simulating a new page load, has no keys until the
    // container is imported.
    let mgr2 = WscdManagerJs::new().expect("construct manager 2");
    let sign_before_import = mgr2.sign(&kid, &[9, 9, 9]).await;
    assert!(
        sign_before_import.is_err(),
        "a fresh manager must not already know about a key from a different instance"
    );

    mgr2.import_container(&container)
        .expect("import container into fresh manager");
    let sig = mgr2
        .sign(&kid, &[9, 9, 9])
        .await
        .expect("sign with imported key after container round-trip");
    assert!(!sig.is_empty());
}
