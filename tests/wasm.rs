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

// ─── FIDO2 previewSign plugin over WebAuthn ─────────────────────────────────

fn js_array_of_strings(v: &JsValue) -> Vec<String> {
    js_sys::Array::from(v)
        .iter()
        .map(|x| x.as_string().unwrap())
        .collect()
}

#[wasm_bindgen_test]
fn fresh_manager_has_only_softkey() {
    let mgr = WscdManagerJs::new().expect("construct manager");
    assert_eq!(
        js_array_of_strings(&mgr.plugin_ids().unwrap()),
        vec!["softkey".to_string()]
    );
    let err = mgr.export_fido2_state();
    assert!(
        err.is_err(),
        "exportFido2State before registerFido2 must be an error, not a panic"
    );
}

#[wasm_bindgen_test]
async fn generate_on_unregistered_fido2_is_a_no_plugin_error() {
    let mgr = WscdManagerJs::new().expect("construct manager");
    let err = mgr
        .generate_key_with_plugin("fido2")
        .await
        .expect_err("fido2 is not registered yet");
    let msg = format!("{:?}", JsValue::from(err));
    assert!(
        msg.contains("no plugin found"),
        "expected the manager's NoPlugin error, got: {msg}"
    );
}

#[wasm_bindgen_test]
async fn register_fido2_makes_the_plugin_reachable_from_js() {
    let mgr = WscdManagerJs::new().expect("construct manager");
    mgr.register_fido2().expect("register fido2");
    assert_eq!(
        js_array_of_strings(&mgr.plugin_ids().unwrap()),
        vec!["fido2".to_string(), "softkey".to_string()]
    );

    // With the plugin registered, generateKeyWithPlugin("fido2") reaches the
    // WebAuthn transport. Headless Chrome has no authenticator (and no user
    // gesture), so navigator.credentials.create() rejects - but the error is
    // the browser's, proving dispatch went to the fido2 plugin and not to
    // the manager's "no plugin found".
    let err = mgr
        .generate_key_with_plugin("fido2")
        .await
        .expect_err("no authenticator in headless Chrome");
    let msg = format!("{:?}", JsValue::from(err));
    assert!(
        !msg.contains("no plugin found"),
        "dispatch must reach the fido2 plugin, got: {msg}"
    );
    // ...and get past the plugin's own gates: no PIN prompt (the browser
    // performs UV) and no CTAP2 ClientPin exchange (which this transport
    // has no command for). What is left is the browser's own rejection.
    for gate in ["cancelled", "unsupported CTAP2 command", "PIN"] {
        assert!(
            !msg.contains(gate),
            "the ceremony must reach navigator.credentials, but stopped at '{gate}': {msg}"
        );
    }

    // Softkey keeps working next to it, and is still the default.
    let kid = mgr.generate_key().await.expect("softkey generate");
    let props = mgr.security_properties(&kid).unwrap();
    assert_eq!(get_str(&props, "key_storage"), "software");
}

#[wasm_bindgen_test]
fn fido2_state_round_trips_through_export_and_register_with_state() {
    let mgr1 = WscdManagerJs::new().expect("construct manager 1");
    mgr1.register_fido2().expect("register fido2");
    let state = mgr1.export_fido2_state().expect("export empty fido2 state");
    assert!(
        !state.is_empty(),
        "even an empty key set serialises to something"
    );

    let mgr2 = WscdManagerJs::new().expect("construct manager 2");
    mgr2.register_fido2_with_state(&state)
        .expect("restore fido2 plugin from exported state");
    assert_eq!(
        js_array_of_strings(&mgr2.plugin_ids().unwrap()),
        vec!["fido2".to_string(), "softkey".to_string()]
    );
    assert_eq!(
        mgr2.export_fido2_state().unwrap(),
        state,
        "restored state re-exports byte-identical"
    );

    let garbage = mgr2.register_fido2_with_state(b"not a state blob");
    assert!(garbage.is_err(), "a corrupt blob is an error, not a panic");
}
