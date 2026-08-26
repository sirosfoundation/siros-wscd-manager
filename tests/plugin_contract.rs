//! Two things the individual plugin test suites cannot check on their own:
//! how [`WscdManager`] decides *which* plugin serves an operation, and
//! whether the plugins agree with each other about the [`WscdPlugin`]
//! contract.
//!
//! Both matter because the manager is the only thing standing between a
//! caller's `kid` and the backend that holds the corresponding private key.
//! A resolution bug does not fail loudly — it signs with a real key that is
//! simply the wrong one, and the caller learns about it when a verifier
//! rejects the credential.

use async_trait::async_trait;
use std::sync::{Arc, Mutex};

use siros_wscd_manager::callbacks::{AuthCallback, NoopProgress, ProgressCallback};
use siros_wscd_manager::config::WscdConfig;
use siros_wscd_manager::error::{Result, WscdError};
use siros_wscd_manager::manager::WscdManager;
use siros_wscd_manager::plugins::softkey::SoftkeyPlugin;
use siros_wscd_manager::traits::WscdPlugin;
use siros_wscd_manager::types::{
    Algorithm, AttestationChain, AuthMethod, CertificationLevel, GeneratedKey, KeyId, KeyInfo,
    KeyStorageType, Secret, SecurityProperties, Signature,
};

struct StubAuth;

#[async_trait]
impl AuthCallback for StubAuth {
    async fn request_pin(&self, _plugin_id: &str) -> Result<Secret> {
        Ok(Secret(b"1234".to_vec()))
    }
    async fn request_webauthn_assertion(
        &self,
        _plugin_id: &str,
        _challenge: &[u8],
        _rp_id: &str,
        _allowed_credentials: &[Vec<u8>],
    ) -> Result<Vec<u8>> {
        Err(WscdError::Unsupported {
            plugin: "stub".into(),
            op: "webauthn".into(),
        })
    }
}

/// A plugin that does nothing but record which of its methods the manager
/// called. Every operation succeeds, so a routing test fails on the *wrong
/// plugin having been asked*, not on an error — which is the shape the real
/// bug takes.
struct RecordingPlugin {
    id: String,
    calls: Mutex<Vec<String>>,
}

impl RecordingPlugin {
    fn new(id: &str) -> Arc<Self> {
        Arc::new(Self {
            id: id.to_string(),
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn record(&self, op: &str) {
        self.calls.lock().unwrap().push(op.to_string());
    }
}

#[async_trait]
impl WscdPlugin for RecordingPlugin {
    fn id(&self) -> &str {
        &self.id
    }
    fn display_name(&self) -> &str {
        &self.id
    }
    fn auth_method(&self) -> AuthMethod {
        AuthMethod::None
    }

    async fn generate_key(
        &self,
        _algorithm: Algorithm,
        _auth: &dyn AuthCallback,
        _progress: &dyn ProgressCallback,
    ) -> Result<GeneratedKey> {
        self.record("generate_key");
        Ok(GeneratedKey {
            kid: KeyId(format!("{}-key", self.id)),
            public_key_jwk: serde_json::json!({ "kty": "EC", "plugin": self.id }),
        })
    }

    async fn sign(
        &self,
        _kid: &KeyId,
        _data: &[u8],
        _algorithm: Algorithm,
        _auth: &dyn AuthCallback,
        _progress: &dyn ProgressCallback,
    ) -> Result<Signature> {
        self.record("sign");
        Ok(Signature(self.id.as_bytes().to_vec()))
    }

    async fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        self.record("list_keys");
        Ok(vec![])
    }

    async fn attestation_chain(&self, _kid: &KeyId) -> Result<Option<AttestationChain>> {
        self.record("attestation_chain");
        Ok(None)
    }

    async fn delete_key(&self, _kid: &KeyId) -> Result<()> {
        self.record("delete_key");
        Ok(())
    }

    async fn export_public_key(&self, _kid: &KeyId) -> Result<serde_json::Value> {
        self.record("export_public_key");
        Ok(serde_json::json!({ "plugin": self.id }))
    }

    fn security_properties(&self, _kid: &KeyId) -> Result<SecurityProperties> {
        self.record("security_properties");
        Ok(SecurityProperties {
            key_storage: KeyStorageType::Software,
            user_authentication: vec![],
            certification: CertificationLevel::None,
            amr: vec![self.id.clone()],
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// The documented resolution chain (see [`WscdManager`]'s doc comment):
/// per-key binding, then per-operation default, then the global default.
///
/// Untested until now, and the failure mode is the worst one this crate has:
/// a signature produced with a real key that is not the key the caller named.
/// Nothing errors, nothing logs; the credential simply fails verification
/// wherever it is eventually presented. Each of the three levels is asserted
/// with the other two pointing somewhere else, so an inverted precedence
/// cannot pass by coincidence.
#[tokio::test]
async fn resolution_prefers_key_binding_then_operation_default_then_global() {
    let bound = RecordingPlugin::new("bound");
    let per_op = RecordingPlugin::new("per-op");
    let global = RecordingPlugin::new("global");

    let mut config = WscdConfig {
        default_plugin: "global".into(),
        ..Default::default()
    };
    config
        .operation_defaults
        .insert("sign".into(), "per-op".into());
    config
        .key_bindings
        .insert(KeyId("bound-key".into()), "bound".into());

    let mut manager = WscdManager::new(config);
    manager.register_plugin(bound.clone());
    manager.register_plugin(per_op.clone());
    manager.register_plugin(global.clone());

    // 1. A key with an explicit binding goes there, even though "sign" has
    //    its own default.
    let sig = manager
        .sign(
            &KeyId("bound-key".into()),
            b"x",
            Algorithm::ES256,
            &StubAuth,
            &NoopProgress,
        )
        .await
        .unwrap();
    assert_eq!(
        sig.0, b"bound",
        "a per-key binding must win over everything"
    );

    // 2. An unbound key falls to the per-operation default, not the global.
    let sig = manager
        .sign(
            &KeyId("unbound-key".into()),
            b"x",
            Algorithm::ES256,
            &StubAuth,
            &NoopProgress,
        )
        .await
        .unwrap();
    assert_eq!(sig.0, b"per-op");

    // 3. An operation with no per-operation default falls to the global one.
    let jwk = manager
        .export_public_key(&KeyId("unbound-key".into()))
        .await
        .unwrap();
    assert_eq!(jwk["plugin"], "global");

    assert_eq!(bound.calls(), vec!["sign"]);
    assert_eq!(per_op.calls(), vec!["sign"]);
    assert_eq!(global.calls(), vec!["export_public_key"]);
}

/// Generating a key must bind it to the plugin that produced it, and
/// deleting it must release that binding.
///
/// The binding is what makes `sign(kid)` reach the right backend when more
/// than one plugin is registered — the WASM manager runs softkey and FIDO2
/// side by side and relies on exactly this. A stale binding left behind
/// after a delete is worse than useless: the kid can be reissued by another
/// plugin later and would then be routed to the plugin that no longer has it.
#[tokio::test]
async fn generate_binds_the_key_to_its_plugin_and_delete_releases_it() {
    let a = RecordingPlugin::new("a");
    let b = RecordingPlugin::new("b");
    let mut manager = WscdManager::new(WscdConfig {
        default_plugin: "a".into(),
        ..Default::default()
    });
    manager.register_plugin(a.clone());
    manager.register_plugin(b.clone());

    // Explicitly generate on the non-default plugin.
    let gen = manager
        .generate_key_with_plugin("b", Algorithm::ES256, &StubAuth, &NoopProgress)
        .await
        .unwrap();
    assert_eq!(
        manager
            .config()
            .key_bindings
            .get(&gen.kid)
            .map(String::as_str),
        Some("b"),
    );

    // Signing that key reaches "b", not the default "a".
    let sig = manager
        .sign(&gen.kid, b"x", Algorithm::ES256, &StubAuth, &NoopProgress)
        .await
        .unwrap();
    assert_eq!(
        sig.0, b"b",
        "the binding recorded at generation must be used"
    );

    manager.delete_key(&gen.kid).await.unwrap();
    assert!(
        !manager.config().key_bindings.contains_key(&gen.kid),
        "a deleted key must not leave its plugin binding behind"
    );

    // Naming a plugin that was never registered is an error rather than a
    // fallback to whatever happens to be the default.
    assert!(manager
        .generate_key_with_plugin("nope", Algorithm::ES256, &StubAuth, &NoopProgress)
        .await
        .is_err());
}

/// A misconfigured `default_plugin` must fail, not quietly pick the only
/// plugin that happens to be registered.
///
/// Silently substituting would mean a config typo routes every key to a
/// backend the operator did not choose — plausibly a software key store
/// where a hardware one was intended, with no error anywhere to say so.
#[tokio::test]
async fn an_unregistered_default_plugin_is_an_error_not_a_fallback() {
    let mut manager = WscdManager::new(WscdConfig {
        default_plugin: "hardware".into(),
        ..Default::default()
    });
    manager.register_plugin(Arc::new(SoftkeyPlugin::new()));

    let err = manager
        .generate_key(Algorithm::ES256, &StubAuth, &NoopProgress)
        .await
        .expect_err("an unknown default plugin must not silently resolve");
    assert!(matches!(err, WscdError::NoPlugin { .. }), "got {err:?}");

    assert!(manager
        .sign(
            &KeyId("k".into()),
            b"x",
            Algorithm::ES256,
            &StubAuth,
            &NoopProgress
        )
        .await
        .is_err());
    assert!(manager.security_properties(&KeyId("k".into())).is_err());
}

/// Every plugin must report an unknown key the same way.
///
/// `WscdManager` and the FFI layer above it map `KeyNotFound` to a distinct
/// host-visible error; a plugin that instead answered `Unsupported`, or
/// worse `Ok`, would make "this key was never enrolled here" indistinguishable
/// from "this backend cannot do that at all" — the two call for opposite
/// recovery (re-enroll vs. pick another plugin). Run as a sweep so a plugin
/// added later has to join the same contract.
#[tokio::test]
async fn unknown_keys_are_reported_uniformly_across_plugins() {
    let unknown = KeyId("no-such-key".into());

    // The FIDO2 transport is deliberately one that panics: none of these
    // calls may reach the authenticator at all. Asking hardware to look for a
    // key the plugin already knows nothing about is a user-visible tap
    // prompt for an operation that cannot succeed.
    struct UnreachableTransport;

    #[async_trait]
    impl siros_wscd_manager::callbacks::Ctap2Transport for UnreachableTransport {
        async fn ctap2_send_command(&self, _command: &[u8]) -> Result<Vec<u8>> {
            panic!("an unknown key must be rejected without touching the authenticator");
        }
    }

    let plugins: Vec<Arc<dyn WscdPlugin>> = vec![
        Arc::new(SoftkeyPlugin::new()),
        Arc::new(
            siros_wscd_manager::plugins::preview_sign::PreviewSignPlugin::new(Box::new(
                UnreachableTransport,
            )),
        ),
    ];

    for plugin in plugins {
        let id = plugin.id().to_string();

        let err = plugin
            .sign(&unknown, b"x", Algorithm::ES256, &StubAuth, &NoopProgress)
            .await
            .expect_err("{id}: sign on an unknown key must fail");
        assert!(
            matches!(err, WscdError::KeyNotFound { .. }),
            "{id}: sign gave {err:?}"
        );

        let err = plugin
            .export_public_key(&unknown)
            .await
            .expect_err("export_public_key on an unknown key must fail");
        assert!(
            matches!(err, WscdError::KeyNotFound { .. }),
            "{id}: export_public_key gave {err:?}"
        );

        let err = plugin
            .security_properties(&unknown)
            .expect_err("security_properties on an unknown key must fail");
        assert!(
            matches!(err, WscdError::KeyNotFound { .. }),
            "{id}: security_properties gave {err:?}"
        );

        let err = plugin
            .delete_key(&unknown)
            .await
            .expect_err("delete_key on an unknown key must fail");
        assert!(
            matches!(err, WscdError::KeyNotFound { .. }),
            "{id}: delete_key gave {err:?}"
        );

        // Lifecycle contexts follow the same rule: an unknown context is
        // KeyNotFound, not a default-constructed status.
        if plugin.supports_lifecycle() {
            let err = plugin
                .lifecycle_status("no-such-context")
                .await
                .expect_err("lifecycle_status on an unknown context must fail");
            assert!(
                matches!(err, WscdError::KeyNotFound { .. }),
                "{id}: lifecycle_status gave {err:?}"
            );
        }
    }
}

/// The default `WscdPlugin` methods must refuse rather than pretend.
///
/// `import_key` and the four lifecycle operations have trait-level defaults
/// that return `Unsupported`. A plugin that does not override them must
/// surface that, because the manager's `migrate_key` decides between
/// "migrated" and "re-enrollment required" on `supports_import()` alone — if
/// the default ever returned `Ok`, a migration would report success while no
/// key had been created anywhere.
#[tokio::test]
async fn trait_defaults_refuse_unimplemented_operations() {
    let plugin = RecordingPlugin::new("minimal");
    assert!(!plugin.supports_import());
    assert!(!plugin.supports_lifecycle());

    let err = plugin
        .import_key(Algorithm::ES256, &StubAuth, &NoopProgress)
        .await
        .expect_err("the default import_key must refuse");
    assert!(matches!(err, WscdError::Unsupported { .. }), "got {err:?}");

    assert!(plugin.lifecycle_status("ctx").await.is_err());
    assert!(
        plugin.calls().is_empty(),
        "no backend call should have happened"
    );
}
