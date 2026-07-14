/// Softkey plugin extended integration tests
///
/// Covers gaps not addressed in tests/integration.rs:
///   - EdDSA (Ed25519) key generation and signing
///   - export_public_key JWK fields (EC and OKP)
///   - container-based import roundtrip
///   - attestation_chain returns None for software keys
///   - multi-key: ES256 and EdDSA coexist and sign independently
///   - rotate_lifecycle via WscdManager produces new key context
///   - container with multiple algorithms survives full roundtrip
#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use siros_wscd_manager::callbacks::{AuthCallback, NoopProgress};
    use siros_wscd_manager::config::WscdConfig;
    use siros_wscd_manager::error::{Result, WscdError};
    use siros_wscd_manager::manager::WscdManager;
    use siros_wscd_manager::plugins::softkey::SoftkeyPlugin;
    use siros_wscd_manager::traits::WscdPlugin;
    use siros_wscd_manager::types::{
        ActivateLifecycleRequest, Algorithm, DestroyLifecycleRequest, DestroyMode, FactorKind,
        KeyInfo, LifecycleState, RegisterLifecycleRequest, RotateLifecycleRequest,
    };
    use std::sync::Arc;

    struct StubAuth;

    #[async_trait]
    impl AuthCallback for StubAuth {
        async fn request_pin(&self) -> Result<Vec<u8>> {
            Ok(b"1234".to_vec())
        }
        async fn request_webauthn_assertion(
            &self,
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

    // ─── EdDSA generate and sign ─────────────────────────────────────────────

    #[tokio::test]
    async fn softkey_eddsa_generate_and_sign() {
        let plugin = SoftkeyPlugin::new();
        let auth = StubAuth;
        let progress = NoopProgress;

        let key = plugin
            .generate_key(Algorithm::EdDSA, &auth, &progress)
            .await
            .expect("EdDSA key generation");

        assert!(!key.kid.0.is_empty());

        let sig = plugin
            .sign(
                &key.kid,
                b"hello ed25519",
                Algorithm::EdDSA,
                &auth,
                &progress,
            )
            .await
            .expect("EdDSA sign");

        // Ed25519 produces a fixed-size 64-byte signature
        assert_eq!(
            sig.0.len(),
            64,
            "Ed25519 signature must be exactly 64 bytes"
        );
    }

    // ─── export_public_key — P-256 ───────────────────────────────────────────

    #[tokio::test]
    async fn softkey_export_public_key_ec() {
        let plugin = SoftkeyPlugin::new();
        let auth = StubAuth;
        let progress = NoopProgress;

        let key = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .expect("ES256 key gen");

        let jwk: serde_json::Value = plugin
            .export_public_key(&key.kid)
            .await
            .expect("export_public_key");

        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk["x"].is_string(), "x coordinate required");
        assert!(jwk["y"].is_string(), "y coordinate required");
        assert!(
            jwk.get("d").is_none(),
            "private scalar must not be exported"
        );
    }

    // ─── export_public_key — Ed25519 (OKP) ───────────────────────────────────

    #[tokio::test]
    async fn softkey_export_public_key_eddsa() {
        let plugin = SoftkeyPlugin::new();
        let auth = StubAuth;
        let progress = NoopProgress;

        let key = plugin
            .generate_key(Algorithm::EdDSA, &auth, &progress)
            .await
            .expect("EdDSA key gen");

        let jwk: serde_json::Value = plugin
            .export_public_key(&key.kid)
            .await
            .expect("export_public_key");

        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert!(jwk["x"].is_string(), "public key bytes required");
        assert!(jwk.get("d").is_none(), "private key must not be exported");
    }

    // ─── container import: key generated in one instance, signed in another ──

    #[tokio::test]
    async fn softkey_import_via_container() {
        let auth = StubAuth;
        let progress = NoopProgress;
        let src = SoftkeyPlugin::new();

        let key = src
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .expect("generate");

        let container = src.export_container().expect("export");
        let dst = SoftkeyPlugin::from_container(&container).expect("from_container");

        let sig = dst
            .sign(&key.kid, b"roundtrip", Algorithm::ES256, &auth, &progress)
            .await
            .expect("sign after import");

        assert!(!sig.0.is_empty());
    }

    // ─── attestation_chain returns None for software keys ────────────────────

    #[tokio::test]
    async fn softkey_attestation_chain_is_none() {
        let plugin = SoftkeyPlugin::new();
        let auth = StubAuth;
        let progress = NoopProgress;

        let key = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .expect("generate");

        let chain = plugin
            .attestation_chain(&key.kid)
            .await
            .expect("attestation_chain should not error");

        assert!(chain.is_none(), "softkey has no hardware attestation");
    }

    // ─── multi-key: ES256 and EdDSA coexist and sign independently ───────────

    #[tokio::test]
    async fn softkey_multi_key_sign_independently() {
        let plugin = SoftkeyPlugin::new();
        let auth = StubAuth;
        let progress = NoopProgress;

        let k1 = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .expect("k1 ES256");
        let k2 = plugin
            .generate_key(Algorithm::EdDSA, &auth, &progress)
            .await
            .expect("k2 EdDSA");

        assert_ne!(k1.kid.0, k2.kid.0, "kid collision");

        let s1 = plugin
            .sign(&k1.kid, b"msg-for-k1", Algorithm::ES256, &auth, &progress)
            .await
            .expect("sign k1");
        let s2 = plugin
            .sign(&k2.kid, b"msg-for-k2", Algorithm::EdDSA, &auth, &progress)
            .await
            .expect("sign k2");

        assert!(!s1.0.is_empty());
        assert!(!s2.0.is_empty());
        assert_ne!(s1.0, s2.0);

        let keys: Vec<KeyInfo> = plugin.list_keys().await.expect("list");
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().any(|k| k.kid == k1.kid));
        assert!(keys.iter().any(|k| k.kid == k2.kid));
    }

    // ─── rotate_lifecycle via WscdManager ────────────────────────────────────

    #[tokio::test]
    async fn softkey_rotate_lifecycle_via_manager() {
        let mut manager = WscdManager::new(WscdConfig::default());
        manager.register_plugin(Arc::new(SoftkeyPlugin::new()));

        let auth = StubAuth;
        let progress = NoopProgress;
        let ctx = "ctx-rotate-extended";

        let reg = manager
            .register_lifecycle(
                &RegisterLifecycleRequest {
                    plugin_id: "softkey".into(),
                    context_id: ctx.into(),
                    factor_kind: FactorKind::Opaque,
                },
                &auth,
                &progress,
            )
            .await
            .expect("register");

        assert_eq!(reg.state, LifecycleState::Registered);

        manager
            .activate_lifecycle(
                &ActivateLifecycleRequest {
                    plugin_id: "softkey".into(),
                    context_id: ctx.into(),
                },
                &auth,
                &progress,
            )
            .await
            .expect("activate");

        let rotated = manager
            .rotate_lifecycle(
                &RotateLifecycleRequest {
                    plugin_id: "softkey".into(),
                    context_id: ctx.into(),
                },
                &auth,
                &progress,
            )
            .await
            .expect("rotate");

        // After rotation the context should still be active
        assert_eq!(rotated.state, LifecycleState::Active);

        let status = manager
            .lifecycle_status("softkey", ctx)
            .await
            .expect("status after rotate");
        assert_eq!(status.state, LifecycleState::Active);

        // Tear down
        manager
            .destroy_lifecycle(
                &DestroyLifecycleRequest {
                    plugin_id: "softkey".into(),
                    context_id: ctx.into(),
                    mode: DestroyMode::LocalOnly,
                    reason: None,
                },
                &auth,
                &progress,
            )
            .await
            .expect("destroy");
    }

    // ─── container with multiple algorithms survives roundtrip ───────────────

    #[tokio::test]
    async fn softkey_container_multi_alg_roundtrip() {
        let plugin = SoftkeyPlugin::new();
        let auth = StubAuth;
        let progress = NoopProgress;

        let k1 = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .expect("k1");
        let k2 = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .expect("k2");
        let k3 = plugin
            .generate_key(Algorithm::EdDSA, &auth, &progress)
            .await
            .expect("k3");

        let container = plugin.export_container().expect("export");
        let restored = SoftkeyPlugin::from_container(&container).expect("restore");

        let restored_keys: Vec<KeyInfo> = restored.list_keys().await.expect("list");
        assert_eq!(
            restored_keys.len(),
            3,
            "all 3 keys survive container roundtrip"
        );

        for (kid, alg) in [
            (&k1.kid, Algorithm::ES256),
            (&k2.kid, Algorithm::ES256),
            (&k3.kid, Algorithm::EdDSA),
        ] {
            assert!(
                restored_keys.iter().any(|k| &k.kid == kid),
                "kid {} missing after restore",
                kid.0
            );
            restored
                .sign(kid, b"restore-check", alg, &auth, &progress)
                .await
                .unwrap_or_else(|e| panic!("sign after restore for {}: {}", kid.0, e));
        }
    }
}
