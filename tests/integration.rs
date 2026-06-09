#[cfg(test)]
mod tests {
    use siros_wscd_manager::callbacks::{AuthCallback, NoopProgress, ProgressCallback};
    use siros_wscd_manager::config::WscdConfig;
    use siros_wscd_manager::error::{Result, WscdError};
    use siros_wscd_manager::manager::WscdManager;
    use siros_wscd_manager::plugins::softkey::SoftkeyPlugin;
    use siros_wscd_manager::traits::WscdPlugin;
    use siros_wscd_manager::types::{Algorithm, MigrationResult, OperationProgress};
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    /// Stub AuthCallback that always returns a dummy PIN.
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

    /// Progress callback that records events.
    struct RecordingProgress {
        events: Mutex<Vec<String>>,
    }

    impl RecordingProgress {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }

        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ProgressCallback for RecordingProgress {
        async fn on_progress(&self, progress: OperationProgress) {
            let desc = match &progress {
                OperationProgress::Started { operation } => format!("started:{operation}"),
                OperationProgress::NetworkRoundTrip { step, total } => {
                    format!("network:{step}/{total}")
                }
                OperationProgress::WaitingForUser => "waiting_for_user".into(),
                OperationProgress::Complete => "complete".into(),
            };
            self.events.lock().unwrap().push(desc);
        }
    }

    #[tokio::test]
    async fn softkey_generate_and_sign() {
        let plugin = SoftkeyPlugin::new();
        let auth = StubAuth;
        let progress = RecordingProgress::new();

        // Generate a key
        let gen = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .expect("generate_key failed");

        assert!(gen.kid.as_str().starts_with("sw-"));
        assert!(gen.public_key_jwk.get("kty").is_some());
        assert_eq!(gen.public_key_jwk["kty"], "EC");
        assert_eq!(gen.public_key_jwk["crv"], "P-256");

        // Verify progress events
        let events = progress.events();
        assert_eq!(events[0], "started:generate_key");
        assert_eq!(events[1], "complete");

        // Sign some data
        let data = b"hello EUDIW";
        let sig = plugin
            .sign(&gen.kid, data, Algorithm::ES256, &auth, &progress)
            .await
            .expect("sign failed");

        // P-256 ECDSA signature is 64 bytes (r || s)
        assert_eq!(sig.0.len(), 64);

        // Verify signature
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        use p256::PublicKey;
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        use p256::EncodedPoint;
        use base64ct::{Base64UrlUnpadded, Encoding};

        let x_bytes = Base64UrlUnpadded::decode_vec(
            gen.public_key_jwk["x"].as_str().unwrap(),
        )
        .unwrap();
        let y_bytes = Base64UrlUnpadded::decode_vec(
            gen.public_key_jwk["y"].as_str().unwrap(),
        )
        .unwrap();
        let point = EncodedPoint::from_affine_coordinates(
            x_bytes.as_slice().into(),
            y_bytes.as_slice().into(),
            false,
        );
        let pubkey = PublicKey::from_encoded_point(&point).unwrap();
        let vk = VerifyingKey::from(pubkey);
        let signature = Signature::from_bytes(sig.0.as_slice().into()).unwrap();
        vk.verify(data, &signature).expect("signature verification failed");
    }

    #[tokio::test]
    async fn softkey_list_and_delete() {
        let plugin = SoftkeyPlugin::new();
        let auth = StubAuth;
        let progress = NoopProgress;

        let gen1 = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();
        let gen2 = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();

        let keys = plugin.list_keys().await.unwrap();
        assert_eq!(keys.len(), 2);

        plugin.delete_key(&gen1.kid).await.unwrap();
        let keys = plugin.list_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, gen2.kid);

        // Signing with deleted key should fail
        let err = plugin
            .sign(&gen1.kid, b"test", Algorithm::ES256, &auth, &progress)
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn softkey_export_import_container() {
        let plugin = SoftkeyPlugin::new();
        let auth = StubAuth;
        let progress = NoopProgress;

        let gen = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();

        // Sign with original
        let sig1 = plugin
            .sign(&gen.kid, b"test", Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();

        // Export and reimport
        let container = plugin.export_container().unwrap();
        let plugin2 = SoftkeyPlugin::from_container(&container).unwrap();

        // Sign with restored — same key, same signature
        let sig2 = plugin2
            .sign(&gen.kid, b"test", Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();

        // Deterministic signatures? ECDSA with RFC 6979 should be deterministic
        assert_eq!(sig1.0, sig2.0);

        // Generate another key in restored plugin — ID should not collide
        let gen2 = plugin2
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();
        assert_ne!(gen.kid, gen2.kid);
    }

    #[tokio::test]
    async fn manager_routing() {
        let mut manager = WscdManager::new(WscdConfig::default());
        let softkey = Arc::new(SoftkeyPlugin::new());
        manager.register_plugin(softkey);

        let auth = StubAuth;
        let progress = NoopProgress;

        // Generate via manager
        let gen = manager
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();

        // Sign via manager — should route to softkey
        let sig = manager
            .sign(&gen.kid, b"managed", Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();
        assert_eq!(sig.0.len(), 64);

        // List keys via manager
        let keys = manager.list_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].plugin_id, "softkey");

        // Delete via manager
        manager.delete_key(&gen.kid).await.unwrap();
        let keys = manager.list_keys().await.unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[tokio::test]
    async fn manager_migration_between_softkeys() {
        // Two softkey plugins simulating migration
        let mut manager = WscdManager::new(WscdConfig {
            default_plugin: "softkey-a".into(),
            ..Default::default()
        });

        // Create two softkey instances with different IDs
        let plugin_a = Arc::new(SoftkeyPluginNamed::new("softkey-a"));
        let plugin_b = Arc::new(SoftkeyPluginNamed::new("softkey-b"));
        manager.register_plugin(plugin_a);
        manager.register_plugin(plugin_b);

        let auth = StubAuth;
        let progress = NoopProgress;

        let gen = manager
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();

        // Migrate to plugin-b
        let result = manager
            .migrate_key(&gen.kid, "softkey-b", &auth)
            .await
            .unwrap();

        match result {
            MigrationResult::Migrated { new_kid } => {
                assert!(new_kid.as_str().starts_with("sw-"));
            }
            MigrationResult::ReEnrollmentRequired { .. } => {
                panic!("expected Migrated, got ReEnrollmentRequired");
            }
        }
    }

    /// A named wrapper around SoftkeyPlugin for testing multi-plugin scenarios.
    struct SoftkeyPluginNamed {
        name: String,
        inner: SoftkeyPlugin,
    }

    impl SoftkeyPluginNamed {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                inner: SoftkeyPlugin::new(),
            }
        }
    }

    #[async_trait]
    impl siros_wscd_manager::WscdPlugin for SoftkeyPluginNamed {
        fn id(&self) -> &str {
            &self.name
        }

        fn display_name(&self) -> &str {
            &self.name
        }

        fn auth_method(&self) -> siros_wscd_manager::AuthMethod {
            siros_wscd_manager::AuthMethod::None
        }

        async fn generate_key(
            &self,
            algorithm: Algorithm,
            auth: &dyn AuthCallback,
            progress: &dyn ProgressCallback,
        ) -> Result<siros_wscd_manager::GeneratedKey> {
            self.inner.generate_key(algorithm, auth, progress).await
        }

        async fn sign(
            &self,
            kid: &siros_wscd_manager::KeyId,
            data: &[u8],
            algorithm: Algorithm,
            auth: &dyn AuthCallback,
            progress: &dyn ProgressCallback,
        ) -> Result<siros_wscd_manager::Signature> {
            self.inner.sign(kid, data, algorithm, auth, progress).await
        }

        async fn list_keys(&self) -> Result<Vec<siros_wscd_manager::KeyInfo>> {
            let mut keys = self.inner.list_keys().await?;
            for k in &mut keys {
                k.plugin_id = self.name.clone();
            }
            Ok(keys)
        }

        async fn attestation_chain(
            &self,
            kid: &siros_wscd_manager::KeyId,
        ) -> Result<Option<siros_wscd_manager::AttestationChain>> {
            self.inner.attestation_chain(kid).await
        }

        async fn delete_key(&self, kid: &siros_wscd_manager::KeyId) -> Result<()> {
            self.inner.delete_key(kid).await
        }

        async fn export_public_key(
            &self,
            kid: &siros_wscd_manager::KeyId,
        ) -> Result<serde_json::Value> {
            self.inner.export_public_key(kid).await
        }

        fn supports_import(&self) -> bool {
            true
        }

        async fn import_key(
            &self,
            algorithm: Algorithm,
            auth: &dyn AuthCallback,
            progress: &dyn ProgressCallback,
        ) -> Result<MigrationResult> {
            self.inner.import_key(algorithm, auth, progress).await
        }
    }

    #[tokio::test]
    async fn softkey_no_attestation() {
        let plugin = SoftkeyPlugin::new();
        let auth = StubAuth;
        let progress = NoopProgress;

        let gen = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();

        let chain = plugin.attestation_chain(&gen.kid).await.unwrap();
        assert!(chain.is_none(), "software keys have no attestation");
    }
}
