#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use siros_wscd_manager::callbacks::{AuthCallback, NoopProgress, ProgressCallback};
    use siros_wscd_manager::config::WscdConfig;
    use siros_wscd_manager::error::{Result, WscdError};
    use siros_wscd_manager::manager::WscdManager;
    use siros_wscd_manager::plugins::softkey::SoftkeyPlugin;
    use siros_wscd_manager::traits::WscdPlugin;
    use siros_wscd_manager::types::{Algorithm, MigrationResult, OperationProgress};
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
        use base64ct::{Base64UrlUnpadded, Encoding};
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        use p256::EncodedPoint;
        use p256::PublicKey;

        let x_bytes =
            Base64UrlUnpadded::decode_vec(gen.public_key_jwk["x"].as_str().unwrap()).unwrap();
        let y_bytes =
            Base64UrlUnpadded::decode_vec(gen.public_key_jwk["y"].as_str().unwrap()).unwrap();
        let point = EncodedPoint::from_affine_coordinates(
            x_bytes.as_slice().into(),
            y_bytes.as_slice().into(),
            false,
        );
        let pubkey = PublicKey::from_encoded_point(&point).unwrap();
        let vk = VerifyingKey::from(pubkey);
        let signature = Signature::from_bytes(sig.0.as_slice().into()).unwrap();
        vk.verify(data, &signature)
            .expect("signature verification failed");
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

        fn security_properties(
            &self,
            kid: &siros_wscd_manager::KeyId,
        ) -> Result<siros_wscd_manager::SecurityProperties> {
            self.inner.security_properties(kid)
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

    #[tokio::test]
    async fn softkey_security_properties() {
        let plugin = SoftkeyPlugin::new();
        let auth = StubAuth;
        let progress = NoopProgress;

        let gen = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();

        let props = plugin.security_properties(&gen.kid).unwrap();
        assert_eq!(
            props.key_storage,
            siros_wscd_manager::KeyStorageType::Software
        );
        assert_eq!(
            props.certification,
            siros_wscd_manager::CertificationLevel::None
        );
        assert!(props.user_authentication.is_empty());
        assert_eq!(props.amr, vec!["swk"]);
    }

    // ── PreviewSign (FIDO2 rawSign) plugin tests ──────────────────────

    use base64ct::Encoding;
    use siros_wscd_manager::callbacks::Ctap2Transport;
    use siros_wscd_manager::plugins::preview_sign::PreviewSignPlugin;

    /// Mock CTAP2 transport that simulates a FIDO2 authenticator using
    /// software P-256 keys. This lets us test the plugin logic without
    /// a real authenticator.
    struct MockCtap2 {
        /// Stored credentials: (key_handle, signing_key_bytes)
        credentials: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    }

    impl MockCtap2 {
        fn new() -> Self {
            Self {
                credentials: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl Ctap2Transport for MockCtap2 {
        async fn ctap2_make_credential(
            &self,
            _client_data_hash: &[u8],
            _rp_id: &str,
            _user_id: &[u8],
            _algorithms: &[i64],
        ) -> Result<Vec<u8>> {
            use p256::ecdsa::SigningKey;
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            use p256::SecretKey;
            use rand::rngs::OsRng;

            // Generate a key pair
            let secret = SecretKey::random(&mut OsRng);
            let signing_key = SigningKey::from(secret.clone());
            let verifying_key = signing_key.verifying_key();
            let point = p256::PublicKey::from(verifying_key).to_encoded_point(false);

            let x = point.x().unwrap().to_vec();
            let y = point.y().unwrap().to_vec();

            // Create a fake key handle (just the secret key bytes)
            let key_handle = secret.to_bytes().to_vec();

            // Store the credential
            self.credentials
                .lock()
                .unwrap()
                .push((key_handle.clone(), secret.to_bytes().to_vec()));

            // Return JSON response matching the plugin's expected format
            let response = serde_json::json!({
                "key_handle": base64ct::Base64UrlUnpadded::encode_string(&key_handle),
                "public_key": {
                    "x": base64ct::Base64UrlUnpadded::encode_string(&x),
                    "y": base64ct::Base64UrlUnpadded::encode_string(&y),
                },
                "algorithm": -7,
                "attestation_object": base64ct::Base64UrlUnpadded::encode_string(b"mock-attestation"),
            });

            Ok(serde_json::to_vec(&response).unwrap())
        }

        async fn ctap2_get_assertion(
            &self,
            _rp_id: &str,
            _challenge: &[u8],
            sign_requests: &[(Vec<u8>, Vec<u8>)],
        ) -> Result<Vec<Vec<u8>>> {
            use p256::ecdsa::{signature::Signer, Signature, SigningKey};
            use p256::SecretKey;

            let creds = self.credentials.lock().unwrap();
            let mut signatures = Vec::new();

            for (key_handle, tbs) in sign_requests {
                // Find the credential by key handle
                let found = creds
                    .iter()
                    .find(|(kh, _)| kh == key_handle)
                    .ok_or_else(|| WscdError::KeyNotFound {
                        kid: "unknown credential".into(),
                    })?;

                let secret = SecretKey::from_slice(&found.1)
                    .map_err(|e| WscdError::Crypto(e.to_string()))?;
                let signing_key = SigningKey::from(secret);
                let sig: Signature = signing_key.sign(tbs);
                signatures.push(sig.to_bytes().to_vec());
            }

            Ok(signatures)
        }
    }

    #[tokio::test]
    async fn preview_sign_generate_and_sign() {
        let transport = Box::new(MockCtap2::new());
        let plugin = PreviewSignPlugin::new(transport);
        let auth = StubAuth;
        let progress = RecordingProgress::new();

        // Generate a key
        let gen = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .expect("generate_key failed");

        assert!(gen.kid.as_str().starts_with("fido-"));
        assert_eq!(gen.public_key_jwk["kty"], "EC");
        assert_eq!(gen.public_key_jwk["crv"], "P-256");

        // Check progress events include waiting_for_user
        let events = progress.events();
        assert!(events.contains(&"started:generate_key".to_string()));
        assert!(events.contains(&"waiting_for_user".to_string()));
        assert!(events.contains(&"complete".to_string()));

        // Sign data
        let data = b"FIDO2 rawSign test";
        let sig = plugin
            .sign(&gen.kid, data, Algorithm::ES256, &auth, &progress)
            .await
            .expect("sign failed");

        // Verify signature with the public key from generate_key
        use base64ct::{Base64UrlUnpadded, Encoding};
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        use p256::EncodedPoint;
        use p256::PublicKey;

        let x_bytes =
            Base64UrlUnpadded::decode_vec(gen.public_key_jwk["x"].as_str().unwrap()).unwrap();
        let y_bytes =
            Base64UrlUnpadded::decode_vec(gen.public_key_jwk["y"].as_str().unwrap()).unwrap();
        let point = EncodedPoint::from_affine_coordinates(
            x_bytes.as_slice().into(),
            y_bytes.as_slice().into(),
            false,
        );
        let pubkey = PublicKey::from_encoded_point(&point).unwrap();
        let vk = VerifyingKey::from(pubkey);
        let signature = Signature::from_bytes(sig.0.as_slice().into()).unwrap();
        vk.verify(data, &signature)
            .expect("FIDO2 signature verification failed");
    }

    #[tokio::test]
    async fn preview_sign_list_delete_attestation() {
        let transport = Box::new(MockCtap2::new());
        let plugin = PreviewSignPlugin::new(transport);
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

        // List keys
        let keys = plugin.list_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].plugin_id, "fido2");

        // Attestation should be present
        let chain = plugin.attestation_chain(&gen1.kid).await.unwrap();
        assert!(chain.is_some(), "FIDO2 keys should have attestation");
        assert_eq!(chain.unwrap().certificates.len(), 1);

        // Delete
        plugin.delete_key(&gen1.kid).await.unwrap();
        let keys = plugin.list_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, gen2.kid);

        // Sign with deleted key should fail
        let err = plugin
            .sign(&gen1.kid, b"test", Algorithm::ES256, &auth, &progress)
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn preview_sign_export_restore_state() {
        let transport1 = Box::new(MockCtap2::new());
        let plugin1 = PreviewSignPlugin::new(transport1);
        let auth = StubAuth;
        let progress = NoopProgress;

        let gen = plugin1
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();

        // Export state
        let state = plugin1.export_state().unwrap();

        // Restore into a new plugin (with a fresh transport that has
        // the same credentials — simulating reconnecting to the same
        // authenticator)
        let transport2 = Box::new(MockCtap2::new());
        let plugin2 = PreviewSignPlugin::from_state(transport2, &state).unwrap();

        // Keys should be restored
        let keys = plugin2.list_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, gen.kid);

        // Public key should match
        let pub_jwk = plugin2.export_public_key(&gen.kid).await.unwrap();
        assert_eq!(pub_jwk["x"], gen.public_key_jwk["x"]);
        assert_eq!(pub_jwk["y"], gen.public_key_jwk["y"]);

        // New key IDs should not collide
        // (can't sign with restored transport — it doesn't have the
        // credential handles, but key metadata is preserved)
    }

    #[tokio::test]
    async fn preview_sign_no_import() {
        let transport = Box::new(MockCtap2::new());
        let plugin = PreviewSignPlugin::new(transport);
        assert!(
            !plugin.supports_import(),
            "FIDO2 plugin should not support key import"
        );
    }

    #[tokio::test]
    async fn manager_with_preview_sign_plugin() {
        let transport = Box::new(MockCtap2::new());
        let fido_plugin = Arc::new(PreviewSignPlugin::new(transport));

        let mut manager = WscdManager::new(WscdConfig {
            default_plugin: "fido2".into(),
            ..Default::default()
        });
        manager.register_plugin(fido_plugin);

        let auth = StubAuth;
        let progress = NoopProgress;

        // Generate via manager
        let gen = manager
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();
        assert!(gen.kid.as_str().starts_with("fido-"));

        // Sign via manager
        let sig = manager
            .sign(
                &gen.kid,
                b"managed-fido",
                Algorithm::ES256,
                &auth,
                &progress,
            )
            .await
            .unwrap();
        assert!(!sig.0.is_empty());

        // List via manager
        let keys = manager.list_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].plugin_id, "fido2");
    }

    #[tokio::test]
    async fn manager_migration_to_fido2_requires_reenrollment() {
        let softkey = Arc::new(SoftkeyPlugin::new());
        let transport = Box::new(MockCtap2::new());
        let fido_plugin = Arc::new(PreviewSignPlugin::new(transport));

        let mut manager = WscdManager::new(WscdConfig {
            default_plugin: "softkey".into(),
            ..Default::default()
        });
        manager.register_plugin(softkey);
        manager.register_plugin(fido_plugin);

        let auth = StubAuth;
        let progress = NoopProgress;

        let gen = manager
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();

        // Migrating to fido2 should require re-enrollment
        let result = manager.migrate_key(&gen.kid, "fido2", &auth).await.unwrap();
        match result {
            MigrationResult::ReEnrollmentRequired { old_kid } => {
                assert_eq!(old_kid, gen.kid);
            }
            MigrationResult::Migrated { .. } => {
                panic!("expected ReEnrollmentRequired for migration to FIDO2");
            }
        }
    }
}
