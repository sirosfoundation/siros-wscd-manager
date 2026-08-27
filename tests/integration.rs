#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use siros_wscd_manager::callbacks::{AuthCallback, NoopProgress, ProgressCallback};
    use siros_wscd_manager::config::WscdConfig;
    use siros_wscd_manager::error::{Result, WscdError};
    use siros_wscd_manager::manager::WscdManager;
    use siros_wscd_manager::plugins::softkey::SoftkeyPlugin;
    use siros_wscd_manager::traits::WscdPlugin;
    use siros_wscd_manager::types::{
        ActivateLifecycleRequest, Algorithm, DestroyLifecycleRequest, DestroyMode, FactorKind,
        LifecycleState, MigrationResult, OperationProgress, RegisterLifecycleRequest,
        RotateLifecycleRequest, Secret,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Stub AuthCallback that always returns a dummy PIN.
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
        use p256::PublicKey;

        let x_bytes =
            Base64UrlUnpadded::decode_vec(gen.public_key_jwk["x"].as_str().unwrap()).unwrap();
        let y_bytes =
            Base64UrlUnpadded::decode_vec(gen.public_key_jwk["y"].as_str().unwrap()).unwrap();
        let mut sec1 = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
        sec1.push(0x04); // uncompressed
        sec1.extend_from_slice(&x_bytes);
        sec1.extend_from_slice(&y_bytes);
        let pubkey = PublicKey::from_sec1_bytes(&sec1).unwrap();
        let vk = VerifyingKey::from(pubkey);
        let signature = Signature::from_slice(sig.0.as_slice()).unwrap();
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

    #[tokio::test]
    async fn manager_lifecycle_routes_to_plugin() {
        let mut manager = WscdManager::new(WscdConfig {
            default_plugin: "lifecycle".into(),
            ..Default::default()
        });
        manager.register_plugin(Arc::new(LifecycleStubPlugin::new("lifecycle")));

        let auth = StubAuth;
        let progress = NoopProgress;

        let reg = manager
            .register_lifecycle(
                &RegisterLifecycleRequest {
                    plugin_id: "lifecycle".into(),
                    context_id: "ctx-1".into(),
                    factor_kind: FactorKind::Opaque,
                },
                &auth,
                &progress,
            )
            .await
            .expect("register_lifecycle should succeed");
        assert_eq!(reg.state, LifecycleState::Registered);

        let status = manager
            .lifecycle_status("lifecycle", "ctx-1")
            .await
            .expect("lifecycle_status should succeed");
        assert_eq!(status.state, LifecycleState::Registered);

        let act = manager
            .activate_lifecycle(
                &ActivateLifecycleRequest {
                    plugin_id: "lifecycle".into(),
                    context_id: "ctx-1".into(),
                },
                &auth,
                &progress,
            )
            .await
            .expect("activate_lifecycle should succeed");
        assert_eq!(act.state, LifecycleState::Active);

        let rot = manager
            .rotate_lifecycle(
                &RotateLifecycleRequest {
                    plugin_id: "lifecycle".into(),
                    context_id: "ctx-1".into(),
                },
                &auth,
                &progress,
            )
            .await
            .expect("rotate_lifecycle should succeed");
        assert_eq!(rot.state, LifecycleState::Registered);

        let des = manager
            .destroy_lifecycle(
                &DestroyLifecycleRequest {
                    plugin_id: "lifecycle".into(),
                    context_id: "ctx-1".into(),
                    mode: DestroyMode::LocalOnly,
                    reason: None,
                },
                &auth,
                &progress,
            )
            .await
            .expect("destroy_lifecycle should succeed");
        assert_eq!(des.state, LifecycleState::Destroyed);
    }

    #[tokio::test]
    async fn manager_lifecycle_supported_for_softkey() {
        let mut manager = WscdManager::new(WscdConfig::default());
        manager.register_plugin(Arc::new(SoftkeyPlugin::new()));

        let auth = StubAuth;
        let progress = NoopProgress;

        let result = manager
            .register_lifecycle(
                &RegisterLifecycleRequest {
                    plugin_id: "softkey".into(),
                    context_id: "ctx-softkey".into(),
                    factor_kind: FactorKind::Opaque,
                },
                &auth,
                &progress,
            )
            .await;

        let outcome = result.expect("softkey should support register_lifecycle");
        assert_eq!(outcome.state, LifecycleState::Registered);
    }

    struct LifecycleStubPlugin {
        id: String,
        contexts: Mutex<HashMap<String, LifecycleState>>,
    }

    impl LifecycleStubPlugin {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                contexts: Mutex::new(HashMap::new()),
            }
        }

        fn now() -> i64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        }
    }

    #[async_trait]
    impl siros_wscd_manager::WscdPlugin for LifecycleStubPlugin {
        fn id(&self) -> &str {
            &self.id
        }

        fn display_name(&self) -> &str {
            &self.id
        }

        fn auth_method(&self) -> siros_wscd_manager::AuthMethod {
            siros_wscd_manager::AuthMethod::None
        }

        async fn generate_key(
            &self,
            _algorithm: Algorithm,
            _auth: &dyn AuthCallback,
            _progress: &dyn ProgressCallback,
        ) -> Result<siros_wscd_manager::GeneratedKey> {
            Err(WscdError::Unsupported {
                plugin: self.id.clone(),
                op: "generate_key".into(),
            })
        }

        async fn sign(
            &self,
            _kid: &siros_wscd_manager::KeyId,
            _data: &[u8],
            _algorithm: Algorithm,
            _auth: &dyn AuthCallback,
            _progress: &dyn ProgressCallback,
        ) -> Result<siros_wscd_manager::Signature> {
            Err(WscdError::Unsupported {
                plugin: self.id.clone(),
                op: "sign".into(),
            })
        }

        async fn list_keys(&self) -> Result<Vec<siros_wscd_manager::KeyInfo>> {
            Ok(vec![])
        }

        async fn attestation_chain(
            &self,
            _kid: &siros_wscd_manager::KeyId,
        ) -> Result<Option<siros_wscd_manager::AttestationChain>> {
            Ok(None)
        }

        async fn delete_key(&self, _kid: &siros_wscd_manager::KeyId) -> Result<()> {
            Ok(())
        }

        async fn export_public_key(
            &self,
            _kid: &siros_wscd_manager::KeyId,
        ) -> Result<serde_json::Value> {
            Err(WscdError::Unsupported {
                plugin: self.id.clone(),
                op: "export_public_key".into(),
            })
        }

        fn security_properties(
            &self,
            _kid: &siros_wscd_manager::KeyId,
        ) -> Result<siros_wscd_manager::SecurityProperties> {
            Err(WscdError::Unsupported {
                plugin: self.id.clone(),
                op: "security_properties".into(),
            })
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn supports_lifecycle(&self) -> bool {
            true
        }

        async fn lifecycle_status(
            &self,
            context_id: &str,
        ) -> Result<siros_wscd_manager::LifecycleStatus> {
            let state = self
                .contexts
                .lock()
                .unwrap()
                .get(context_id)
                .copied()
                .ok_or_else(|| WscdError::KeyNotFound {
                    kid: context_id.to_string(),
                })?;
            Ok(siros_wscd_manager::LifecycleStatus {
                context_id: context_id.to_string(),
                plugin_id: self.id.clone(),
                factor_kind: FactorKind::Opaque,
                state,
                updated_at: Self::now(),
            })
        }

        async fn register_lifecycle(
            &self,
            request: &siros_wscd_manager::RegisterLifecycleRequest,
            _auth: &dyn AuthCallback,
            _progress: &dyn ProgressCallback,
        ) -> Result<siros_wscd_manager::RegistrationOutcome> {
            self.contexts
                .lock()
                .unwrap()
                .insert(request.context_id.clone(), LifecycleState::Registered);
            Ok(siros_wscd_manager::RegistrationOutcome {
                context_id: request.context_id.clone(),
                state: LifecycleState::Registered,
            })
        }

        async fn activate_lifecycle(
            &self,
            request: &siros_wscd_manager::ActivateLifecycleRequest,
            _auth: &dyn AuthCallback,
            _progress: &dyn ProgressCallback,
        ) -> Result<siros_wscd_manager::ActivationOutcome> {
            self.contexts
                .lock()
                .unwrap()
                .insert(request.context_id.clone(), LifecycleState::Active);
            Ok(siros_wscd_manager::ActivationOutcome {
                context_id: request.context_id.clone(),
                state: LifecycleState::Active,
            })
        }

        async fn rotate_lifecycle(
            &self,
            request: &siros_wscd_manager::RotateLifecycleRequest,
            _auth: &dyn AuthCallback,
            _progress: &dyn ProgressCallback,
        ) -> Result<siros_wscd_manager::RotationOutcome> {
            self.contexts
                .lock()
                .unwrap()
                .insert(request.context_id.clone(), LifecycleState::Registered);
            Ok(siros_wscd_manager::RotationOutcome {
                context_id: request.context_id.clone(),
                state: LifecycleState::Registered,
            })
        }

        async fn destroy_lifecycle(
            &self,
            request: &siros_wscd_manager::DestroyLifecycleRequest,
            _auth: &dyn AuthCallback,
            _progress: &dyn ProgressCallback,
        ) -> Result<siros_wscd_manager::DestructionOutcome> {
            self.contexts
                .lock()
                .unwrap()
                .insert(request.context_id.clone(), LifecycleState::Destroyed);
            Ok(siros_wscd_manager::DestructionOutcome {
                context_id: request.context_id.clone(),
                state: LifecycleState::Destroyed,
                remote_performed: false,
            })
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

        fn as_any(&self) -> &dyn std::any::Any {
            self
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

    use ciborium::Value;
    use siros_wscd_manager::callbacks::Ctap2Transport;
    use siros_wscd_manager::ctap2_client_pin;
    use siros_wscd_manager::plugins::preview_sign::PreviewSignPlugin;

    /// (credential_id, key_handle, signing_key_bytes)
    type MockCredential = (Vec<u8>, Vec<u8>, Vec<u8>);

    /// Mock CTAP2 transport that simulates a FIDO2 authenticator using
    /// software P-256 keys, at the RAW WIRE level - it parses real CBOR
    /// commands and builds real CBOR responses, exactly like a physical
    /// authenticator would receive over `ctap2_send_command`. This
    /// exercises `preview_sign_protocol`'s real request-building and
    /// response-parsing logic end to end, rather than intercepting at a
    /// structured business-object layer above it.
    struct MockCtap2 {
        /// Stored credentials, keyed by nothing in particular; see
        /// [`MockCredential`].
        credentials: Mutex<Vec<MockCredential>>,
        /// When set, `makeCredential` answers an ARKG `generateKey` request
        /// with a real ARKG-pub seed built from these two long-term secrets
        /// (`skBl`, `skKem`) instead of a plain EC2 key, and `getAssertion`
        /// re-derives the matching private key the way a real authenticator
        /// does. See [`MockCtap2::with_arkg`].
        arkg_secrets: Mutex<Option<(p256::SecretKey, p256::SecretKey)>>,
        /// This mock's own ClientPin ECDH secret, set by `getKeyAgreement`
        /// and consumed by the following `getPinUvAuthTokenUsingPin*`
        /// call - real authenticators are similarly stateful across this
        /// exchange (one in-progress key agreement at a time).
        pending_key_agreement: Mutex<Option<p256::SecretKey>>,
        /// Key handles created for the BLS12-381 Schnorr algorithm, so
        /// `getAssertion` knows to answer with a 64-octet raw signature
        /// instead of DER.
        bls_key_handles: Mutex<Vec<Vec<u8>>>,
        /// The exact `tbs` the last `getAssertion` received. A real
        /// authenticator cannot tell the caller what it was asked to sign;
        /// this mock can, which is the only way to assert that a
        /// pre-hashed challenge crossed the boundary unmodified.
        last_tbs: Mutex<Option<Vec<u8>>>,
    }

    impl MockCtap2 {
        fn new() -> Self {
            Self {
                credentials: Mutex::new(Vec::new()),
                arkg_secrets: Mutex::new(None),
                pending_key_agreement: Mutex::new(None),
                bls_key_handles: Mutex::new(Vec::new()),
                last_tbs: Mutex::new(None),
            }
        }

        /// A mock that behaves like real previewSign hardware: `generateKey`
        /// returns an ARKG-pub *seed*, not a usable public key, and the
        /// signing key exists only once both sides have done their half of
        /// the ARKG derivation.
        ///
        /// [`MockCtap2::new`] returns a plain EC2 key instead, which is the
        /// plugin's explicitly-documented defensive fallback — so every
        /// existing previewSign test takes the fallback branch and the branch
        /// that actually runs against a YubiKey has never been exercised.
        fn with_arkg() -> Self {
            use p256::elliptic_curve::Generate;
            let mock = Self::new();
            *mock.arkg_secrets.lock().unwrap() =
                Some((p256::SecretKey::generate(), p256::SecretKey::generate()));
            mock
        }
    }

    /// COSE encoding of a P-256 public key as a nested CBOR *value* (the
    /// shape an ARKG-pub seed nests at labels -1 and -2).
    fn cose_ec2_value(public: &p256::PublicKey) -> Value {
        use p256::elliptic_curve::sec1::ToSec1Point;
        let point = public.to_sec1_point(false);
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-7).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (
                Value::Integer((-2).into()),
                Value::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                Value::Integer((-3).into()),
                Value::Bytes(point.y().unwrap().to_vec()),
            ),
        ])
    }

    /// `{1: -65537 (ARKG-pub), 3: -65700 (ARKG-P256), -1: pkBl, -2: pkKem}`.
    fn encode_cose_arkg_pub_seed(sk_bl: &p256::SecretKey, sk_kem: &p256::SecretKey) -> Vec<u8> {
        encode_value(&Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer((-65537).into())),
            (Value::Integer(3.into()), Value::Integer((-65700).into())),
            (
                Value::Integer((-1).into()),
                cose_ec2_value(&sk_bl.public_key()),
            ),
            (
                Value::Integer((-2).into()),
                cose_ec2_value(&sk_kem.public_key()),
            ),
        ]))
    }

    /// The authenticator's half of ARKG: `ARKG-derive-private-key`
    /// (draft-bradleylundberg-cfrg-arkg-08 §3.2), specialised to ARKG-P256.
    ///
    /// Written out from the draft rather than calling into the crate, so a
    /// change to `src/arkg.rs`'s derivation shows up here as a signature that
    /// does not verify — which is exactly how it would show up against real
    /// hardware.
    fn arkg_derive_private_key(
        sk_bl: &p256::SecretKey,
        sk_kem: &p256::SecretKey,
        kh: &[u8],
        ctx: &[u8],
    ) -> p256::Scalar {
        use hkdf::Hkdf;
        use hmac::{Hmac, KeyInit, Mac};
        use num_bigint::BigUint;
        use p256::ecdh::diffie_hellman;
        use p256::elliptic_curve::PrimeField;
        use sha2::Sha256;

        const DST_AUG: &[u8] = b"ARKG-ECDH.ARKG-P256";
        let ctx_kem = [b"ARKG-Derive-Key-KEM.".as_slice(), &[ctx.len() as u8], ctx].concat();
        let ctx_bl = [b"ARKG-Derive-Key-BL.".as_slice(), &[ctx.len() as u8], ctx].concat();

        let (tag, c_prime) = kh.split_at(16);
        let pk_prime = p256::PublicKey::from_sec1_bytes(c_prime).expect("c' is a P-256 point");
        let k_prime = diffie_hellman(sk_kem.to_nonzero_scalar(), pk_prime.as_affine());
        let expand = |info: &[u8]| -> [u8; 32] {
            let mut out = [0u8; 32];
            Hkdf::<Sha256>::new(Some(&[]), k_prime.raw_secret_bytes())
                .expand(info, &mut out)
                .unwrap();
            out
        };
        let mac_key = expand(&[b"ARKG-KEM-HMAC-mac.".as_slice(), DST_AUG, &ctx_kem].concat());
        let tau = expand(&[b"ARKG-KEM-HMAC-shared.".as_slice(), DST_AUG, &ctx_kem].concat());

        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&mac_key).unwrap();
        mac.update(c_prime);
        assert_eq!(
            &mac.finalize().into_bytes()[..16],
            tag,
            "a real authenticator refuses a key handle whose MAC does not check out"
        );

        // tau' = hash_to_field(tau) over the P-256 group order, RFC 9380
        // expand_message_xmd(SHA-256) with L = 48.
        let dst = [b"ARKG-BL-EC.ARKG-P256".as_slice(), &ctx_bl].concat();
        let uniform = expand_message_xmd_sha256(&tau, &dst, 48);
        let order = BigUint::from_bytes_be(
            &hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
                .unwrap(),
        );
        let mut reduced = (BigUint::from_bytes_be(&uniform) % &order).to_bytes_be();
        while reduced.len() < 32 {
            reduced.insert(0, 0);
        }
        let tau_prime: p256::Scalar = Option::from(p256::Scalar::from_repr(
            p256::FieldBytes::try_from(reduced.as_slice()).unwrap(),
        ))
        .unwrap();
        *sk_bl.to_nonzero_scalar().as_ref() + tau_prime
    }

    /// RFC 9380 §5.3.1 `expand_message_xmd`, SHA-256.
    fn expand_message_xmd_sha256(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let ell = len_in_bytes.div_ceil(32);
        let mut dst_prime = dst.to_vec();
        dst_prime.push(dst.len() as u8);

        let mut msg_prime = vec![0u8; 64];
        msg_prime.extend_from_slice(msg);
        msg_prime.extend_from_slice(&(len_in_bytes as u16).to_be_bytes());
        msg_prime.push(0);
        msg_prime.extend_from_slice(&dst_prime);

        let b0 = Sha256::digest(&msg_prime).to_vec();
        let mut blocks = vec![b0.clone()];
        let mut b1_input = b0.clone();
        b1_input.push(1);
        b1_input.extend_from_slice(&dst_prime);
        blocks.push(Sha256::digest(&b1_input).to_vec());
        for i in 2..=ell {
            let mut input: Vec<u8> = b0
                .iter()
                .zip(blocks[i - 1].iter())
                .map(|(a, c)| a ^ c)
                .collect();
            input.push(i as u8);
            input.extend_from_slice(&dst_prime);
            blocks.push(Sha256::digest(&input).to_vec());
        }
        blocks[1..].concat()[..len_in_bytes].to_vec()
    }

    /// A COSE_Key shaped the way a real YubiKey 5.8.1-alpha0 returns a BLS
    /// key binding key: EC2-style, with x at -2 and y at -3, each 48
    /// octets, and the PLACEHOLDER curve id rather than 13.
    ///
    /// An earlier version of this mock emitted a single compressed point at
    /// -2 with no -3 - which is what the plugin had been written to expect,
    /// so the two agreed with each other and neither matched hardware. The
    /// shape here is taken from a verbatim capture.
    fn encode_cose_bls_g1_key(x: &[u8], y: &[u8]) -> Vec<u8> {
        let value = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
            (
                Value::Integer(3.into()),
                Value::Integer((-65609).into()), // alg
            ),
            (Value::Integer((-1).into()), Value::Integer((-65601).into())), // crv placeholder
            (Value::Integer((-2).into()), Value::Bytes(x.to_vec())),
            (Value::Integer((-3).into()), Value::Bytes(y.to_vec())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&value, &mut buf).unwrap();
        buf
    }

    fn encode_cose_ec2_key(x: &[u8], y: &[u8]) -> Vec<u8> {
        let value = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
            (Value::Integer(3.into()), Value::Integer((-7).into())), // alg: ES256
            (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
            (Value::Integer((-2).into()), Value::Bytes(x.to_vec())),
            (Value::Integer((-3).into()), Value::Bytes(y.to_vec())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&value, &mut buf).unwrap();
        buf
    }

    fn cbor_map(value: &Value) -> &Vec<(Value, Value)> {
        value.as_map().expect("expected a CBOR map")
    }

    fn cbor_get(map: &[(Value, Value)], key: i64) -> Option<&Value> {
        map.iter()
            .find(|(k, _)| k.as_integer().map(i128::from) == Some(key as i128))
            .map(|(_, v)| v)
    }

    fn cbor_get_text<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
        map.iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    }

    /// Build a fake `authenticatorData` blob: `rpIdHash(32, zeroed - not
    /// validated by our parsing code) || flags(1) || signCount(4) ||
    /// [attestedCredentialData] || [extensions]`.
    fn build_auth_data(
        attested: Option<(&[u8], &[u8], &[u8])>, // (aaguid, cred_id, cose_key_bytes)
        extensions: Option<Value>,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        let mut flags = 0u8;
        if attested.is_some() {
            flags |= 0x40;
        }
        if extensions.is_some() {
            flags |= 0x80;
        }
        buf.push(flags);
        buf.extend_from_slice(&[0, 0, 0, 1]);
        if let Some((aaguid, cred_id, cose_key)) = attested {
            buf.extend_from_slice(aaguid);
            let len = cred_id.len() as u16;
            buf.push((len >> 8) as u8);
            buf.push((len & 0xFF) as u8);
            buf.extend_from_slice(cred_id);
            buf.extend_from_slice(cose_key);
        }
        if let Some(ext) = extensions {
            ciborium::ser::into_writer(&ext, &mut buf).unwrap();
        }
        buf
    }

    fn encode_value(value: &Value) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(value, &mut buf).unwrap();
        buf
    }

    fn generate_p256_keypair() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::sec1::ToSec1Point;
        use p256::elliptic_curve::Generate;
        use p256::SecretKey;

        let secret = SecretKey::generate();
        let signing_key = SigningKey::from(secret.clone());
        let point = p256::PublicKey::from(signing_key.verifying_key()).to_sec1_point(false);
        (
            point.x().unwrap().to_vec(),
            point.y().unwrap().to_vec(),
            secret.to_bytes().to_vec(),
        )
    }

    /// Lets a test keep a handle on the mock (to inspect what it was asked
    /// to sign) while the plugin owns a boxed transport.
    ///
    /// A newtype because `impl Ctap2Transport for Arc<MockCtap2>` is
    /// rejected with E0117. `Ctap2Transport` is local to the *library*
    /// crate, but `tests/` is compiled as a separate crate, so from here it
    /// is foreign; and `Arc` is not `#[fundamental]` (unlike `Box` or `&`),
    /// so `Arc<MockCtap2>` does not count as a local type either. Foreign
    /// trait, foreign type — orphan rule.
    struct SharedMock(std::sync::Arc<MockCtap2>);

    #[async_trait]
    impl Ctap2Transport for SharedMock {
        async fn ctap2_send_command(&self, command: &[u8]) -> Result<Vec<u8>> {
            self.0.ctap2_send_command(command).await
        }
    }

    #[async_trait]
    impl Ctap2Transport for MockCtap2 {
        async fn ctap2_send_command(&self, command: &[u8]) -> Result<Vec<u8>> {
            let cmd = command[0];

            // authenticatorGetInfo (0x04) has no CBOR params at all -
            // handle it before the unconditional parse below, which would
            // otherwise fail on an empty body.
            if cmd == 0x04 {
                let info = Value::Map(vec![(
                    Value::Integer(6.into()),
                    Value::Array(vec![Value::Integer(2.into()), Value::Integer(1.into())]),
                )]);
                let mut response = vec![0x00u8];
                response.extend(encode_value(&info));
                return Ok(response);
            }

            let params: Value = ciborium::de::from_reader(&command[1..]).unwrap();
            let map = cbor_map(&params);

            match cmd {
                0x06 => {
                    // authenticatorClientPIN: only the two subcommands
                    // `preview_sign_protocol`'s ClientPin exchange actually
                    // uses (getKeyAgreement, getPinUvAuthTokenUsingPinWithPermissions).
                    let sub_command = cbor_get(map, 2)
                        .and_then(|v| v.as_integer())
                        .and_then(|i| i64::try_from(i).ok())
                        .expect("missing subCommand");
                    match sub_command {
                        0x02 => {
                            use p256::elliptic_curve::Generate;
                            let secret = p256::SecretKey::generate();
                            let public_cose =
                                ctap2_client_pin::encode_platform_cose_key(&secret.public_key());
                            *self.pending_key_agreement.lock().unwrap() = Some(secret);

                            let response_map =
                                Value::Map(vec![(Value::Integer(1.into()), public_cose)]);
                            let mut response = vec![0x00u8];
                            response.extend(encode_value(&response_map));
                            Ok(response)
                        }
                        0x09 => {
                            let protocol_int = cbor_get(map, 1)
                                .and_then(|v| v.as_integer())
                                .and_then(|i| i64::try_from(i).ok())
                                .expect("missing pinUvAuthProtocol");
                            let protocol =
                                ctap2_client_pin::PinUvAuthProtocol::from_int(protocol_int)
                                    .expect("unsupported pinUvAuthProtocol");
                            let platform_cose_key =
                                cbor_get(map, 3).expect("missing platform keyAgreement key");
                            let platform_public =
                                ctap2_client_pin::decode_cose_ec2_public_key(platform_cose_key)
                                    .expect("invalid platform public key");
                            let secret = self
                                .pending_key_agreement
                                .lock()
                                .unwrap()
                                .take()
                                .expect("getPinUvAuthToken called before getKeyAgreement");
                            let shared_x =
                                ctap2_client_pin::ecdh_shared_x(&secret, &platform_public).unwrap();
                            let aes_key = ctap2_client_pin::derive_aes_key(protocol, &shared_x);

                            // A real authenticator would verify pinHashEnc
                            // against its own stored PIN here; this mock
                            // just needs the exchange to be crypto-valid,
                            // not a real PIN check.
                            let token = [0x42u8; 32];
                            let token_enc = ctap2_client_pin::encrypt(protocol, &aes_key, &token);

                            let response_map = Value::Map(vec![(
                                Value::Integer(2.into()),
                                Value::Bytes(token_enc),
                            )]);
                            let mut response = vec![0x00u8];
                            response.extend(encode_value(&response_map));
                            Ok(response)
                        }
                        other => Err(WscdError::Crypto(format!(
                            "mock: unexpected ClientPin subCommand 0x{other:02x}"
                        ))),
                    }
                }
                0x01 => {
                    // authenticatorMakeCredential: read previewSign.generateKey's
                    // algorithms (key 3 inside the extension map at key 6).
                    let extensions = cbor_get(map, 6).expect("missing extensions");
                    let preview_sign = cbor_get_text(cbor_map(extensions), "previewSign")
                        .expect("missing previewSign extension");
                    let algorithms = cbor_get(cbor_map(preview_sign), 3)
                        .and_then(|v| v.as_array())
                        .expect("missing generateKey algorithms");
                    let algorithm = algorithms[0]
                        .as_integer()
                        .map(i64::try_from)
                        .unwrap()
                        .unwrap();

                    let (gx, gy, g_secret) = generate_p256_keypair();
                    let key_handle = g_secret;
                    let is_bls = algorithm == -65609;
                    let arkg = self.arkg_secrets.lock().unwrap().clone();
                    let generated_cose = if let (false, Some((sk_bl, sk_kem))) = (is_bls, &arkg) {
                        // Real previewSign hardware answers generateKey with
                        // an ARKG-pub seed. The signing key does not exist
                        // yet - the platform derives its public half and the
                        // authenticator derives the private half at sign
                        // time, from the `kh` in additionalArgs.
                        encode_cose_arkg_pub_seed(sk_bl, sk_kem)
                    } else if is_bls {
                        // Not a real G1 point - this mock never does BLS
                        // arithmetic. The plugin only decodes and stores it,
                        // so shape and length are what matter here.
                        self.bls_key_handles
                            .lock()
                            .unwrap()
                            .push(key_handle.clone());
                        encode_cose_bls_g1_key(&[0xa1u8; 48], &[0xa2u8; 48])
                    } else {
                        encode_cose_ec2_key(&gx, &gy)
                    };

                    // Nested attestation object for the generated key (unsigned
                    // extension output, response key 7).
                    let inner_auth_data =
                        build_auth_data(Some((&[0u8; 16], &key_handle, &generated_cose)), None);
                    let inner_att_obj = Value::Map(vec![
                        (Value::Integer(1.into()), Value::Text("none".into())),
                        (Value::Integer(2.into()), Value::Bytes(inner_auth_data)),
                        (Value::Integer(3.into()), Value::Map(vec![])),
                    ]);
                    let inner_att_obj_bytes = encode_value(&inner_att_obj);

                    // Deliberately use a WebAuthn credential ID that is NOT equal
                    // to the previewSign key handle, so tests exercise the
                    // separation between the two rather than trivially passing
                    // if they were conflated.
                    let mut credential_id = b"mock-credential-id-".to_vec();
                    credential_id.extend_from_slice(&key_handle);

                    let (ox, oy, _) = generate_p256_keypair();
                    let outer_cose = encode_cose_ec2_key(&ox, &oy);
                    let signed_extensions = Value::Map(vec![(
                        Value::Text("previewSign".into()),
                        Value::Map(vec![(
                            Value::Integer(3.into()),
                            Value::Integer(algorithm.into()),
                        )]),
                    )]);
                    let outer_auth_data = build_auth_data(
                        Some((&[0u8; 16], &credential_id, &outer_cose)),
                        Some(signed_extensions),
                    );

                    // key_handle IS the raw secret bytes in this mock (see
                    // `generate_p256_keypair`), so it doubles as the stored
                    // signing key.
                    self.credentials.lock().unwrap().push((
                        credential_id.clone(),
                        key_handle.clone(),
                        key_handle,
                    ));

                    let outer_att_obj = Value::Map(vec![
                        (Value::Integer(1.into()), Value::Text("none".into())),
                        (Value::Integer(2.into()), Value::Bytes(outer_auth_data)),
                        (Value::Integer(3.into()), Value::Map(vec![])),
                        (Value::Integer(7.into()), Value::Bytes(inner_att_obj_bytes)),
                    ]);

                    let mut response = vec![0x00u8];
                    response.extend(encode_value(&outer_att_obj));
                    Ok(response)
                }
                0x02 => {
                    // authenticatorGetAssertion: previewSign.signByCredential's
                    // keyHandle (key 2) and tbs (key 6), inside extensions - key
                    // 4 of the OUTER GetAssertion params (per CTAP2 §6.2; distinct
                    // from authenticatorMakeCredential's numbering, where
                    // extensions is key 6 - a real bug here previously read key 6
                    // for both commands, which happened to also be GetAssertion's
                    // pinUvAuthParam once the real client started sending PIN-auth
                    // params for v4 previewSign, making cbor_map() panic on that
                    // Bytes value). Distinct from the extension's OWN inner key 6,
                    // which is `tbs`.
                    let extensions = cbor_get(map, 4).expect("missing extensions");
                    let preview_sign = cbor_get_text(cbor_map(extensions), "previewSign")
                        .expect("missing previewSign extension");
                    let inner = cbor_map(preview_sign);
                    let key_handle = cbor_get(inner, 2)
                        .and_then(|v| v.as_bytes())
                        .unwrap()
                        .clone();
                    let tbs = cbor_get(inner, 6)
                        .and_then(|v| v.as_bytes())
                        .unwrap()
                        .clone();

                    *self.last_tbs.lock().unwrap() = Some(tbs.clone());

                    // ARKG mode: the private key is derived on demand from
                    // additionalArgs (COSE Signing Arguments,
                    // {3: alg, -1: kh, -2: ctx}), not looked up. A missing or
                    // wrongly-encoded additionalArgs is fatal here, exactly as
                    // it is on real hardware.
                    //
                    // BLS key binding keys are excluded: they are held by the
                    // authenticator directly, are not ARKG-derived, and
                    // legitimately carry no additionalArgs - so an ARKG mock
                    // that also issued one must still answer it the BLS way
                    // rather than demanding a key handle that does not exist.
                    let is_bls_credential =
                        self.bls_key_handles.lock().unwrap().contains(&key_handle);
                    let arkg = self.arkg_secrets.lock().unwrap().clone();
                    if let (false, Some((sk_bl, sk_kem))) = (is_bls_credential, arkg) {
                        use p256::ecdsa::{
                            signature::hazmat::PrehashSigner, Signature, SigningKey,
                        };

                        let additional_args = cbor_get(inner, 7)
                            .and_then(|v| v.as_bytes())
                            .expect(
                                "previewSign signByCredential for an ARKG key must carry \
                                 additionalArgs (key 7)",
                            )
                            .clone();
                        let args: Value = ciborium::de::from_reader(additional_args.as_slice())
                            .expect(
                                "additionalArgs must be a CBOR map, not raw kh bytes - a real \
                                 YubiKey answers CTAP2_ERR_CBOR_UNEXPECTED_TYPE otherwise",
                            );
                        let args_map = cbor_map(&args);
                        let kh = cbor_get(args_map, -1)
                            .and_then(|v| v.as_bytes())
                            .expect("additionalArgs is missing kh (-1)")
                            .clone();
                        let ctx = cbor_get(args_map, -2)
                            .and_then(|v| v.as_bytes())
                            .expect("additionalArgs is missing ctx (-2)")
                            .clone();

                        let scalar = arkg_derive_private_key(&sk_bl, &sk_kem, &kh, &ctx);
                        let nonzero: p256::NonZeroScalar =
                            Option::from(p256::NonZeroScalar::new(scalar)).unwrap();
                        let sig: Signature = SigningKey::from(nonzero).sign_prehash(&tbs).unwrap();
                        let der_sig = sig.to_der().to_bytes().to_vec();

                        let signed_extensions = Value::Map(vec![(
                            Value::Text("previewSign".into()),
                            Value::Map(vec![(Value::Integer(6.into()), Value::Bytes(der_sig))]),
                        )]);
                        let auth_data = build_auth_data(None, Some(signed_extensions));
                        let assert_obj =
                            Value::Map(vec![(Value::Integer(2.into()), Value::Bytes(auth_data))]);
                        let mut response = vec![0x00u8];
                        response.extend(encode_value(&assert_obj));
                        return Ok(response);
                    }

                    if is_bls_credential {
                        // Schnorr-over-G1 is two raw 32-octet scalars, NOT
                        // DER. Contents are irrelevant to the plugin, which
                        // validates the shape and passes the bytes through.
                        let raw_sig = vec![0x5au8; 64];
                        let signed_extensions = Value::Map(vec![(
                            Value::Text("previewSign".into()),
                            Value::Map(vec![(Value::Integer(6.into()), Value::Bytes(raw_sig))]),
                        )]);
                        let auth_data = build_auth_data(None, Some(signed_extensions));
                        let assert_obj =
                            Value::Map(vec![(Value::Integer(2.into()), Value::Bytes(auth_data))]);
                        let mut response = vec![0x00u8];
                        response.extend(encode_value(&assert_obj));
                        return Ok(response);
                    }

                    let creds = self.credentials.lock().unwrap();
                    let found = creds
                        .iter()
                        .find(|(_, kh, _)| kh == &key_handle)
                        .expect("unknown key handle")
                        .clone();
                    drop(creds);

                    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
                    use p256::SecretKey;
                    let secret = SecretKey::from_slice(&found.2).unwrap();
                    let signing_key = SigningKey::from(secret);
                    // `tbs` is already a SHA-256 digest (see
                    // `PreviewSignPlugin::sign`'s `sha2::Sha256::digest`) - a
                    // real authenticator signs that prehash directly, so this
                    // mock must use `sign_prehash` (raw ECDSA over the given
                    // bytes), not `Signer::sign` (which would hash `tbs` a
                    // second time and produce a signature that verifies
                    // against nothing real).
                    let sig: Signature = signing_key.sign_prehash(&tbs).unwrap();
                    // A real authenticator returns its ECDSA signature in
                    // CTAP2's native ASN.1 DER encoding (confirmed via real
                    // YubiKey hardware testing - see `der_signature_to_raw`'s
                    // doc comment), which `preview_sign_protocol` then
                    // converts to raw r||s. This mock must emulate that same
                    // DER contract, not hand back raw bytes directly.
                    let der_sig = sig.to_der().to_bytes().to_vec();

                    let signed_extensions = Value::Map(vec![(
                        Value::Text("previewSign".into()),
                        Value::Map(vec![(Value::Integer(6.into()), Value::Bytes(der_sig))]),
                    )]);
                    let auth_data = build_auth_data(None, Some(signed_extensions));
                    let assert_obj =
                        Value::Map(vec![(Value::Integer(2.into()), Value::Bytes(auth_data))]);

                    let mut response = vec![0x00u8];
                    response.extend(encode_value(&assert_obj));
                    Ok(response)
                }
                other => Err(WscdError::Crypto(format!(
                    "mock: unexpected command 0x{other:02x}"
                ))),
            }
        }
    }

    /// A stored key whose coordinate width is neither curve's must be
    /// rejected at load, not filed under the fallback.
    ///
    /// The curve is inferred from that width, so an unreadable record would
    /// otherwise surface much later - as a signature over the wrong curve,
    /// or a JWK published with empty coordinates.
    #[tokio::test]
    async fn state_with_unrecognised_coordinate_width_is_rejected() {
        let good = r#"{"keys":[{"kid":"fido-0","credential_id":[1],"key_handle":[2],
            "pub_x":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "pub_y":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "algorithm":-7,"attestation_object":[],"client_data_hash":[],
            "created_at":0}],"next_id":1,"lifecycle":{}}"#;
        assert!(
            PreviewSignPlugin::from_state(Box::new(MockCtap2::new()), good.as_bytes()).is_ok(),
            "a well-formed P-256 record must load"
        );

        // 40 octets: neither curve.
        let bad = good.replace(
            r#""pub_x":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"#,
            r#""pub_x":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"#,
        );
        // PreviewSignPlugin is not Debug, so match rather than expect_err.
        match PreviewSignPlugin::from_state(Box::new(MockCtap2::new()), bad.as_bytes()) {
            Ok(_) => panic!("a 40-octet coordinate is not a key on either curve"),
            Err(err) => assert!(
                format!("{err}").contains("40"),
                "the error should name the bad width, got: {err}"
            ),
        }
    }

    /// A BBS key binding key is generated with COSE -65609 and comes back
    /// as an (x, y) pair of 48-octet coordinates - the shape a real
    /// 5.8.1-alpha0 authenticator reports.
    #[tokio::test]
    async fn preview_sign_generates_a_bls_key_binding_key() {
        let transport = Box::new(MockCtap2::new());
        let plugin = PreviewSignPlugin::new(transport);
        let auth = StubAuth;
        let progress = RecordingProgress::new();

        let gen = plugin
            .generate_key(Algorithm::Bls12381G1Schnorr, &auth, &progress)
            .await
            .expect("BLS key binding key generation");

        assert_eq!(gen.public_key_jwk["kty"], "EC");
        assert_eq!(gen.public_key_jwk["crv"], "BLS12381G1");
        // Both coordinates are published, because that is what the
        // authenticator reports and what deriving the key binding key needs.
        // The BBS key is the compression of this point's NEGATION, which is
        // curve arithmetic and lives in zk-cred-bbs, not here.
        assert!(gen.public_key_jwk.get("x").is_some(), "x coordinate");
        assert!(gen.public_key_jwk.get("y").is_some(), "y coordinate");

        let keys = plugin.list_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].algorithm,
            Algorithm::Bls12381G1Schnorr,
            "list_keys must report the algorithm the key was created for, \
             not a default"
        );
    }

    /// The regression this whole code path exists to avoid.
    ///
    /// A key binding challenge arrives already SHA-256'd, to fit the
    /// authenticator's 64-octet ceiling. If the plugin hashes it again the
    /// authenticator signs SHA-256(SHA-256(challenge)) and every resulting
    /// BBS proof fails verification with nothing to point at. This asserts
    /// the bytes reach the authenticator untouched.
    #[tokio::test]
    async fn bls_key_binding_challenge_is_not_hashed_again() {
        let mock = std::sync::Arc::new(MockCtap2::new());
        let plugin = PreviewSignPlugin::new(Box::new(SharedMock(mock.clone())));
        let auth = StubAuth;
        let progress = RecordingProgress::new();

        let gen = plugin
            .generate_key(Algorithm::Bls12381G1Schnorr, &auth, &progress)
            .await
            .unwrap();

        // Exactly what zk-cred-bbs hands over: a 32-octet digest.
        let challenge: Vec<u8> = (0..32u8).collect();
        let sig = plugin
            .sign(
                &gen.kid,
                &challenge,
                Algorithm::Bls12381G1Schnorr,
                &auth,
                &progress,
            )
            .await
            .expect("signing a pre-hashed key binding challenge");

        let seen = mock.last_tbs.lock().unwrap().clone().expect("tbs recorded");
        assert_eq!(
            seen, challenge,
            "the challenge must reach the authenticator verbatim; \
             a second SHA-256 here silently breaks every proof"
        );
        assert_eq!(
            sig.0.len(),
            64,
            "Schnorr-over-G1 is two raw 32-octet scalars, not DER"
        );
    }

    /// An ES256 key must keep hashing its input — the BLS change must not
    /// alter the existing contract.
    #[tokio::test]
    async fn es256_input_is_still_hashed() {
        let mock = std::sync::Arc::new(MockCtap2::new());
        let plugin = PreviewSignPlugin::new(Box::new(SharedMock(mock.clone())));
        let auth = StubAuth;
        let progress = RecordingProgress::new();

        let gen = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();

        let data = b"a JWS signing input, far longer than any digest".to_vec();
        plugin
            .sign(&gen.kid, &data, Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();

        let seen = mock.last_tbs.lock().unwrap().clone().expect("tbs recorded");
        use sha2::Digest as _;
        assert_eq!(seen, sha2::Sha256::digest(&data).to_vec());
    }

    /// Anything that is not a 32-octet challenge is refused at the
    /// boundary. Capping at the firmware's 64-octet ceiling alone would let
    /// a 48-octet compressed point through, and it would fail verification
    /// much later with nothing to point at.
    #[tokio::test]
    async fn bls_rejects_input_that_is_not_a_challenge() {
        let transport = Box::new(MockCtap2::new());
        let plugin = PreviewSignPlugin::new(transport);
        let auth = StubAuth;
        let progress = RecordingProgress::new();

        let gen = plugin
            .generate_key(Algorithm::Bls12381G1Schnorr, &auth, &progress)
            .await
            .unwrap();

        // 80 octets: exactly the un-hashed key binding challenge size
        // (48-octet point + 32-octet scalar) that motivates the prehash.
        let too_long = vec![0u8; 80];
        let err = plugin
            .sign(
                &gen.kid,
                &too_long,
                Algorithm::Bls12381G1Schnorr,
                &auth,
                &progress,
            )
            .await
            .expect_err("80 octets is over the 64-octet ceiling");
        assert!(
            format!("{err}").contains("64"),
            "the error should name the limit, got: {err}"
        );
    }

    /// No software BLS12-381 today: softkey must refuse rather than quietly
    /// hand back a P-256 key that cannot back a BBS credential.
    #[tokio::test]
    async fn softkey_refuses_bls_key_binding() {
        let plugin = SoftkeyPlugin::new();
        let auth = StubAuth;
        let progress = RecordingProgress::new();
        assert!(plugin
            .generate_key(Algorithm::Bls12381G1Schnorr, &auth, &progress)
            .await
            .is_err());
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
        use p256::PublicKey;

        let x_bytes =
            Base64UrlUnpadded::decode_vec(gen.public_key_jwk["x"].as_str().unwrap()).unwrap();
        let y_bytes =
            Base64UrlUnpadded::decode_vec(gen.public_key_jwk["y"].as_str().unwrap()).unwrap();
        let mut sec1 = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
        sec1.push(0x04); // uncompressed
        sec1.extend_from_slice(&x_bytes);
        sec1.extend_from_slice(&y_bytes);
        let pubkey = PublicKey::from_sec1_bytes(&sec1).unwrap();
        let vk = VerifyingKey::from(pubkey);
        let signature = Signature::from_slice(sig.0.as_slice()).unwrap();
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

        // Attestation should be present, along with the clientDataHash
        // needed to verify its signature (authData || client_data_hash) -
        // without it, a verifier has no way to check the attestation
        // statement at all.
        let chain = plugin.attestation_chain(&gen1.kid).await.unwrap().unwrap();
        assert_eq!(chain.certificates.len(), 1);
        assert_eq!(chain.client_data_hash.len(), 32);

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

    /// Verify a signature against the JWK `generate_key` published, the way
    /// a credential verifier would.
    fn verify_es256_jwk(jwk: &serde_json::Value, data: &[u8], signature: &[u8]) {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        let mut sec1 = vec![0x04u8];
        sec1.extend(Base64UrlUnpadded::decode_vec(jwk["x"].as_str().unwrap()).unwrap());
        sec1.extend(Base64UrlUnpadded::decode_vec(jwk["y"].as_str().unwrap()).unwrap());
        let vk = VerifyingKey::from(p256::PublicKey::from_sec1_bytes(&sec1).unwrap());
        vk.verify(data, &Signature::from_slice(signature).unwrap())
            .expect("signature must verify under the published public key");
    }

    /// The previewSign path that actually runs against a YubiKey, end to end.
    ///
    /// Every other previewSign test here uses a mock whose `generateKey`
    /// returns a plain EC2 key, which sends `PreviewSignPlugin::generate_key`
    /// down its documented *fallback* branch ("defensive; not expected in
    /// practice"). Real hardware returns an ARKG-pub seed, so the ARKG branch
    /// — derive a public key, keep `(kh, ctx)`, hand them back as COSE
    /// Signing Arguments at sign time — was the one branch with no test at
    /// all, despite being the one that broke four separate times against real
    /// hardware.
    ///
    /// This asserts the property a credential issuer depends on: the key the
    /// wallet publishes and the key the authenticator can sign with are the
    /// same key. A wrong ARKG derivation, a `kh` stored but not sent, a
    /// `ctx` that disagrees between derive and sign time, or additionalArgs
    /// encoded as raw bytes instead of a COSE map all break it, and all are
    /// otherwise invisible until a verifier rejects a real credential.
    #[tokio::test]
    async fn preview_sign_arkg_derived_key_signs_and_verifies() {
        let plugin = PreviewSignPlugin::new(Box::new(MockCtap2::with_arkg()));
        let auth = StubAuth;
        let progress = NoopProgress;

        let gen = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .expect("ARKG generateKey");

        // The published key must be the *derived* key, not the seed: an
        // ARKG-pub seed has no single (x, y) to publish, so anything that
        // skipped the derivation could not produce this shape at all.
        assert_eq!(gen.public_key_jwk["kty"], "EC");
        assert_eq!(gen.public_key_jwk["crv"], "P-256");

        let data = b"a JWS signing input bound to an issued credential";
        let sig = plugin
            .sign(&gen.kid, data, Algorithm::ES256, &auth, &progress)
            .await
            .expect("the authenticator must be able to sign for the derived key");
        assert_eq!(sig.0.len(), 64, "ES256 signatures are raw r||s, not DER");
        verify_es256_jwk(&gen.public_key_jwk, data, &sig.0);
    }

    /// The ARKG key handle must survive `export_state`/`from_state`.
    ///
    /// `arkg_kh_and_ctx` is `#[serde(default)]`, so a restored blob that lost
    /// it deserialises perfectly happily — and then `sign` sends no
    /// `additionalArgs`, the authenticator cannot re-derive the private key,
    /// and every signature after a process restart fails. Nothing in the
    /// existing state round-trip test would notice: it only compares the
    /// public JWK, which is stored separately.
    #[tokio::test]
    async fn preview_sign_arkg_key_handle_survives_state_restore() {
        let mock = std::sync::Arc::new(MockCtap2::with_arkg());
        let plugin = PreviewSignPlugin::new(Box::new(SharedMock(mock.clone())));
        let auth = StubAuth;
        let progress = NoopProgress;

        let gen = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();
        let state = plugin.export_state().unwrap();
        drop(plugin);

        // Same authenticator (same ARKG secrets), fresh plugin instance -
        // exactly the app-restart case.
        let restored =
            PreviewSignPlugin::from_state(Box::new(SharedMock(mock.clone())), &state).unwrap();

        let data = b"signed after a restart";
        let sig = restored
            .sign(&gen.kid, data, Algorithm::ES256, &auth, &progress)
            .await
            .expect("a restored plugin must still be able to sign");
        verify_es256_jwk(&gen.public_key_jwk, data, &sig.0);
    }

    /// Two credentials from one authenticator must get two different keys.
    ///
    /// Unlinkability is the entire reason ARKG is here: `ikm` is fresh per
    /// key, and if it were not (a constant, a reused buffer, a seed derived
    /// from something stable) every credential this wallet ever issues would
    /// carry the same public key, silently correlating the holder across
    /// relying parties. Nothing about that failure is visible from the
    /// outside — the credentials still work.
    #[tokio::test]
    async fn preview_sign_arkg_keys_are_unlinkable_across_credentials() {
        let plugin = PreviewSignPlugin::new(Box::new(MockCtap2::with_arkg()));
        let auth = StubAuth;
        let progress = NoopProgress;

        let a = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();
        let b = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();

        assert_ne!(
            a.public_key_jwk["x"], b.public_key_jwk["x"],
            "two credentials from the same authenticator must not share a public key"
        );

        // And each one still signs under its own key, i.e. the two key
        // handles are not crossed.
        for gen in [&a, &b] {
            let sig = plugin
                .sign(
                    &gen.kid,
                    b"per-credential",
                    Algorithm::ES256,
                    &auth,
                    &progress,
                )
                .await
                .unwrap();
            verify_es256_jwk(&gen.public_key_jwk, b"per-credential", &sig.0);
        }
    }

    /// One authenticator can hold both kinds of key at once, and the two are
    /// answered along completely different paths: an ARKG key needs
    /// `additionalArgs` to re-derive a private key, a BLS key binding key is
    /// held directly and legitimately carries none. Nothing keys that choice
    /// off the algorithm at sign time — `PreviewSignPlugin` reads it back off
    /// the stored key's shape — so this pins that the two do not interfere.
    #[tokio::test]
    async fn preview_sign_arkg_and_bls_keys_coexist_on_one_authenticator() {
        let mock = std::sync::Arc::new(MockCtap2::with_arkg());
        let plugin = PreviewSignPlugin::new(Box::new(SharedMock(mock.clone())));
        let auth = StubAuth;
        let progress = NoopProgress;

        let arkg_key = plugin
            .generate_key(Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();
        let bls_key = plugin
            .generate_key(Algorithm::Bls12381G1Schnorr, &auth, &progress)
            .await
            .unwrap();
        assert_eq!(bls_key.public_key_jwk["crv"], "BLS12381G1");

        // The BLS key signs a 32-octet challenge and comes back as two raw
        // scalars, with no ARKG derivation attempted on its behalf.
        let challenge: Vec<u8> = (0..32u8).collect();
        let bls_sig = plugin
            .sign(
                &bls_key.kid,
                &challenge,
                Algorithm::Bls12381G1Schnorr,
                &auth,
                &progress,
            )
            .await
            .expect("a BLS key must not be routed down the ARKG path");
        assert_eq!(bls_sig.0.len(), 64);
        assert_eq!(mock.last_tbs.lock().unwrap().clone().unwrap(), challenge);

        // And the ARKG key still verifies afterwards.
        let data = b"still an ARKG credential";
        let sig = plugin
            .sign(&arkg_key.kid, data, Algorithm::ES256, &auth, &progress)
            .await
            .unwrap();
        verify_es256_jwk(&arkg_key.public_key_jwk, data, &sig.0);
    }

    /// EdDSA is named explicitly in the plugin's `generate_key` match. It
    /// must stay an error: no FIDO2 authenticator serves Ed25519 through the
    /// previewSign extension, and falling through to the ARKG branch would
    /// hand back a P-256 key labelled as something else.
    #[tokio::test]
    async fn preview_sign_refuses_eddsa() {
        let plugin = PreviewSignPlugin::new(Box::new(MockCtap2::new()));
        let err = plugin
            .generate_key(Algorithm::EdDSA, &StubAuth, &NoopProgress)
            .await
            .expect_err("EdDSA must be refused, not silently substituted");
        assert!(matches!(err, WscdError::Unsupported { .. }), "got {err:?}");
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
