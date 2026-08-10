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
        RotateLifecycleRequest,
    };
    use std::collections::HashMap;
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
        /// This mock's own ClientPin ECDH secret, set by `getKeyAgreement`
        /// and consumed by the following `getPinUvAuthTokenUsingPin*`
        /// call - real authenticators are similarly stateful across this
        /// exchange (one in-progress key agreement at a time).
        pending_key_agreement: Mutex<Option<p256::SecretKey>>,
    }

    impl MockCtap2 {
        fn new() -> Self {
            Self {
                credentials: Mutex::new(Vec::new()),
                pending_key_agreement: Mutex::new(None),
            }
        }
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
                    let generated_cose = encode_cose_ec2_key(&gx, &gy);

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
                    // keyHandle (key 2) and tbs (key 6), inside extensions (key 6
                    // of the outer params - distinct from the extension's OWN
                    // inner key 6, which is `tbs`).
                    let extensions = cbor_get(map, 6).expect("missing extensions");
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

                    let creds = self.credentials.lock().unwrap();
                    let found = creds
                        .iter()
                        .find(|(_, kh, _)| kh == &key_handle)
                        .expect("unknown key handle")
                        .clone();
                    drop(creds);

                    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
                    use p256::SecretKey;
                    let secret = SecretKey::from_slice(&found.2).unwrap();
                    let signing_key = SigningKey::from(secret);
                    let sig: Signature = signing_key.sign(&tbs);

                    let signed_extensions = Value::Map(vec![(
                        Value::Text("previewSign".into()),
                        Value::Map(vec![(
                            Value::Integer(6.into()),
                            Value::Bytes(sig.to_bytes().to_vec()),
                        )]),
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
