#[cfg(feature = "plugin-r2ps")]
use async_trait::async_trait;
#[cfg(feature = "plugin-r2ps")]
use p256::elliptic_curve::sec1::ToEncodedPoint;
#[cfg(feature = "plugin-r2ps")]
use r2ps_client::{
    AssertionResult, Fido2Ceremony, HsmKeyInfo, PakeClient, R2psClient, R2psRawSign, RawSign,
    RegistrationResult, Transport,
};
#[cfg(feature = "plugin-r2ps")]
use std::collections::HashMap;
#[cfg(feature = "plugin-r2ps")]
use std::sync::Mutex;

#[cfg(feature = "plugin-r2ps")]
use crate::callbacks::{AuthCallback, ProgressCallback};
#[cfg(feature = "plugin-r2ps")]
use crate::config::R2psConfig;
#[cfg(feature = "plugin-r2ps")]
use crate::error::{Result, WscdError};
#[cfg(feature = "plugin-r2ps")]
use crate::traits::WscdPlugin;
#[cfg(feature = "plugin-r2ps")]
use crate::types::{
    ActivateLifecycleRequest, ActivationOutcome, Algorithm, AttestationChain, AuthMethod,
    CertificationLevel, DestructionOutcome, DestroyLifecycleRequest, DestroyMode, FactorKind,
    GeneratedKey, KeyId, KeyInfo, KeyStorageType, LifecycleState, LifecycleStatus,
    OperationProgress, RegisterLifecycleRequest, RegistrationOutcome, RotateLifecycleRequest,
    RotationOutcome, SecurityProperties, Signature,
};

// R2PS plugin — remote PKCS#11 HSM signing via the R2PS protocol.
//
// This plugin wraps `r2ps_client::R2psClient` and delegates key
// generation and signing to a remote HSM. Authentication is performed
// via OPAQUE (with PIN from `AuthCallback::request_pin`) or WebAuthn
// (with assertion from `AuthCallback::request_webauthn_assertion`).
//
// The underlying r2ps-client is synchronous; we hold it behind a Mutex
// and call it from async context. For mobile apps, the Transport
// implementation should use the host's HTTP stack.

/// Adapter that bridges our async `AuthCallback` to the sync `Fido2Ceremony` trait.
///
/// The r2ps-client's `Fido2Ceremony` trait is synchronous, but our
/// `AuthCallback` is async. Since we call the R2PS client from within
/// a tokio runtime (inside a sync Mutex lock region), we use
/// `tokio::task::block_in_place` + `Handle::block_on` to bridge.
///
/// **Important:** This requires a multi-threaded tokio runtime.
/// Using a current-thread runtime will panic at `block_in_place`.
/// The WSCD manager enforces this by creating its own `rt-multi-thread`
/// runtime in the FFI layer.
#[cfg(feature = "plugin-r2ps")]
struct AuthCallbackCeremonyAdapter<'a> {
    auth: &'a dyn AuthCallback,
}

#[cfg(feature = "plugin-r2ps")]
impl<'a> Fido2Ceremony for AuthCallbackCeremonyAdapter<'a> {
    fn create_credential(
        &self,
        challenge: &str,
        rp_id: &str,
        _user_id: &str,
    ) -> r2ps_client::Result<RegistrationResult> {
        use base64ct::{Base64UrlUnpadded, Encoding};

        // Decode the base64url challenge to raw bytes
        let challenge_bytes = Base64UrlUnpadded::decode_vec(challenge)
            .map_err(|e| r2ps_client::R2psError::Base64(e.to_string()))?;

        // NOTE: We reuse request_webauthn_assertion for both registration and
        // assertion ceremonies. The host must distinguish based on the empty
        // allow_credentials list (empty = registration, non-empty = assertion).
        // This is a deliberate simplification to keep AuthCallback's surface
        // minimal; the host inspects the challenge context to determine which
        // navigator.credentials API to call (create vs get).
        let assertion_json = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.auth
                    .request_webauthn_assertion(&challenge_bytes, rp_id, &[])
                    .await
            })
        })
        .map_err(|e| r2ps_client::R2psError::Protocol(format!("auth callback failed: {e}")))?;

        // Parse the JSON response from the host
        let result: RegistrationResult = serde_json::from_slice(&assertion_json).map_err(|e| {
            r2ps_client::R2psError::Protocol(format!("invalid registration JSON: {e}"))
        })?;

        Ok(result)
    }

    fn get_assertion(
        &self,
        challenge: &str,
        rp_id: &str,
        allow_credentials: &[String],
    ) -> r2ps_client::Result<AssertionResult> {
        use base64ct::{Base64UrlUnpadded, Encoding};

        // Decode challenge
        let challenge_bytes = Base64UrlUnpadded::decode_vec(challenge)
            .map_err(|e| r2ps_client::R2psError::Base64(e.to_string()))?;

        // Decode allowed credential IDs from base64url to raw bytes
        let cred_ids: Vec<Vec<u8>> = allow_credentials
            .iter()
            .map(|c| {
                Base64UrlUnpadded::decode_vec(c).map_err(|e| {
                    r2ps_client::R2psError::Base64(format!("invalid credential ID '{}': {}", c, e))
                })
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let allowed_refs: Vec<Vec<u8>> = cred_ids;

        // Call our async AuthCallback
        let assertion_json = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.auth
                    .request_webauthn_assertion(&challenge_bytes, rp_id, &allowed_refs)
                    .await
            })
        })
        .map_err(|e| r2ps_client::R2psError::Protocol(format!("auth callback failed: {e}")))?;

        // Parse the JSON response from the host into an AssertionResult
        let result: AssertionResult = serde_json::from_slice(&assertion_json).map_err(|e| {
            r2ps_client::R2psError::Protocol(format!("invalid assertion JSON: {e}"))
        })?;

        Ok(result)
    }
}

#[cfg(feature = "plugin-r2ps")]
pub struct R2psPlugin<T: Transport, P: PakeClient> {
    inner: Mutex<R2psClient<T, P>>,
    config: R2psConfig,
    /// AMR values from the last successful sign operation.
    last_amr: Mutex<Vec<String>>,
    lifecycle: Mutex<HashMap<String, LifecycleContext>>,
}

#[cfg(feature = "plugin-r2ps")]
#[derive(Clone)]
struct LifecycleContext {
    factor_kind: FactorKind,
    state: LifecycleState,
    updated_at: i64,
}

#[cfg(feature = "plugin-r2ps")]
impl<T: Transport + Send + 'static, P: PakeClient + Send + 'static> R2psPlugin<T, P> {
    pub fn new(
        client: R2psClient<T, P>,
        config: R2psConfig,
    ) -> std::result::Result<Self, WscdError> {
        if config.auth_mode == "webauthn" && config.rp_id.is_empty() {
            return Err(WscdError::Plugin(
                "R2PS WebAuthn mode requires a non-empty rp_id".to_string(),
            ));
        }
        Ok(Self {
            inner: Mutex::new(client),
            config,
            last_amr: Mutex::new(Vec::new()),
            lifecycle: Mutex::new(HashMap::new()),
        })
    }

    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// Ensure the client is authenticated, requesting credentials via callback.
    async fn ensure_authenticated(&self, auth: &dyn AuthCallback) -> Result<()> {
        {
            let client = self
                .inner
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;
            if client.is_authenticated() {
                return Ok(());
            }
        } // drop lock before await

        match self.config.auth_mode.as_str() {
            "opaque" => {
                let pin = auth.request_pin().await?;
                let mut client = self
                    .inner
                    .lock()
                    .map_err(|e| WscdError::Plugin(e.to_string()))?;
                client
                    .authenticate(&pin)
                    .map_err(|e| WscdError::Plugin(format!("OPAQUE auth failed: {e}")))?;
                Ok(())
            }
            "webauthn" => {
                // WebAuthn mode: authenticate without SAD binding.
                // For signing with hash binding, use sign_with_sad directly.
                let ceremony = AuthCallbackCeremonyAdapter { auth };
                let mut client = self
                    .inner
                    .lock()
                    .map_err(|e| WscdError::Plugin(e.to_string()))?;
                client
                    .authenticate_fido2(
                        &ceremony,
                        &self.config.rp_id,
                        "session",
                        &self.config.allowed_credential_ids,
                    )
                    .map_err(|e| WscdError::Plugin(format!("FIDO2 auth failed: {e}")))?;
                Ok(())
            }
            other => Err(WscdError::Plugin(format!(
                "unknown R2PS auth mode: {other}"
            ))),
        }
    }

    /// Perform FIDO2 registration (provision a new credential for this R2PS client).
    ///
    /// This should be called once during initial provisioning or when
    /// credentials need to be rotated.
    pub async fn register_fido2(&self, auth: &dyn AuthCallback) -> Result<()> {
        let ceremony = AuthCallbackCeremonyAdapter { auth };
        let client = self
            .inner
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        client
            .register_fido2(&ceremony, &self.config.rp_id)
            .map_err(|e| WscdError::Plugin(format!("FIDO2 registration failed: {e}")))?;
        Ok(())
    }

    /// Sign with FIDO2 SAD (Signature Activation Data) binding.
    ///
    /// This authenticates via FIDO2 with the hash bound to the session,
    /// ensuring SCAL2-compliant data binding per EN 419 241-1.
    fn sign_with_sad_sync(
        &self,
        auth: &dyn AuthCallback,
        kid: &KeyId,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let ceremony = AuthCallbackCeremonyAdapter { auth };
        let mut client = self
            .inner
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        client
            .sign_with_sad(
                &ceremony,
                &self.config.rp_id,
                &self.config.allowed_credential_ids,
                kid.as_str(),
                data,
            )
            .map_err(|e| WscdError::Plugin(format!("R2PS sign_with_sad failed: {e}")))
    }

    /// Convert r2ps HsmKeyInfo to our KeyInfo.
    fn convert_key_info(info: &HsmKeyInfo) -> KeyInfo {
        KeyInfo {
            kid: KeyId(info.kid.clone()),
            algorithm: Algorithm::ES256,
            plugin_id: "r2ps".to_string(),
            created_at: info.creation_time,
        }
    }

    /// Build a public key JWK from SPKI DER base64.
    fn public_key_jwk_from_spki(spki_b64: &str) -> Result<serde_json::Value> {
        use base64ct::{Base64, Base64UrlUnpadded, Encoding};
        use p256::pkcs8::DecodePublicKey;

        let spki_der =
            Base64::decode_vec(spki_b64).map_err(|e| WscdError::Crypto(e.to_string()))?;

        let pubkey = p256::PublicKey::from_public_key_der(&spki_der)
            .map_err(|e| WscdError::Crypto(format!("invalid SPKI: {e}")))?;

        let point = p256::PublicKey::to_encoded_point(&pubkey, false);
        let x = Base64UrlUnpadded::encode_string(
            point
                .x()
                .ok_or_else(|| WscdError::Crypto("missing x".into()))?,
        );
        let y = Base64UrlUnpadded::encode_string(
            point
                .y()
                .ok_or_else(|| WscdError::Crypto("missing y".into()))?,
        );

        Ok(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        }))
    }
}

#[cfg(feature = "plugin-r2ps")]
#[async_trait]
impl<T, P> WscdPlugin for R2psPlugin<T, P>
where
    T: Transport + Send + Sync + 'static,
    P: PakeClient + Send + Sync + 'static,
{
    fn id(&self) -> &str {
        "r2ps"
    }

    fn display_name(&self) -> &str {
        "Remote PKCS#11 HSM (R2PS)"
    }

    fn auth_method(&self) -> AuthMethod {
        match self.config.auth_mode.as_str() {
            "webauthn" => AuthMethod::WebAuthn,
            _ => AuthMethod::Opaque,
        }
    }

    async fn generate_key(
        &self,
        _algorithm: Algorithm,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<GeneratedKey> {
        let _ = auth; // keygen is 1FA — no auth required
        progress
            .on_progress(OperationProgress::Started {
                operation: "generate_key".to_string(),
            })
            .await;

        // Key generation is 1FA (no auth needed for keygen itself)
        progress
            .on_progress(OperationProgress::NetworkRoundTrip { step: 1, total: 2 })
            .await;

        let (kid, pub_jwk) = {
            let mut client = self
                .inner
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;

            let mut raw = R2psRawSign::new(&mut client);
            let kid_bytes = raw
                .generate_key()
                .map_err(|e| WscdError::Plugin(format!("R2PS keygen failed: {e}")))?;
            let kid_str = String::from_utf8(kid_bytes)
                .map_err(|e| WscdError::Plugin(format!("invalid kid: {e}")))?;

            // Get the public key from list_keys
            let keys = raw
                .list_keys(&["P-256"])
                .map_err(|e| WscdError::Plugin(format!("R2PS list_keys failed: {e}")))?;
            let key_info =
                keys.iter()
                    .find(|k| k.kid == kid_str)
                    .ok_or_else(|| WscdError::KeyNotFound {
                        kid: kid_str.clone(),
                    })?;

            let jwk = Self::public_key_jwk_from_spki(&key_info.public_key)?;
            (kid_str, jwk)
        };

        progress.on_progress(OperationProgress::Complete).await;

        Ok(GeneratedKey {
            kid: KeyId(kid),
            public_key_jwk: pub_jwk,
        })
    }

    async fn sign(
        &self,
        kid: &KeyId,
        data: &[u8],
        _algorithm: Algorithm,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<Signature> {
        progress
            .on_progress(OperationProgress::Started {
                operation: "sign".to_string(),
            })
            .await;

        // Signing requires 2FA authentication
        progress
            .on_progress(OperationProgress::WaitingForUser)
            .await;

        let sig_bytes = if self.config.auth_mode == "webauthn" {
            // WebAuthn: use sign_with_sad for SCAL2-compliant hash binding.
            // The FIDO2 session is bound to the specific hash being signed.
            progress
                .on_progress(OperationProgress::NetworkRoundTrip { step: 1, total: 1 })
                .await;

            let result = self.sign_with_sad_sync(auth, kid, data)?;
            // Record amr: hardware key + proof-of-possession + PIN (SAD implies PIN binding)
            if let Ok(mut amr) = self.last_amr.lock() {
                *amr = vec!["hwk".to_string(), "pop".to_string(), "pin".to_string()];
            }
            result
        } else {
            // OPAQUE: authenticate first, then sign separately.
            self.ensure_authenticated(auth).await?;

            progress
                .on_progress(OperationProgress::NetworkRoundTrip { step: 1, total: 1 })
                .await;

            let mut client = self
                .inner
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;

            let mut raw = R2psRawSign::new(&mut client);
            let result = raw
                .sign(kid.as_str().as_bytes(), data)
                .map_err(|e| WscdError::Plugin(format!("R2PS sign failed: {e}")))?;
            // Record amr: password-authenticated key exchange
            if let Ok(mut amr) = self.last_amr.lock() {
                *amr = vec!["pwd".to_string()];
            }
            result
        };

        progress.on_progress(OperationProgress::Complete).await;

        Ok(Signature(sig_bytes))
    }

    async fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        let mut client = self
            .inner
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;

        let mut raw = R2psRawSign::new(&mut client);
        let keys = raw
            .list_keys(&["P-256"])
            .map_err(|e| WscdError::Plugin(format!("R2PS list_keys failed: {e}")))?;

        Ok(keys.iter().map(Self::convert_key_info).collect())
    }

    async fn attestation_chain(&self, _kid: &KeyId) -> Result<Option<AttestationChain>> {
        // R2PS keys are backed by a certified PKCS#11 HSM.
        // The attestation chain comes from the HSM vendor certificate.
        // For now, return None — this will be populated when we integrate
        // the HSM vendor attestation API.
        Ok(None)
    }

    async fn delete_key(&self, _kid: &KeyId) -> Result<()> {
        // R2PS HSM does not support key deletion via the R2PS protocol.
        Err(WscdError::Unsupported {
            plugin: "r2ps".into(),
            op: "delete_key".into(),
        })
    }

    async fn export_public_key(&self, kid: &KeyId) -> Result<serde_json::Value> {
        let mut client = self
            .inner
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;

        let mut raw = R2psRawSign::new(&mut client);
        let keys = raw
            .list_keys(&["P-256"])
            .map_err(|e| WscdError::Plugin(format!("R2PS list_keys failed: {e}")))?;

        let key_info =
            keys.iter()
                .find(|k| k.kid == kid.as_str())
                .ok_or_else(|| WscdError::KeyNotFound {
                    kid: kid.to_string(),
                })?;

        Self::public_key_jwk_from_spki(&key_info.public_key)
    }

    fn supports_import(&self) -> bool {
        // R2PS generates keys on the HSM — you can't import existing
        // private keys. Migration TO r2ps requires re-enrollment.
        false
    }

    fn security_properties(&self, _kid: &KeyId) -> Result<SecurityProperties> {
        let amr = self.last_amr.lock().map(|a| a.clone()).unwrap_or_else(|_| {
            match self.config.auth_mode.as_str() {
                "webauthn" => vec!["hwk".to_string(), "pop".to_string()],
                _ => vec!["pwd".to_string()],
            }
        });
        Ok(SecurityProperties {
            key_storage: KeyStorageType::RemoteHsm,
            user_authentication: vec!["iso_18045_high".to_string()],
            certification: CertificationLevel::Substantial,
            amr,
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn supports_lifecycle(&self) -> bool {
        true
    }

    async fn lifecycle_status(&self, context_id: &str) -> Result<LifecycleStatus> {
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        let ctx = lifecycle
            .get(context_id)
            .ok_or_else(|| WscdError::KeyNotFound {
                kid: context_id.to_string(),
            })?;
        Ok(LifecycleStatus {
            context_id: context_id.to_string(),
            plugin_id: self.id().to_string(),
            factor_kind: ctx.factor_kind,
            state: ctx.state,
            updated_at: ctx.updated_at,
        })
    }

    async fn register_lifecycle(
        &self,
        request: &RegisterLifecycleRequest,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<RegistrationOutcome> {
        progress
            .on_progress(OperationProgress::Started {
                operation: "register_lifecycle".to_string(),
            })
            .await;

        match request.factor_kind {
            FactorKind::Opaque => {
                let pin = auth.request_pin().await?;
                let mut client = self
                    .inner
                    .lock()
                    .map_err(|e| WscdError::Plugin(e.to_string()))?;
                client
                    .register(&pin)
                    .map_err(|e| WscdError::Plugin(format!("OPAQUE registration failed: {e}")))?;
            }
            FactorKind::WebAuthn => {
                if self.config.rp_id.is_empty() {
                    return Err(WscdError::Plugin(
                        "R2PS WebAuthn mode requires non-empty rp_id".to_string(),
                    ));
                }
                self.register_fido2(auth).await?;
            }
            FactorKind::RawSign => {
                return Err(WscdError::Unsupported {
                    plugin: self.id().to_string(),
                    op: "register_lifecycle(raw_sign)".to_string(),
                });
            }
        }

        let now = Self::now_unix();
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        lifecycle.insert(
            request.context_id.clone(),
            LifecycleContext {
                factor_kind: request.factor_kind,
                state: LifecycleState::Registered,
                updated_at: now,
            },
        );

        progress.on_progress(OperationProgress::Complete).await;

        Ok(RegistrationOutcome {
            context_id: request.context_id.clone(),
            state: LifecycleState::Registered,
        })
    }

    async fn activate_lifecycle(
        &self,
        request: &ActivateLifecycleRequest,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<ActivationOutcome> {
        progress
            .on_progress(OperationProgress::Started {
                operation: "activate_lifecycle".to_string(),
            })
            .await;

        let factor_kind = {
            let lifecycle = self
                .lifecycle
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;
            lifecycle
                .get(&request.context_id)
                .map(|v| v.factor_kind)
                .ok_or_else(|| WscdError::KeyNotFound {
                    kid: request.context_id.clone(),
                })?
        };

        match factor_kind {
            FactorKind::Opaque => {
                let pin = auth.request_pin().await?;
                let mut client = self
                    .inner
                    .lock()
                    .map_err(|e| WscdError::Plugin(e.to_string()))?;
                client
                    .authenticate(&pin)
                    .map_err(|e| WscdError::Plugin(format!("OPAQUE auth failed: {e}")))?;
            }
            FactorKind::WebAuthn => {
                let ceremony = AuthCallbackCeremonyAdapter { auth };
                let mut client = self
                    .inner
                    .lock()
                    .map_err(|e| WscdError::Plugin(e.to_string()))?;
                client
                    .authenticate_fido2(
                        &ceremony,
                        &self.config.rp_id,
                        "session",
                        &self.config.allowed_credential_ids,
                    )
                    .map_err(|e| WscdError::Plugin(format!("FIDO2 auth failed: {e}")))?;
            }
            FactorKind::RawSign => {
                return Err(WscdError::Unsupported {
                    plugin: self.id().to_string(),
                    op: "activate_lifecycle(raw_sign)".to_string(),
                });
            }
        }

        let now = Self::now_unix();
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        if let Some(ctx) = lifecycle.get_mut(&request.context_id) {
            ctx.state = LifecycleState::Active;
            ctx.updated_at = now;
        }

        progress.on_progress(OperationProgress::Complete).await;

        Ok(ActivationOutcome {
            context_id: request.context_id.clone(),
            state: LifecycleState::Active,
        })
    }

    async fn rotate_lifecycle(
        &self,
        request: &RotateLifecycleRequest,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<RotationOutcome> {
        let factor_kind = {
            let lifecycle = self
                .lifecycle
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;
            lifecycle
                .get(&request.context_id)
                .map(|v| v.factor_kind)
                .ok_or_else(|| WscdError::KeyNotFound {
                    kid: request.context_id.clone(),
                })?
        };

        let reg_req = RegisterLifecycleRequest {
            plugin_id: request.plugin_id.clone(),
            context_id: request.context_id.clone(),
            factor_kind,
        };
        let _ = self.register_lifecycle(&reg_req, auth, progress).await?;

        let now = Self::now_unix();
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        if let Some(ctx) = lifecycle.get_mut(&request.context_id) {
            ctx.state = LifecycleState::Registered;
            ctx.updated_at = now;
        }

        Ok(RotationOutcome {
            context_id: request.context_id.clone(),
            state: LifecycleState::Registered,
        })
    }

    async fn destroy_lifecycle(
        &self,
        request: &DestroyLifecycleRequest,
        _auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<DestructionOutcome> {
        progress
            .on_progress(OperationProgress::Started {
                operation: "destroy_lifecycle".to_string(),
            })
            .await;

        let mut remote_performed = false;
        match request.mode {
            DestroyMode::LocalOnly => {}
            DestroyMode::RemoteRevokeIfSupported | DestroyMode::Strict => {
                let revoke_result = {
                    let client = self
                        .inner
                        .lock()
                        .map_err(|e| WscdError::Plugin(e.to_string()))?;
                    client.wi_revoke(request.reason.as_deref())
                };
                match revoke_result {
                    Ok(_) => {
                        remote_performed = true;
                    }
                    Err(e) => {
                        if matches!(request.mode, DestroyMode::Strict) {
                            return Err(WscdError::Plugin(format!(
                                "strict destroy failed remote revoke: {e}"
                            )));
                        }
                    }
                }
            }
        }

        let now = Self::now_unix();
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        lifecycle.insert(
            request.context_id.clone(),
            LifecycleContext {
                factor_kind: FactorKind::Opaque,
                state: LifecycleState::Destroyed,
                updated_at: now,
            },
        );

        progress.on_progress(OperationProgress::Complete).await;

        Ok(DestructionOutcome {
            context_id: request.context_id.clone(),
            state: LifecycleState::Destroyed,
            remote_performed,
        })
    }
}
