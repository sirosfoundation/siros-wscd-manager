#[cfg(feature = "plugin-r2ps")]
use async_trait::async_trait;
#[cfg(feature = "plugin-r2ps")]
use p256::elliptic_curve::sec1::ToSec1Point;
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
    CertificationLevel, DestroyLifecycleRequest, DestroyMode, DestructionOutcome, FactorKind,
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
                    .request_webauthn_assertion("r2ps", &challenge_bytes, rp_id, &[])
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
                    .request_webauthn_assertion("r2ps", &challenge_bytes, rp_id, &allowed_refs)
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

    /// Lock `inner`, recovering from poison instead of propagating it - see
    /// `FfiWscdManager::lock_inner`'s doc comment (src/ffi.rs) for why: a
    /// panic elsewhere while this lock is held must not permanently brick
    /// every subsequent call to this plugin for the life of the process.
    fn lock_inner(&self) -> std::sync::MutexGuard<'_, R2psClient<T, P>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Lock `lifecycle`, recovering from poison - see [`Self::lock_inner`].
    fn lock_lifecycle(&self) -> std::sync::MutexGuard<'_, HashMap<String, LifecycleContext>> {
        self.lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn now_unix() -> i64 {
        crate::timeutil::now_unix()
    }

    /// Ensure the client is authenticated, requesting credentials via callback.
    async fn ensure_authenticated(&self, auth: &dyn AuthCallback) -> Result<()> {
        {
            let client = self.lock_inner();
            if client.is_authenticated() {
                return Ok(());
            }
        } // drop lock before await

        match self.config.auth_mode.as_str() {
            "opaque" => {
                let pin = auth.request_pin("r2ps").await?;
                let mut client = self.lock_inner();
                client
                    .authenticate(&pin)
                    .map_err(|e| WscdError::Plugin(format!("OPAQUE auth failed: {e}")))?;
                Ok(())
            }
            "webauthn" => {
                // WebAuthn mode: authenticate without SAD binding.
                // For signing with hash binding, use sign_with_sad directly.
                let ceremony = AuthCallbackCeremonyAdapter { auth };
                let mut client = self.lock_inner();
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
        let client = self.lock_inner();
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
        let mut client = self.lock_inner();
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

        let point = pubkey.to_sec1_point(false);
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
            let mut client = self.lock_inner();

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

            let mut client = self.lock_inner();

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
        let mut client = self.lock_inner();

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
        let mut client = self.lock_inner();

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
        let lifecycle = self.lock_lifecycle();
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
                let pin = auth.request_pin(self.id()).await?;
                let mut client = self.lock_inner();
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
        {
            let mut lifecycle = self.lock_lifecycle();
            lifecycle.insert(
                request.context_id.clone(),
                LifecycleContext {
                    factor_kind: request.factor_kind,
                    state: LifecycleState::Registered,
                    updated_at: now,
                },
            );
        }

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
            let lifecycle = self.lock_lifecycle();
            lifecycle
                .get(&request.context_id)
                .map(|v| v.factor_kind)
                .ok_or_else(|| WscdError::KeyNotFound {
                    kid: request.context_id.clone(),
                })?
        };

        match factor_kind {
            FactorKind::Opaque => {
                let pin = auth.request_pin(self.id()).await?;
                let mut client = self.lock_inner();
                client
                    .authenticate(&pin)
                    .map_err(|e| WscdError::Plugin(format!("OPAQUE auth failed: {e}")))?;
            }
            FactorKind::WebAuthn => {
                let ceremony = AuthCallbackCeremonyAdapter { auth };
                let mut client = self.lock_inner();
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
        {
            let mut lifecycle = self.lock_lifecycle();
            if let Some(ctx) = lifecycle.get_mut(&request.context_id) {
                ctx.state = LifecycleState::Active;
                ctx.updated_at = now;
            }
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
            let lifecycle = self.lock_lifecycle();
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
        let mut lifecycle = self.lock_lifecycle();
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
                    let client = self.lock_inner();
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
        {
            let mut lifecycle = self.lock_lifecycle();
            lifecycle.insert(
                request.context_id.clone(),
                LifecycleContext {
                    factor_kind: FactorKind::Opaque,
                    state: LifecycleState::Destroyed,
                    updated_at: now,
                },
            );
        }

        progress.on_progress(OperationProgress::Complete).await;

        Ok(DestructionOutcome {
            context_id: request.context_id.clone(),
            state: LifecycleState::Destroyed,
            remote_performed,
        })
    }
}

/// Tests that need no R2PS server.
///
/// Everything this plugin does over the wire needs a live remote HSM, so
/// none of it was covered at all. What *is* reachable offline is the part
/// that decides, without asking anyone, whether an operation is allowed and
/// what it reports back — configuration validation, the unsupported
/// operations, the failure handling around remote revocation, and the SPKI →
/// JWK conversion that decides which public key a credential is bound to.
/// Those are the decisions a caller cannot second-guess.
#[cfg(all(test, feature = "plugin-r2ps"))]
mod offline_tests {
    use super::*;
    use crate::callbacks::NoopProgress;
    use crate::types::Secret;
    use p256::elliptic_curve::Generate;

    /// Every request fails. A real R2PS deployment is a network call away,
    /// so "the server is unreachable" is the common case, not the exotic one.
    struct FailingTransport;

    impl Transport for FailingTransport {
        fn send(&self, _body: &[u8]) -> r2ps_client::Result<Vec<u8>> {
            Err(r2ps_client::R2psError::Transport("no server".into()))
        }
    }

    struct StubPake;

    impl PakeClient for StubPake {
        fn registration_init(&mut self, _password: &[u8]) -> r2ps_client::Result<Vec<u8>> {
            Ok(vec![0u8; 32])
        }
        fn registration_finalize(&mut self, _resp: &[u8]) -> r2ps_client::Result<Vec<u8>> {
            Ok(vec![0u8; 32])
        }
        fn auth_init(&mut self, _password: &[u8]) -> r2ps_client::Result<Vec<u8>> {
            Ok(vec![0u8; 32])
        }
        fn auth_finalize(&mut self, _resp: &[u8]) -> r2ps_client::Result<(Vec<u8>, Vec<u8>)> {
            Ok((vec![0u8; 32], vec![0u8; 32]))
        }
    }

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
            _allowed: &[Vec<u8>],
        ) -> Result<Vec<u8>> {
            Err(WscdError::AuthCancelled)
        }
    }

    fn config(auth_mode: &str, rp_id: &str) -> R2psConfig {
        R2psConfig {
            server_url: "https://r2ps.invalid/r2ps".into(),
            client_id: "test-client".into(),
            context: "test-context".into(),
            auth_mode: auth_mode.into(),
            rp_id: rp_id.into(),
            allowed_credential_ids: vec![],
        }
    }

    fn plugin(cfg: R2psConfig) -> Result<R2psPlugin<FailingTransport, StubPake>> {
        let client = R2psClient::new(
            cfg.client_id.clone(),
            cfg.context.clone(),
            p256::SecretKey::generate(),
            p256::SecretKey::generate().public_key(),
            FailingTransport,
            StubPake,
        );
        R2psPlugin::new(client, cfg)
    }

    /// WebAuthn mode without an `rp_id` must be refused at construction.
    ///
    /// `rp_id` is what scopes a WebAuthn assertion to this relying party. An
    /// empty one is not a harmless default: the ceremony would be built
    /// against `""`, and rejecting it here is the difference between a
    /// configuration error at startup and an authentication path that only
    /// fails the first time a user tries to sign something.
    #[test]
    fn webauthn_mode_requires_an_rp_id() {
        assert!(plugin(config("webauthn", "")).is_err());
        assert!(plugin(config("webauthn", "wallet.example.com")).is_ok());
        // OPAQUE mode has no rp_id and must not be caught by the same check.
        assert!(plugin(config("opaque", "")).is_ok());
    }

    #[test]
    fn auth_method_follows_the_configured_mode() {
        assert_eq!(
            plugin(config("webauthn", "wallet.example.com"))
                .unwrap()
                .auth_method(),
            AuthMethod::WebAuthn
        );
        assert_eq!(
            plugin(config("opaque", "")).unwrap().auth_method(),
            AuthMethod::Opaque
        );
    }

    /// Deleting a key must report that it did not happen.
    ///
    /// The R2PS protocol has no delete. Returning `Ok(())` would tell a
    /// wallet that key material was destroyed while it is still live in the
    /// HSM — the caller then drops its own record of the key and has no way
    /// left to ask for its revocation.
    #[tokio::test]
    async fn delete_key_is_refused_rather_than_silently_ignored() {
        let plugin = plugin(config("opaque", "")).unwrap();
        let err = plugin
            .delete_key(&KeyId("hsm-key".into()))
            .await
            .expect_err("R2PS cannot delete keys and must say so");
        assert!(matches!(err, WscdError::Unsupported { .. }), "got {err:?}");
        assert!(!plugin.supports_import(), "HSM keys cannot be imported");
    }

    /// `DestroyMode::Strict` must fail when the remote revoke fails, and
    /// `RemoteRevokeIfSupported` must succeed while admitting it did not.
    ///
    /// This is the whole point of having three destroy modes. If Strict
    /// swallowed the error the caller would believe the remote key was
    /// revoked when it is still usable by anyone holding the credentials —
    /// and `remote_performed` is the only signal distinguishing "revoked" from
    /// "forgotten locally", so it must never be optimistic.
    #[tokio::test]
    async fn strict_destroy_fails_when_remote_revocation_fails() {
        let plugin = plugin(config("opaque", "")).unwrap();
        let request = |mode| DestroyLifecycleRequest {
            plugin_id: "r2ps".into(),
            context_id: "ctx-1".into(),
            mode,
            reason: Some("test".into()),
        };

        let err = plugin
            .destroy_lifecycle(&request(DestroyMode::Strict), &StubAuth, &NoopProgress)
            .await
            .expect_err("a strict destroy must not report success on a failed revoke");
        assert!(matches!(err, WscdError::Plugin(_)), "got {err:?}");

        let outcome = plugin
            .destroy_lifecycle(
                &request(DestroyMode::RemoteRevokeIfSupported),
                &StubAuth,
                &NoopProgress,
            )
            .await
            .expect("a best-effort destroy still completes locally");
        assert_eq!(outcome.state, LifecycleState::Destroyed);
        assert!(
            !outcome.remote_performed,
            "the revoke failed, so remote_performed must be false"
        );

        // LocalOnly never contacts the server at all.
        let outcome = plugin
            .destroy_lifecycle(&request(DestroyMode::LocalOnly), &StubAuth, &NoopProgress)
            .await
            .unwrap();
        assert!(!outcome.remote_performed);
    }

    /// An `auth_mode` this plugin does not implement must be an error, not a
    /// fall-through to one of the modes it does. Treating an unrecognised
    /// mode as OPAQUE would silently downgrade a deployment configured for
    /// WebAuthn — and typos in configuration are how that happens.
    #[tokio::test]
    async fn an_unrecognised_auth_mode_is_rejected_at_use() {
        let plugin = plugin(config("totally-bogus", "")).unwrap();
        let err = plugin
            .sign(
                &KeyId("k".into()),
                b"data",
                Algorithm::ES256,
                &StubAuth,
                &NoopProgress,
            )
            .await
            .expect_err("an unknown auth mode must not authenticate anything");
        assert!(
            format!("{err}").contains("totally-bogus"),
            "the error should name the offending mode, got: {err}"
        );
    }

    #[tokio::test]
    async fn raw_sign_lifecycle_is_unsupported_and_unknown_contexts_are_not_found() {
        let plugin = plugin(config("opaque", "")).unwrap();

        let err = plugin
            .register_lifecycle(
                &RegisterLifecycleRequest {
                    plugin_id: "r2ps".into(),
                    context_id: "ctx".into(),
                    factor_kind: FactorKind::RawSign,
                },
                &StubAuth,
                &NoopProgress,
            )
            .await
            .expect_err("R2PS has no rawSign factor");
        assert!(matches!(err, WscdError::Unsupported { .. }), "got {err:?}");

        for result in [
            plugin.lifecycle_status("nope").await.err(),
            plugin
                .activate_lifecycle(
                    &ActivateLifecycleRequest {
                        plugin_id: "r2ps".into(),
                        context_id: "nope".into(),
                    },
                    &StubAuth,
                    &NoopProgress,
                )
                .await
                .err(),
            plugin
                .rotate_lifecycle(
                    &RotateLifecycleRequest {
                        plugin_id: "r2ps".into(),
                        context_id: "nope".into(),
                    },
                    &StubAuth,
                    &NoopProgress,
                )
                .await
                .err(),
        ] {
            assert!(
                matches!(result, Some(WscdError::KeyNotFound { .. })),
                "an unknown lifecycle context must be KeyNotFound, got {result:?}"
            );
        }
    }

    /// Known-answer test for the SPKI → JWK conversion.
    ///
    /// This decides which public key a credential ends up bound to, and it
    /// has two silent failure modes: swapping x and y (a key that verifies
    /// nothing), and getting the base64 alphabets backwards. The two here are
    /// genuinely different — the HSM's `public_key` field is *standard*
    /// base64, while the JWK coordinates are base64**url** without padding —
    /// so a single `Base64`/`Base64UrlUnpadded` mix-up produces a JWK that is
    /// well-formed and wrong. The vector below was produced independently
    /// (Python `cryptography`) from a fixed private scalar.
    #[test]
    fn spki_to_jwk_matches_an_independently_generated_vector() {
        const SPKI_STANDARD_BASE64: &str =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQfZI+TM8DKDAXqESNxVLzppy1D7RFSeA\
             UPLpMtU5GXyfyer7+Ah76rZLj2GckO51dHRUx7yWJwYX175XWuKKww==";

        let jwk = R2psPlugin::<FailingTransport, StubPake>::public_key_jwk_from_spki(
            SPKI_STANDARD_BASE64,
        )
        .expect("a valid P-256 SPKI must decode");

        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["x"], "QfZI-TM8DKDAXqESNxVLzppy1D7RFSeAUPLpMtU5GXw");
        assert_eq!(jwk["y"], "n8nq-_gIe-q2S49hnJDudXR0VMe8licGF9e-V1riisM");
    }

    #[test]
    fn spki_to_jwk_rejects_input_that_is_not_a_p256_public_key() {
        type P = R2psPlugin<FailingTransport, StubPake>;
        // Not base64 at all.
        assert!(P::public_key_jwk_from_spki("not base64 !!").is_err());
        // Valid base64, not valid DER.
        assert!(P::public_key_jwk_from_spki("AAAAAAAA").is_err());
        assert!(P::public_key_jwk_from_spki("").is_err());
        // Valid SPKI DER, but for Ed25519 rather than P-256: it must not be
        // reinterpreted as a curve point.
        assert!(P::public_key_jwk_from_spki(
            "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE="
        )
        .is_err());
    }
}
