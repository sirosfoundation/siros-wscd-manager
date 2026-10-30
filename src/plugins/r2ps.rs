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
use crate::factors::{
    derive_factors, AuthFactor, FactorCapability, RecordingAuth, SignOptions, SignOutcome,
};
#[cfg(feature = "plugin-r2ps")]
use crate::traits::WscdPlugin;
#[cfg(feature = "plugin-r2ps")]
use crate::types::{
    ActivateLifecycleRequest, ActivationOutcome, Algorithm, AttestationChain, AuthMethod,
    CertificationLevel, DestroyLifecycleRequest, DestroyMode, DestructionOutcome, FactorKind,
    GeneratedKey, KeyId, KeyInfo, KeyStorageType, LifecycleState, OperationProgress,
    RegisterLifecycleRequest, RegistrationOutcome, RotateLifecycleRequest, RotationOutcome, Secret,
    SecurityProperties, Signature,
};
#[cfg(feature = "plugin-r2ps")]
use crate::webauthn_uvm;

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
/// Whether this ceremony's assertions agree on a single `uvm`-classified
/// TS12 factor - see [`AuthCallbackCeremonyAdapter::record_assertion`].
#[cfg(feature = "plugin-r2ps")]
#[derive(Clone)]
enum FactorAgreement {
    /// No assertion recorded yet.
    Unseen,
    /// Every assertion recorded so far classified to the same factor.
    Agreed(AuthFactor),
    /// At least one assertion classified to nothing, or a later one
    /// disagreed with an earlier one - ambiguous, never reported.
    Disagreed,
}

#[cfg(feature = "plugin-r2ps")]
struct AuthCallbackCeremonyAdapter<'a> {
    auth: &'a dyn AuthCallback,
    /// Assertions the host returned, and how many of them carried the
    /// authenticator-data UV flag. The flag says user verification happened,
    /// never HOW (PIN, biometric, passcode) - unless `uvm` closes that gap,
    /// see `verified_factor` below.
    assertions: std::sync::atomic::AtomicUsize,
    uv_assertions: std::sync::atomic::AtomicUsize,
    /// A TS12 factor classified from the `uvm` WebAuthn extension (WebAuthn
    /// L2 §10.4), parsed directly out of each assertion's signed
    /// `authenticator_data` - see `crate::webauthn_uvm`'s module doc for
    /// what this does and does not prove, and
    /// `AuthCallbackCeremonyAdapter::agreed_verified_factor`'s doc for why
    /// this manager cannot itself guarantee the host's WebAuthn ceremony
    /// requested `uvm` (unlike the browser previewSign transport in
    /// `crate::wasm_fido2`, R2PS's WebAuthn ceremony runs entirely inside
    /// the host's own `request_webauthn_assertion` implementation - this
    /// crate never calls `navigator.credentials` for R2PS). When the host
    /// does request it, this is parsed and used for free; when it does not,
    /// `agreed_verified_factor()` is always `None` and behaviour is
    /// unchanged from before this existed.
    verified_factor: Mutex<FactorAgreement>,
}

#[cfg(feature = "plugin-r2ps")]
impl<'a> AuthCallbackCeremonyAdapter<'a> {
    fn new(auth: &'a dyn AuthCallback) -> Self {
        Self {
            auth,
            assertions: std::sync::atomic::AtomicUsize::new(0),
            uv_assertions: std::sync::atomic::AtomicUsize::new(0),
            verified_factor: Mutex::new(FactorAgreement::Unseen),
        }
    }

    fn record_assertion(&self, authenticator_data_b64: &str) {
        use std::sync::atomic::Ordering::Relaxed;
        self.assertions.fetch_add(1, Relaxed);
        if authenticator_data_uv_flag(authenticator_data_b64) {
            self.uv_assertions.fetch_add(1, Relaxed);
        }

        let classified = classify_authenticator_data_uvm(authenticator_data_b64);
        let mut state = self
            .verified_factor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = match (&*state, classified) {
            (FactorAgreement::Unseen, Some(f)) => FactorAgreement::Agreed(f),
            (FactorAgreement::Agreed(prev), Some(f)) if *prev == f => FactorAgreement::Agreed(f),
            _ => FactorAgreement::Disagreed,
        };
    }

    /// Every assertion of this ceremony was user-verified (and there was one).
    fn all_assertions_user_verified(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let n = self.assertions.load(Relaxed);
        n > 0 && self.uv_assertions.load(Relaxed) == n
    }

    /// A TS12 factor every assertion of this ceremony agreed on, for a
    /// ceremony where every assertion was also user-verified - `None`
    /// whenever that is not the case (no assertion classified, assertions
    /// disagreed, or UV was not confirmed for all of them). This manager
    /// does not control whether the host's `request_webauthn_assertion`
    /// implementation requested the `uvm` extension at all (see
    /// [`AuthCallbackCeremonyAdapter`]'s doc comment) - it can only use the
    /// result opportunistically when the host did.
    fn agreed_verified_factor(&self) -> Option<AuthFactor> {
        if !self.all_assertions_user_verified() {
            return None;
        }
        match &*self
            .verified_factor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            FactorAgreement::Agreed(f) => Some(f.clone()),
            FactorAgreement::Unseen | FactorAgreement::Disagreed => None,
        }
    }
}

/// Base64url-decode a WebAuthn `authenticatorData` blob. Shared by the UV
/// flag check and the `uvm` classification below - both read the same bytes.
#[cfg(feature = "plugin-r2ps")]
fn decode_authenticator_data(authenticator_data_b64: &str) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(authenticator_data_b64).ok()
}

/// The UV flag (bit 2 of the flags byte at offset 32) of a base64url
/// authenticator-data blob. Anything too short to carry flags is not
/// user-verified.
#[cfg(feature = "plugin-r2ps")]
fn authenticator_data_uv_flag(authenticator_data_b64: &str) -> bool {
    decode_authenticator_data(authenticator_data_b64)
        .and_then(|d| d.get(32).copied())
        .is_some_and(|flags| flags & 0x04 != 0)
}

/// `uvm` classification of a base64url authenticator-data blob - see
/// `crate::webauthn_uvm`. `None` whenever `uvm` is absent or unclassifiable;
/// never a guess.
#[cfg(feature = "plugin-r2ps")]
fn classify_authenticator_data_uvm(authenticator_data_b64: &str) -> Option<AuthFactor> {
    let bytes = decode_authenticator_data(authenticator_data_b64)?;
    let entries = webauthn_uvm::parse_uvm_extension(&bytes)?;
    webauthn_uvm::classify_uvm_for_ts12(&entries)
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

        self.record_assertion(&result.authenticator_data);
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

    /// Ask the user for the OPAQUE PIN if this sign needs one: always when
    /// `fresh`, otherwise only when there is no cached session. `None` means
    /// the cached session will be reused.
    ///
    /// This only COLLECTS the PIN. It must not authenticate: the PIN prompt
    /// is an await point and the client mutex is a synchronous one, so the
    /// authentication and the signature that depends on its session have to
    /// run together in one critical section afterwards (see `sign_with_factors`).
    /// Otherwise a concurrent sign could replace the shared session between
    /// them and the signature would be made under another caller's session
    /// while reporting this caller's PIN factor.
    async fn collect_opaque_pin(
        &self,
        auth: &dyn AuthCallback,
        fresh: bool,
    ) -> Result<Option<Secret>> {
        if self.config.auth_mode != "opaque" {
            return Err(WscdError::Plugin(format!(
                "unknown R2PS auth mode: {}",
                self.config.auth_mode
            )));
        }
        if !fresh && self.lock_inner().is_authenticated() {
            return Ok(None);
        } // lock dropped before the await below
        Ok(Some(auth.request_pin("r2ps").await?))
    }

    /// Perform FIDO2 registration (provision a new credential for this R2PS client).
    ///
    /// This should be called once during initial provisioning or when
    /// credentials need to be rotated.
    pub async fn register_fido2(&self, auth: &dyn AuthCallback) -> Result<()> {
        let ceremony = AuthCallbackCeremonyAdapter::new(auth);
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
        ceremony: &AuthCallbackCeremonyAdapter<'_>,
        kid: &KeyId,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut client = self.lock_inner();
        client
            .sign_with_sad(
                ceremony,
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
        algorithm: Algorithm,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<Signature> {
        Ok(self
            .sign_with_factors(
                kid,
                data,
                algorithm,
                &SignOptions::default(),
                auth,
                progress,
            )
            .await?
            .signature)
    }

    /// OPAQUE: possession `key_in_remote_wscd`, plus a knowledge factor whose
    /// class is measured from the PIN typed for THIS sign. When a cached
    /// session was reused (no PIN asked), no knowledge factor is reported and
    /// the outcome says so; `require_fresh_user_authentication` forces the
    /// PIN round trip.
    ///
    /// WebAuthn: possession `key_in_remote_wscd`. The assertion is bound to
    /// the hash (SAD), but that does not prove the user verification itself
    /// was uncached, and the host callback is told nothing about freshness,
    /// so `require_fresh_user_authentication` is refused with `Unsupported`
    /// BEFORE signing regardless of anything below. The UV flag alone does
    /// not say how the user was verified; when the host's WebAuthn ceremony
    /// requested the `uvm` extension and every assertion of this ceremony
    /// agrees on one classifiable method (see
    /// `AuthCallbackCeremonyAdapter::agreed_verified_factor`), that names
    /// the second category on its own. Otherwise it still needs
    /// `host_verified_factor`, otherwise the outcome is short.
    async fn sign_with_factors(
        &self,
        kid: &KeyId,
        data: &[u8],
        _algorithm: Algorithm,
        options: &SignOptions,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<SignOutcome> {
        options.validate()?;
        if options.require_fresh_user_authentication && self.config.auth_mode == "webauthn" {
            return Err(WscdError::Unsupported {
                plugin: "r2ps".to_string(),
                op: "require_fresh_user_authentication in WebAuthn mode".to_string(),
            });
        }
        progress
            .on_progress(OperationProgress::Started {
                operation: "sign".to_string(),
            })
            .await;

        // Signing requires 2FA authentication
        progress
            .on_progress(OperationProgress::WaitingForUser)
            .await;

        let (sig_bytes, factors) = if self.config.auth_mode == "webauthn" {
            // WebAuthn: use sign_with_sad for SCAL2-compliant hash binding.
            // The FIDO2 session is bound to the specific hash being signed.
            progress
                .on_progress(OperationProgress::NetworkRoundTrip { step: 1, total: 1 })
                .await;

            let ceremony = AuthCallbackCeremonyAdapter::new(auth);
            let result = self.sign_with_sad_sync(&ceremony, kid, data)?;
            // Record amr: hardware key + proof-of-possession + PIN (SAD implies PIN binding)
            if let Ok(mut amr) = self.last_amr.lock() {
                *amr = vec!["hwk".to_string(), "pop".to_string(), "pin".to_string()];
            }
            let factors = derive_factors(
                "key_in_remote_wscd",
                None,
                ceremony.all_assertions_user_verified(),
                ceremony.agreed_verified_factor().as_ref(),
                options,
                "the WebAuthn assertion did not carry the user-verified flag",
            );
            (result, factors)
        } else {
            // OPAQUE: collect the PIN (an await), then authenticate and sign
            // in ONE critical section so the session this sign uses is the one
            // this PIN established, even with concurrent callers.
            let recorder = RecordingAuth::new(auth);
            let pin = self
                .collect_opaque_pin(&recorder, options.require_fresh_user_authentication)
                .await?;

            progress
                .on_progress(OperationProgress::NetworkRoundTrip { step: 1, total: 1 })
                .await;

            let mut client = self.lock_inner();
            if let Some(pin) = &pin {
                // A failure here propagates: a fresh authentication never
                // falls back to the session it was meant to replace.
                client
                    .authenticate(pin)
                    .map_err(|e| WscdError::Plugin(format!("OPAQUE auth failed: {e}")))?;
            }
            let mut raw = R2psRawSign::new(&mut client);
            let result = raw
                .sign(kid.as_str().as_bytes(), data)
                .map_err(|e| WscdError::Plugin(format!("R2PS sign failed: {e}")))?;
            // Record amr: password-authenticated key exchange
            if let Ok(mut amr) = self.last_amr.lock() {
                *amr = vec!["pwd".to_string()];
            }
            let factors = derive_factors(
                "key_in_remote_wscd",
                recorder.last_pin(),
                false,
                None,
                options,
                "no PIN was entered for this sign: a cached session was reused \
                 (set require_fresh_user_authentication)",
            );
            (result, factors)
        };

        progress.on_progress(OperationProgress::Complete).await;

        Ok(SignOutcome {
            signature: Signature(sig_bytes),
            factors,
        })
    }

    fn authentication_capability(&self, _kid: &KeyId) -> Result<FactorCapability> {
        Ok(match self.config.auth_mode.as_str() {
            // The PIN is asked for through AuthCallback when the sign runs.
            "opaque" => FactorCapability::can(),
            // Conservative on purpose: whether the host's WebAuthn ceremony
            // requested `uvm`, and whether it comes back classifiable, is
            // only known once a real assertion runs - this call must not
            // prompt or guess ahead of time. `host_verified_factor` stays
            // the documented fallback.
            "webauthn" => FactorCapability::with_host_factor(
                "WebAuthn user verification does not say how the user was verified unless \
                 the host's ceremony requested the uvm extension and it classifies cleanly \
                 (known only once the sign runs); until then, or if it doesn't, \
                 the host must supply host_verified_factor",
            ),
            other => FactorCapability::cannot(format!("unknown R2PS auth mode: {other}")),
        })
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
        // This plugin has no local attestation artifact to inspect, full
        // stop — the key lives on a remote HSM this process never touches
        // directly, and nothing in the R2PS protocol hands this plugin a
        // chain or any other structural evidence about that HSM. See
        // `security_properties`'s `certification` comment for why that
        // means `CertificationLevel::Unattested`, not a placeholder pending
        // a future HSM-vendor-attestation integration.
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
            // A remote HSM is not a HIGHER tier than a local one — it's
            // just DIFFERENT, and this plugin has zero local, structural
            // evidence to check (see `attestation_chain`, which
            // unconditionally returns `None`: there is no artifact here).
            // `KeyStorageType::RemoteHsm` above already carries the
            // "it's remote" fact on its own, separate axis — a deployment's
            // own assurance-scheme config (SDK side) remains free to credit
            // a *specific* known HSM deployment with whatever assurance
            // label its out-of-band provenance actually supports; this
            // plugin just stops pretending to know that itself.
            certification: CertificationLevel::Unattested,
            amr,
        })
    }

    fn supports_lifecycle(&self) -> bool {
        true
    }

    fn lifecycle_entry(&self, context_id: &str) -> Option<(FactorKind, LifecycleState, i64)> {
        let lifecycle = self.lock_lifecycle();
        lifecycle
            .get(context_id)
            .map(|ctx| (ctx.factor_kind, ctx.state, ctx.updated_at))
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
                let ceremony = AuthCallbackCeremonyAdapter::new(auth);
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

/// TS12 factors and fresh-authentication for the OPAQUE mode, against a
/// signing mock server so a whole authenticate-then-sign round trip runs.
#[cfg(all(test, feature = "plugin-r2ps"))]
mod ts12_factor_tests {
    use super::*;
    use crate::callbacks::{NoopProgress, ProgressCallback};
    use crate::factors::{AuthFactor, FactorCategory};
    use crate::types::Secret;
    use base64ct::{Base64, Base64UrlUnpadded, Encoding};
    use p256::elliptic_curve::Generate;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    type Log = Arc<std::sync::Mutex<Vec<&'static str>>>;

    fn count(log: &Log, what: &str) -> usize {
        log.lock().unwrap().iter().filter(|e| **e == what).count()
    }

    /// A server that answers the OPAQUE handshake and `sign_ecdsa`, signing
    /// its responses so the client's verification passes.
    struct MockServer {
        key: p256::SecretKey,
        log: Log,
    }

    impl Transport for MockServer {
        fn send(&self, body: &[u8]) -> r2ps_client::Result<Vec<u8>> {
            let compact = std::str::from_utf8(body).unwrap();
            let payload_b64 = compact.split('.').nth(1).unwrap();
            let request: serde_json::Value =
                serde_json::from_slice(&Base64UrlUnpadded::decode_vec(payload_b64).unwrap())
                    .unwrap();
            let data = match request["type"].as_str().unwrap() {
                "2fa_authenticate" => match request["data"]["state"].as_str().unwrap() {
                    "evaluate" => {
                        self.log.lock().unwrap().push("evaluate");
                        serde_json::json!({
                            "session_id": "s1",
                            "p_data": Base64UrlUnpadded::encode_string(&[0u8; 32]),
                        })
                    }
                    _ => {
                        self.log.lock().unwrap().push("finalize");
                        serde_json::json!({})
                    }
                },
                "sign_ecdsa" => {
                    self.log.lock().unwrap().push("sign");
                    serde_json::json!(Base64::encode_string(b"signature"))
                }
                other => panic!("unexpected request type {other}"),
            };
            let response = serde_json::json!({
                "ver": "1.0", "nonce": "n", "iat": 0, "data": data, "success": true
            });
            r2ps_client::jws::sign_jws(
                response.to_string().as_bytes(),
                &p256::ecdsa::SigningKey::from(&self.key),
                None,
                Some("r2ps-response+jwt"),
            )
            .map(String::into_bytes)
        }
    }

    struct StubPake;

    impl PakeClient for StubPake {
        fn registration_init(&mut self, _: &[u8]) -> r2ps_client::Result<Vec<u8>> {
            Ok(vec![0u8; 32])
        }
        fn registration_finalize(&mut self, _: &[u8]) -> r2ps_client::Result<Vec<u8>> {
            Ok(vec![0u8; 32])
        }
        fn auth_init(&mut self, _: &[u8]) -> r2ps_client::Result<Vec<u8>> {
            Ok(vec![0u8; 32])
        }
        fn auth_finalize(&mut self, _: &[u8]) -> r2ps_client::Result<(Vec<u8>, Vec<u8>)> {
            Ok((vec![0u8; 32], vec![0u8; 32]))
        }
    }

    /// Counts PIN prompts; `None` PIN = the user cancels.
    struct CountingAuth {
        pin: Option<&'static [u8]>,
        prompts: AtomicUsize,
    }

    impl CountingAuth {
        fn new(pin: &'static [u8]) -> Self {
            Self {
                pin: Some(pin),
                prompts: AtomicUsize::new(0),
            }
        }
        fn prompts(&self) -> usize {
            self.prompts.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl AuthCallback for CountingAuth {
        async fn request_pin(&self, plugin_id: &str) -> Result<Secret> {
            assert_eq!(plugin_id, "r2ps");
            self.prompts.fetch_add(1, Ordering::SeqCst);
            self.pin
                .map(|p| Secret(p.to_vec()))
                .ok_or(WscdError::AuthCancelled)
        }
        async fn request_webauthn_assertion(
            &self,
            _: &str,
            _: &[u8],
            _: &str,
            _: &[Vec<u8>],
        ) -> Result<Vec<u8>> {
            unreachable!("OPAQUE mode never asks for a WebAuthn assertion")
        }
    }

    fn opaque_plugin() -> (R2psPlugin<MockServer, StubPake>, Log) {
        plugin_in_mode("opaque", "")
    }

    fn plugin_in_mode(auth_mode: &str, rp_id: &str) -> (R2psPlugin<MockServer, StubPake>, Log) {
        let server_key = p256::SecretKey::generate();
        let log: Log = Arc::default();
        let client = R2psClient::new(
            "client".into(),
            "ctx".into(),
            p256::SecretKey::generate(),
            server_key.public_key(),
            MockServer {
                key: server_key,
                log: log.clone(),
            },
            StubPake,
        );
        let cfg = R2psConfig {
            server_url: "https://r2ps.invalid/r2ps".into(),
            client_id: "client".into(),
            context: "ctx".into(),
            auth_mode: auth_mode.into(),
            rp_id: rp_id.into(),
            allowed_credential_ids: vec![],
        };
        (R2psPlugin::new(client, cfg).unwrap(), log)
    }

    fn kid() -> KeyId {
        KeyId("k".into())
    }

    async fn sign(
        plugin: &R2psPlugin<MockServer, StubPake>,
        options: &SignOptions,
        auth: &CountingAuth,
    ) -> Result<SignOutcome> {
        plugin
            .sign_with_factors(
                &kid(),
                b"tbs",
                Algorithm::ES256,
                options,
                auth,
                &NoopProgress,
            )
            .await
    }

    fn fresh() -> SignOptions {
        SignOptions {
            require_fresh_user_authentication: true,
            ..Default::default()
        }
    }

    /// The headline requirement (#101): a flagged sign must ask for the PIN
    /// again even though a session is cached, and the factors it reports
    /// belong to that PIN entry.
    #[tokio::test]
    async fn a_fresh_sign_asks_for_the_pin_even_with_a_cached_session() {
        let (plugin, log) = opaque_plugin();
        let auth = CountingAuth::new(b"1234");

        sign(&plugin, &SignOptions::default(), &auth).await.unwrap();
        assert_eq!(auth.prompts(), 1, "first sign has no session yet");

        let before = auth.prompts();
        let outcome = sign(&plugin, &fresh(), &auth).await.unwrap();
        assert_eq!(
            auth.prompts(),
            before + 1,
            "a flagged sign must complete only through AuthCallback::request_pin"
        );
        assert_eq!(count(&log, "evaluate"), 2, "a new OPAQUE round trip");
        assert!(outcome.factors.satisfies_two_categories());
        assert_eq!(outcome.signature.0, b"signature");
    }

    /// Default behaviour is unchanged (one prompt, then the session is
    /// reused) and the factors do not pretend otherwise: a sign that reused
    /// the session reports possession only, with the reason.
    #[tokio::test]
    async fn a_sign_that_reused_the_session_does_not_claim_a_knowledge_factor() {
        let (plugin, log) = opaque_plugin();
        let auth = CountingAuth::new(b"1234");

        let first = sign(&plugin, &SignOptions::default(), &auth).await.unwrap();
        assert!(first.factors.satisfies_two_categories());

        let second = sign(&plugin, &SignOptions::default(), &auth).await.unwrap();
        assert_eq!(auth.prompts(), 1, "default signing reuses the session");
        assert_eq!(count(&log, "evaluate"), 1);
        assert!(!second.factors.satisfies_two_categories());
        assert_eq!(
            second.factors.factors(),
            &[AuthFactor::new(FactorCategory::Possession, "key_in_remote_wscd").unwrap()]
        );
        assert!(second
            .factors
            .shortfall()
            .unwrap()
            .contains("cached session"));

        // The plain sign() path is the same call with default options.
        plugin
            .sign(&kid(), b"tbs", Algorithm::ES256, &auth, &NoopProgress)
            .await
            .unwrap();
        assert_eq!(auth.prompts(), 1);
    }

    /// The PIN length class is measured from what was typed for this sign.
    #[tokio::test]
    async fn the_pin_class_comes_from_the_pin_entered_for_this_sign() {
        for (pin, method) in [
            (&b"12345"[..], "pin_less_than_6_digits"),
            (&b"123456"[..], "pin_6_or_more_digits"),
            (&b"correct horse"[..], "passphrase_12_or_more_chars"),
        ] {
            let (plugin, _) = opaque_plugin();
            let auth = CountingAuth::new(pin);
            let outcome = sign(&plugin, &fresh(), &auth).await.unwrap();
            assert_eq!(
                outcome.factors.factors(),
                &[
                    AuthFactor::new(FactorCategory::Possession, "key_in_remote_wscd").unwrap(),
                    AuthFactor::new(FactorCategory::Knowledge, method).unwrap(),
                ]
            );
        }
        // An unclassifiable secret is not guessed at.
        let (plugin, _) = opaque_plugin();
        let outcome = sign(&plugin, &fresh(), &CountingAuth::new(&[0xff]))
            .await
            .unwrap();
        assert!(!outcome.factors.satisfies_two_categories());
        assert!(outcome.factors.shortfall().unwrap().contains("classified"));
    }

    /// A cancelled re-authentication must fail the sign, never fall back to
    /// the cached session.
    #[tokio::test]
    async fn a_failed_fresh_authentication_does_not_fall_back_to_the_cached_session() {
        let (plugin, _) = opaque_plugin();
        sign(
            &plugin,
            &SignOptions::default(),
            &CountingAuth::new(b"1234"),
        )
        .await
        .unwrap();

        let cancelling = CountingAuth {
            pin: None,
            prompts: AtomicUsize::new(0),
        };
        let err = sign(&plugin, &fresh(), &cancelling).await.unwrap_err();
        assert!(matches!(err, WscdError::AuthCancelled), "{err}");
    }

    /// Yields at every await so concurrent signs interleave as much as the
    /// scheduler allows.
    struct YieldingProgress;

    #[async_trait]
    impl ProgressCallback for YieldingProgress {
        async fn on_progress(&self, _: OperationProgress) {
            tokio::task::yield_now().await;
        }
    }

    struct YieldingAuth(CountingAuth);

    #[async_trait]
    impl AuthCallback for YieldingAuth {
        async fn request_pin(&self, plugin_id: &str) -> Result<Secret> {
            tokio::task::yield_now().await;
            self.0.request_pin(plugin_id).await
        }
        async fn request_webauthn_assertion(
            &self,
            a: &str,
            b: &[u8],
            c: &str,
            d: &[Vec<u8>],
        ) -> Result<Vec<u8>> {
            self.0.request_webauthn_assertion(a, b, c, d).await
        }
    }

    /// Two concurrent fresh signs must each sign under the session their OWN
    /// authentication established: the server sees authenticate-then-sign
    /// twice, never both authentications before either signature (which
    /// would let one sign run under the other's session while reporting its
    /// own PIN factor).
    #[tokio::test]
    async fn concurrent_fresh_signs_do_not_interleave_authentication_and_signing() {
        let (plugin, log) = opaque_plugin();
        let a = YieldingAuth(CountingAuth::new(b"1234"));
        let b = YieldingAuth(CountingAuth::new(b"123456"));
        async fn one(
            plugin: &R2psPlugin<MockServer, StubPake>,
            auth: &YieldingAuth,
        ) -> Result<SignOutcome> {
            plugin
                .sign_with_factors(
                    &kid(),
                    b"tbs",
                    Algorithm::ES256,
                    &fresh(),
                    auth,
                    &YieldingProgress,
                )
                .await
        }
        let (ra, rb) = tokio::join!(one(&plugin, &a), one(&plugin, &b));
        let (ra, rb) = (ra.unwrap(), rb.unwrap());

        assert_eq!(
            *log.lock().unwrap(),
            ["evaluate", "finalize", "sign", "evaluate", "finalize", "sign"]
        );
        // Each outcome reports the PIN class of its own caller.
        assert_eq!(ra.factors.factors()[1].method, "pin_less_than_6_digits");
        assert_eq!(rb.factors.factors()[1].method, "pin_6_or_more_digits");
    }

    /// A WebAuthn sign cannot prove its user verification was uncached, so
    /// a fresh request is refused before anything is sent or signed.
    #[tokio::test]
    async fn webauthn_refuses_a_fresh_request_before_signing() {
        let (plugin, log) = plugin_in_mode("webauthn", "wallet.example.com");
        let auth = CountingAuth::new(b"1234");
        let err = sign(&plugin, &fresh(), &auth).await.unwrap_err();
        assert!(matches!(err, WscdError::Unsupported { .. }), "{err}");
        assert!(log.lock().unwrap().is_empty(), "nothing reached the server");
        assert_eq!(auth.prompts(), 0);
    }

    #[test]
    fn capabilities_follow_the_auth_mode() {
        let (opaque, _) = opaque_plugin();
        let cap = opaque.authentication_capability(&kid()).unwrap();
        assert!(cap.can_reach_two_categories && !cap.requires_host_verified_factor);

        // WebAuthn cannot say how the user was verified: possession alone
        // unless the host supplies the second factor.
        let (webauthn, _) = plugin_in_mode("webauthn", "wallet.example.com");
        let cap = webauthn.authentication_capability(&kid()).unwrap();
        assert!(!cap.can_reach_two_categories && cap.requires_host_verified_factor);
        assert!(cap.reason.is_some());
    }

    /// The UV flag is bit 2 of the flags byte after the 32-byte rpIdHash.
    #[test]
    fn the_uv_flag_is_read_from_the_authenticator_data() {
        let enc = |flags: u8| {
            let mut d = vec![0u8; 37];
            d[32] = flags;
            Base64UrlUnpadded::encode_string(&d)
        };
        assert!(authenticator_data_uv_flag(&enc(0x05))); // UP + UV
        assert!(!authenticator_data_uv_flag(&enc(0x01))); // UP only
        assert!(!authenticator_data_uv_flag("AAAA")); // too short
        assert!(!authenticator_data_uv_flag("not base64 !!"));
    }

    // ── Issue #105 (Angle B): R2PS WebAuthn `uvm` classification ──────────
    //
    // R2PS's own WebAuthn ceremony runs entirely inside the host's
    // `request_webauthn_assertion` implementation (this crate never calls
    // `navigator.credentials` for R2PS - see `AuthCallbackCeremonyAdapter`'s
    // doc comment), so these tests exercise the classification state
    // machine directly against crafted `authenticator_data`, the same way
    // `the_uv_flag_is_read_from_the_authenticator_data` above tests the UV
    // flag in isolation. A full end-to-end `sign_with_factors` test through
    // a real `sign_with_sad` round trip is not added here: `MockServer`
    // only simulates the OPAQUE `2fa_authenticate`/`sign_ecdsa` wire
    // protocol, never R2PS's separate FIDO2/WebAuthn service calls - no
    // existing test exercises a non-refused WebAuthn sign end-to-end
    // either (`webauthn_refuses_a_fresh_request_before_signing` is the only
    // one, and it deliberately refuses before any request is sent). Adding
    // that simulation is a pre-existing gap, not one this PR introduces;
    // see the PR description for why it's left as a follow-up rather than
    // invented here.

    /// A getAssertion authenticatorData carrying a real `uvm` extension
    /// (WebAuthn L2 §10.4) - the shape a host's `request_webauthn_assertion`
    /// would need to return for this manager to classify a factor at all.
    fn authenticator_data_with_uvm(user_verified: bool, entries: &[(u32, u16, u16)]) -> String {
        let mut data = vec![0u8; 32]; // rpIdHash
        let mut flags = 0x80u8; // ED (extensions present)
        if user_verified {
            flags |= 0x04; // UV
        }
        data.push(flags);
        data.extend_from_slice(&[0, 0, 0, 1]); // signCount

        let uvm_array: Vec<ciborium::Value> = entries
            .iter()
            .map(|(m, k, mt)| {
                ciborium::Value::Array(vec![
                    ciborium::Value::Integer((*m).into()),
                    ciborium::Value::Integer((*k).into()),
                    ciborium::Value::Integer((*mt).into()),
                ])
            })
            .collect();
        let extensions = ciborium::Value::Map(vec![(
            ciborium::Value::Text("uvm".into()),
            ciborium::Value::Array(uvm_array),
        )]);
        ciborium::ser::into_writer(&extensions, &mut data).unwrap();
        Base64UrlUnpadded::encode_string(&data)
    }

    #[test]
    fn classify_authenticator_data_uvm_reads_the_signed_extension() {
        let b64 = authenticator_data_with_uvm(true, &[(0x04, 1, 1)]); // passcode, internal
        let factor = classify_authenticator_data_uvm(&b64).unwrap();
        assert_eq!(
            factor,
            AuthFactor::new(FactorCategory::Knowledge, "other").unwrap()
        );
        // A biometric is `*_INTERNAL` to the authenticator, which says
        // nothing about whether that authenticator is the wallet device's
        // own: unclassified, never `_external`.
        let fp = authenticator_data_with_uvm(true, &[(0x02, 1, 1)]);
        assert!(classify_authenticator_data_uvm(&fp).is_none());
        assert!(classify_authenticator_data_uvm("not base64 !!").is_none());
    }

    /// A single user-verified assertion with a classifiable `uvm` entry is
    /// what `sign_with_factors` consults for the WebAuthn second category -
    /// this is the "succeeds with an attested factor" half of issue #105's
    /// requested test (the other half, fresh-auth still refusing, is
    /// `webauthn_refuses_a_fresh_request_before_signing` above, unchanged).
    #[test]
    fn ceremony_reports_a_single_assertions_classified_factor() {
        let auth = CountingAuth::new(b"unused");
        let ceremony = AuthCallbackCeremonyAdapter::new(&auth);
        ceremony.record_assertion(&authenticator_data_with_uvm(true, &[(0x04, 1, 1)])); // passcode
        assert_eq!(
            ceremony.agreed_verified_factor(),
            Some(AuthFactor::new(FactorCategory::Knowledge, "other").unwrap())
        );
    }

    /// `uvm` present but the UV flag absent must never be trusted - a
    /// classifiable method with no confirmed verification is not a factor.
    #[test]
    fn ceremony_ignores_uvm_when_uv_flag_is_not_set() {
        let auth = CountingAuth::new(b"unused");
        let ceremony = AuthCallbackCeremonyAdapter::new(&auth);
        ceremony.record_assertion(&authenticator_data_with_uvm(false, &[(0x04, 1, 1)])); // passcode: classifiable, so only the UV guard can reject it
        assert!(ceremony.agreed_verified_factor().is_none());
    }

    /// Two assertions in one ceremony that classify to DIFFERENT factors are
    /// ambiguous - which one actually gated the signature is not knowable,
    /// so neither is reported.
    #[test]
    fn ceremony_disagreement_across_assertions_is_unclassified() {
        let auth = CountingAuth::new(b"unused");
        let ceremony = AuthCallbackCeremonyAdapter::new(&auth);
        // Both classify successfully (pattern, then passcode), so only the
        // agreement guard can reject them.
        ceremony.record_assertion(&authenticator_data_with_uvm(true, &[(0x80, 1, 1)])); // pattern
        ceremony.record_assertion(&authenticator_data_with_uvm(true, &[(0x04, 1, 1)])); // passcode
        assert!(ceremony.agreed_verified_factor().is_none());
    }

    /// An unclassifiable assertion (a biometric, whose `_device`/`_external`
    /// split is unknowable) mixed with a classified one must not let the
    /// classified one stand for the whole ceremony.
    #[test]
    fn ceremony_with_an_unclassified_assertion_reports_no_factor() {
        let auth = CountingAuth::new(b"unused");
        let ceremony = AuthCallbackCeremonyAdapter::new(&auth);
        ceremony.record_assertion(&authenticator_data_with_uvm(true, &[(0x04, 1, 1)])); // passcode
        ceremony.record_assertion(&authenticator_data_with_uvm(true, &[(0x02, 1, 1)])); // fingerprint
        assert!(ceremony.agreed_verified_factor().is_none());
    }

    /// Two assertions that classify to the SAME factor stay agreed.
    #[test]
    fn ceremony_agrees_across_consistent_assertions() {
        let auth = CountingAuth::new(b"unused");
        let ceremony = AuthCallbackCeremonyAdapter::new(&auth);
        ceremony.record_assertion(&authenticator_data_with_uvm(true, &[(0x04, 1, 1)]));
        ceremony.record_assertion(&authenticator_data_with_uvm(true, &[(0x04, 1, 1)]));
        assert_eq!(
            ceremony.agreed_verified_factor(),
            Some(AuthFactor::new(FactorCategory::Knowledge, "other").unwrap())
        );
    }

    /// A platform authenticator's own fingerprint reports `*_INTERNAL`, same
    /// as a roaming key's. The ceremony must report NO factor for it, so a
    /// correct host-supplied `face_device`/`fingerprint_device` is used
    /// instead of being overridden by a guessed `_external`; with no host
    /// factor the outcome stays short (fail closed), never a guessed
    /// inherence method.
    #[test]
    fn biometric_uvm_does_not_override_host_device_factor_and_fails_closed() {
        let auth = CountingAuth::new(b"unused");
        let ceremony = AuthCallbackCeremonyAdapter::new(&auth);
        ceremony.record_assertion(&authenticator_data_with_uvm(true, &[(0x02, 1, 1)]));
        let plugin_factor = ceremony.agreed_verified_factor();
        assert!(plugin_factor.is_none());

        let host = AuthFactor::new(FactorCategory::Inherence, "fingerprint_device").unwrap();
        let with_host = crate::factors::derive_factors(
            "key_in_remote_wscd",
            None,
            true,
            plugin_factor.as_ref(),
            &crate::factors::SignOptions {
                host_verified_factor: Some(host.clone()),
                ..Default::default()
            },
            "no UV",
        );
        assert!(with_host.satisfies_two_categories());
        assert_eq!(with_host.factors()[1], host);

        let without_host = crate::factors::derive_factors(
            "key_in_remote_wscd",
            None,
            true,
            plugin_factor.as_ref(),
            &crate::factors::SignOptions::default(),
            "no UV",
        );
        assert!(!without_host.satisfies_two_categories());
        assert!(without_host.shortfall().is_some());
    }
}
