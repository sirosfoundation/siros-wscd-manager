#[cfg(feature = "plugin-r2ps")]
use async_trait::async_trait;
#[cfg(feature = "plugin-r2ps")]
use p256::elliptic_curve::sec1::ToEncodedPoint;
#[cfg(feature = "plugin-r2ps")]
use r2ps_client::{HsmKeyInfo, PakeClient, R2psClient, R2psRawSign, RawSign, Transport};
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
    Algorithm, AttestationChain, AuthMethod, GeneratedKey, KeyId, KeyInfo, OperationProgress,
    Signature,
};

/// R2PS plugin — remote PKCS#11 HSM signing via the R2PS protocol.
///
/// This plugin wraps `r2ps_client::R2psClient` and delegates key
/// generation and signing to a remote HSM. Authentication is performed
/// via OPAQUE (with PIN from `AuthCallback::request_pin`) or WebAuthn
/// (with assertion from `AuthCallback::request_webauthn_assertion`).
///
/// The underlying r2ps-client is synchronous; we hold it behind a Mutex
/// and call it from async context. For mobile apps, the Transport
/// implementation should use the host's HTTP stack.
#[cfg(feature = "plugin-r2ps")]
pub struct R2psPlugin<T: Transport, P: PakeClient> {
    inner: Mutex<R2psClient<T, P>>,
    config: R2psConfig,
}

#[cfg(feature = "plugin-r2ps")]
impl<T: Transport + Send + 'static, P: PakeClient + Send + 'static> R2psPlugin<T, P> {
    pub fn new(client: R2psClient<T, P>, config: R2psConfig) -> Self {
        Self {
            inner: Mutex::new(client),
            config,
        }
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
                // WebAuthn mode: the R2PS server issues a challenge, the host
                // performs the assertion, and we send the result back.
                // For now, signal that this auth mode requires the callback.
                Err(WscdError::Plugin(
                    "WebAuthn auth mode not yet implemented in R2PS plugin".into(),
                ))
            }
            other => Err(WscdError::Plugin(format!(
                "unknown R2PS auth mode: {other}"
            ))),
        }
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

        self.ensure_authenticated(auth).await?;

        progress
            .on_progress(OperationProgress::NetworkRoundTrip { step: 1, total: 1 })
            .await;

        let sig_bytes = {
            let mut client = self
                .inner
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;

            let mut raw = R2psRawSign::new(&mut client);
            raw.sign(kid.as_str().as_bytes(), data)
                .map_err(|e| WscdError::Plugin(format!("R2PS sign failed: {e}")))?
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
}
