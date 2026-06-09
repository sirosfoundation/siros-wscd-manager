use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::callbacks::{AuthCallback, Ctap2Transport, ProgressCallback};
use crate::error::{Result, WscdError};
use crate::traits::WscdPlugin;
use crate::types::{
    Algorithm, AttestationChain, AuthMethod, GeneratedKey, KeyId, KeyInfo, OperationProgress,
    Signature,
};

/// COSE algorithm identifier for ES256 (ECDSA w/ SHA-256 on P-256).
const COSE_ALG_ES256: i64 = -7;

/// RP ID used for rawSign credential scoping.
const RAW_SIGN_RP_ID: &str = "siros.wscd.preview-sign";

/// PreviewSign plugin — FIDO2 rawSign extension (Yubico CTAP2 previewSign v4).
///
/// This plugin delegates key generation and signing to a FIDO2
/// authenticator that supports the rawSign / previewSign extension.
/// The host application provides the CTAP2 transport (BLE/NFC/USB)
/// via the [`Ctap2Transport`] callback trait.
///
/// # Key storage
///
/// The authenticator generates keys on its secure element. The plugin
/// stores only the credential handle (key_handle) and public key
/// coordinates returned by `makeCredential`. The private key never
/// leaves the authenticator hardware.
///
/// # Attestation
///
/// The attestation object from `makeCredential` is stored and returned
/// via `attestation_chain()`. This provides hardware-backed proof that
/// the key was generated on a certified FIDO2 authenticator.
pub struct PreviewSignPlugin {
    transport: Box<dyn Ctap2Transport>,
    state: Mutex<PluginState>,
}

#[derive(Default, Serialize, Deserialize)]
struct PluginState {
    keys: Vec<StoredFidoKey>,
    next_id: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredFidoKey {
    /// Plugin-assigned key identifier (e.g., "fido-0").
    kid: String,
    /// CTAP2 credential handle (key_handle) from the authenticator.
    key_handle: Vec<u8>,
    /// Public key x-coordinate (32 bytes, P-256).
    pub_x: Vec<u8>,
    /// Public key y-coordinate (32 bytes, P-256).
    pub_y: Vec<u8>,
    /// COSE algorithm identifier.
    algorithm: i64,
    /// Raw attestation object from makeCredential.
    attestation_object: Vec<u8>,
    /// Creation timestamp (Unix seconds).
    created_at: i64,
}

/// Parsed result from a makeCredential response.
struct MakeCredentialResult {
    key_handle: Vec<u8>,
    pub_x: Vec<u8>,
    pub_y: Vec<u8>,
    algorithm: i64,
    attestation_object: Vec<u8>,
}

impl PreviewSignPlugin {
    /// Create a new PreviewSign plugin with the given CTAP2 transport.
    pub fn new(transport: Box<dyn Ctap2Transport>) -> Self {
        Self {
            transport,
            state: Mutex::new(PluginState::default()),
        }
    }

    /// Restore from a previously exported state blob.
    ///
    /// The state contains only credential handles and public keys —
    /// no private key material. The caller should still protect this
    /// data (the credential handles are opaque authenticator secrets).
    pub fn from_state(transport: Box<dyn Ctap2Transport>, state_bytes: &[u8]) -> Result<Self> {
        let state: PluginState = serde_json::from_slice(state_bytes)
            .map_err(|e| WscdError::Serialization(e.to_string()))?;
        Ok(Self {
            transport,
            state: Mutex::new(state),
        })
    }

    /// Export the plugin state for persistence.
    pub fn export_state(&self) -> Result<Vec<u8>> {
        let state = self
            .state
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        serde_json::to_vec(&*state).map_err(|e| WscdError::Serialization(e.to_string()))
    }

    fn find_key<'a>(state: &'a PluginState, kid: &KeyId) -> Result<&'a StoredFidoKey> {
        state
            .keys
            .iter()
            .find(|k| k.kid == kid.as_str())
            .ok_or_else(|| WscdError::KeyNotFound {
                kid: kid.to_string(),
            })
    }

    fn build_public_key_jwk(key: &StoredFidoKey) -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": Base64UrlUnpadded::encode_string(&key.pub_x),
            "y": Base64UrlUnpadded::encode_string(&key.pub_y),
        })
    }

    /// Parse a makeCredential attestation object to extract credential
    /// handle and public key coordinates.
    ///
    /// The attestation object is CBOR-encoded per WebAuthn §6.5.4:
    /// ```text
    /// attestationObject = {
    ///   "fmt": text,
    ///   "attStmt": ...,
    ///   "authData": bytes
    /// }
    /// ```
    /// authData contains: rpIdHash(32) || flags(1) || signCount(4) ||
    ///   attestedCredentialData { aaguid(16) || credIdLen(2) || credId(N) || credPubKey(COSE) }
    ///
    /// For the previewSign plugin, the host CTAP2 transport returns a
    /// structured response instead of raw CBOR. We define a simple
    /// JSON envelope that the host transport populates:
    ///
    /// ```json
    /// {
    ///   "key_handle": "<base64url>",
    ///   "public_key": { "x": "<base64url>", "y": "<base64url>" },
    ///   "algorithm": -7,
    ///   "attestation_object": "<base64url raw bytes>"
    /// }
    /// ```
    fn parse_make_credential_response(response: &[u8]) -> Result<MakeCredentialResult> {
        let v: serde_json::Value = serde_json::from_slice(response)
            .map_err(|e| WscdError::Plugin(format!("invalid makeCredential response: {e}")))?;

        let key_handle = Base64UrlUnpadded::decode_vec(
            v["key_handle"]
                .as_str()
                .ok_or_else(|| WscdError::Plugin("missing key_handle".into()))?,
        )
        .map_err(|e| WscdError::Crypto(e.to_string()))?;

        let pub_x = Base64UrlUnpadded::decode_vec(
            v["public_key"]["x"]
                .as_str()
                .ok_or_else(|| WscdError::Plugin("missing public_key.x".into()))?,
        )
        .map_err(|e| WscdError::Crypto(e.to_string()))?;

        let pub_y = Base64UrlUnpadded::decode_vec(
            v["public_key"]["y"]
                .as_str()
                .ok_or_else(|| WscdError::Plugin("missing public_key.y".into()))?,
        )
        .map_err(|e| WscdError::Crypto(e.to_string()))?;

        let algorithm = v["algorithm"].as_i64().unwrap_or(COSE_ALG_ES256);

        let attestation_object = if let Some(att) = v["attestation_object"].as_str() {
            Base64UrlUnpadded::decode_vec(att).map_err(|e| WscdError::Crypto(e.to_string()))?
        } else {
            // If the host didn't include the raw attestation object,
            // store the entire response as the attestation record.
            response.to_vec()
        };

        Ok(MakeCredentialResult {
            key_handle,
            pub_x,
            pub_y,
            algorithm,
            attestation_object,
        })
    }
}

#[async_trait]
impl WscdPlugin for PreviewSignPlugin {
    fn id(&self) -> &str {
        "fido2"
    }

    fn display_name(&self) -> &str {
        "FIDO2 previewSign (rawSign)"
    }

    fn auth_method(&self) -> AuthMethod {
        // The FIDO2 authenticator handles its own user verification
        // (PIN, biometric). From the plugin's perspective, no
        // additional auth callback is needed — the CTAP2 transport
        // layer triggers UV on the authenticator directly.
        AuthMethod::None
    }

    async fn generate_key(
        &self,
        _algorithm: Algorithm,
        _auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<GeneratedKey> {
        progress
            .on_progress(OperationProgress::Started {
                operation: "generate_key".to_string(),
            })
            .await;

        // Generate a random user ID for the credential
        let user_id: Vec<u8> = {
            use rand::RngCore;
            let mut buf = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut buf);
            buf.to_vec()
        };

        let client_data_hash: Vec<u8> = {
            use rand::RngCore;
            let mut buf = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut buf);
            buf.to_vec()
        };

        progress
            .on_progress(OperationProgress::WaitingForUser)
            .await;

        // Call the host CTAP2 transport to create a credential
        let response = self
            .transport
            .ctap2_make_credential(
                &client_data_hash,
                RAW_SIGN_RP_ID,
                &user_id,
                &[COSE_ALG_ES256],
            )
            .await?;

        let cr = Self::parse_make_credential_response(&response)?;
        let pub_x = cr.pub_x.clone();
        let pub_y = cr.pub_y.clone();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let kid = {
            let mut state = self
                .state
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;
            let kid = format!("fido-{}", state.next_id);
            state.next_id += 1;

            let stored = StoredFidoKey {
                kid: kid.clone(),
                key_handle: cr.key_handle,
                pub_x: cr.pub_x,
                pub_y: cr.pub_y,
                algorithm: cr.algorithm,
                attestation_object: cr.attestation_object,
                created_at: now,
            };
            state.keys.push(stored);
            kid
        };

        progress.on_progress(OperationProgress::Complete).await;

        Ok(GeneratedKey {
            kid: KeyId(kid.clone()),
            public_key_jwk: serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": Base64UrlUnpadded::encode_string(&pub_x),
                "y": Base64UrlUnpadded::encode_string(&pub_y),
            }),
        })
    }

    async fn sign(
        &self,
        kid: &KeyId,
        data: &[u8],
        _algorithm: Algorithm,
        _auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<Signature> {
        progress
            .on_progress(OperationProgress::Started {
                operation: "sign".to_string(),
            })
            .await;

        let key_handle = {
            let state = self
                .state
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;
            let key = Self::find_key(&state, kid)?;
            key.key_handle.clone()
        };

        progress
            .on_progress(OperationProgress::WaitingForUser)
            .await;

        // rawSign: the data-to-be-signed is passed directly to the
        // authenticator via the sign_requests parameter.
        let challenge = {
            use rand::RngCore;
            let mut buf = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut buf);
            buf.to_vec()
        };

        let sign_requests = vec![(key_handle, data.to_vec())];
        let signatures = self
            .transport
            .ctap2_get_assertion(RAW_SIGN_RP_ID, &challenge, &sign_requests)
            .await?;

        let sig = signatures
            .into_iter()
            .next()
            .ok_or_else(|| WscdError::Plugin("authenticator returned no signatures".into()))?;

        progress.on_progress(OperationProgress::Complete).await;

        Ok(Signature(sig))
    }

    async fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        let state = self
            .state
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        Ok(state
            .keys
            .iter()
            .map(|k| KeyInfo {
                kid: KeyId(k.kid.clone()),
                algorithm: Algorithm::ES256,
                plugin_id: "fido2".to_string(),
                created_at: k.created_at,
            })
            .collect())
    }

    async fn attestation_chain(&self, kid: &KeyId) -> Result<Option<AttestationChain>> {
        let state = self
            .state
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        let key = Self::find_key(&state, kid)?;

        if key.attestation_object.is_empty() {
            return Ok(None);
        }

        // The attestation object is the raw CBOR from the authenticator.
        // Return it as a single "certificate" in the chain — the consumer
        // knows how to parse the FIDO2 attestation format.
        Ok(Some(AttestationChain {
            certificates: vec![key.attestation_object.clone()],
        }))
    }

    async fn delete_key(&self, kid: &KeyId) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        let pos = state
            .keys
            .iter()
            .position(|k| k.kid == kid.as_str())
            .ok_or_else(|| WscdError::KeyNotFound {
                kid: kid.to_string(),
            })?;
        state.keys.remove(pos);
        Ok(())
    }

    async fn export_public_key(&self, kid: &KeyId) -> Result<serde_json::Value> {
        let state = self
            .state
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        let key = Self::find_key(&state, kid)?;
        Ok(Self::build_public_key_jwk(key))
    }

    fn supports_import(&self) -> bool {
        // FIDO2 keys are generated on the authenticator hardware.
        // You cannot import an existing private key. Migration to
        // this plugin always requires re-enrollment.
        false
    }
}
