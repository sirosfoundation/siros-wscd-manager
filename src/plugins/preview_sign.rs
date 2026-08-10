use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::elliptic_curve::sec1::ToSec1Point;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::callbacks::{AuthCallback, Ctap2Transport, ProgressCallback};
use crate::error::{Result, WscdError};
use crate::preview_sign_protocol::{self, GenerateKeyInput, SignInput, ARKG_P256_ESP256};
use crate::traits::WscdPlugin;
use crate::types::{
    ActivateLifecycleRequest, ActivationOutcome, Algorithm, AttestationChain, AuthMethod,
    CertificationLevel, DestroyLifecycleRequest, DestructionOutcome, FactorKind,
    GeneratedKey as WscdGeneratedKey, KeyId, KeyInfo, KeyStorageType, LifecycleState,
    LifecycleStatus, OperationProgress, RegisterLifecycleRequest, RegistrationOutcome,
    RotateLifecycleRequest, RotationOutcome, SecurityProperties, Signature,
};

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
    lifecycle: Mutex<HashMap<String, LifecycleContext>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct LifecycleContext {
    factor_kind: FactorKind,
    state: LifecycleState,
    updated_at: i64,
    key_ids: Vec<KeyId>,
}

#[derive(Default, Serialize, Deserialize)]
struct PluginState {
    keys: Vec<StoredFidoKey>,
    next_id: u64,
}

/// Wire shape for [`PreviewSignPlugin::export_state`]/[`PreviewSignPlugin::from_state`] -
/// snapshots both [`PluginState`] (keys) and the plugin's separate
/// `lifecycle` map (context ID -> which keys it owns) in one blob, so
/// `destroyLifecycle`/`rotateLifecycle` still work against a restored
/// plugin, not just `listKeys`. `lifecycle` defaults to empty on
/// deserialize so a blob exported before this field existed still loads
/// (with no lifecycle contexts, matching the old behavior exactly).
#[derive(Serialize, Deserialize)]
struct ExportedPluginState {
    keys: Vec<StoredFidoKey>,
    next_id: u64,
    #[serde(default)]
    lifecycle: HashMap<String, LifecycleContext>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredFidoKey {
    /// Plugin-assigned key identifier (e.g., "fido-0").
    kid: String,
    /// WebAuthn credential ID (`credential.rawId`) — scopes the
    /// `signByCredential` request. Distinct from the signing key's own
    /// `key_handle`.
    credential_id: Vec<u8>,
    /// previewSign-generated signing key handle.
    key_handle: Vec<u8>,
    /// Public key x-coordinate (32 bytes, P-256).
    pub_x: Vec<u8>,
    /// Public key y-coordinate (32 bytes, P-256).
    pub_y: Vec<u8>,
    /// COSE algorithm identifier.
    algorithm: i64,
    /// Raw attestation object from makeCredential.
    attestation_object: Vec<u8>,
    /// The clientDataHash passed to makeCredential (see
    /// `AttestationChain::client_data_hash` doc) - required to verify
    /// `attestation_object`'s signature; discarded before this field
    /// existed, which made server-side attestation verification
    /// impossible for any key created before this change.
    client_data_hash: Vec<u8>,
    /// ARKG key handle (`kh`) + context (`ctx`) from this key's
    /// `ARKG-derive-public-key` call (see [`crate::arkg`]) - `None` for
    /// a plain (non-ARKG) EC2 key, a defensive fallback this plugin
    /// doesn't expect a real authenticator to return but tolerates.
    /// Required at sign time so the authenticator can re-derive the
    /// matching *private* key (its own `ARKG-derive-private-key`,
    /// keyed by `kh`) via previewSign's `signByCredential`
    /// `additionalArgs` - `sign()` COSE-encodes both `kh` and `ctx`
    /// together via [`crate::arkg::encode_arkg_sign_args`], confirmed
    /// against real YubiKey hardware.
    #[serde(default)]
    arkg_kh_and_ctx: Option<(Vec<u8>, Vec<u8>)>,
    /// Creation timestamp (Unix seconds).
    created_at: i64,
}

/// Context string for this plugin's ARKG-derived signing keys - see
/// [`crate::arkg::derive_public_key`]'s doc comment for what `ctx` is
/// for. Fixed rather than per-key: `ikm` (fresh randomness per key) is
/// what actually needs to vary for ARKG's unlinkability property, not
/// `ctx` (an application-chosen constant is exactly what the ARKG draft
/// expects here).
const ARKG_DERIVE_CTX: &[u8] = b"siros-wscd-manager previewSign";

impl PreviewSignPlugin {
    /// Create a new PreviewSign plugin with the given CTAP2 transport.
    pub fn new(transport: Box<dyn Ctap2Transport>) -> Self {
        Self {
            transport,
            state: Mutex::new(PluginState::default()),
            lifecycle: Mutex::new(HashMap::new()),
        }
    }

    /// Restore from a previously exported state blob.
    ///
    /// The state contains only credential handles and public keys, plus
    /// lifecycle bookkeeping (context ID -> which keys it owns) - no
    /// private key material. The caller should still protect this data
    /// (the credential handles are opaque authenticator secrets).
    pub fn from_state(transport: Box<dyn Ctap2Transport>, state_bytes: &[u8]) -> Result<Self> {
        let exported: ExportedPluginState = serde_json::from_slice(state_bytes)
            .map_err(|e| WscdError::Serialization(e.to_string()))?;
        Ok(Self {
            transport,
            state: Mutex::new(PluginState {
                keys: exported.keys,
                next_id: exported.next_id,
            }),
            lifecycle: Mutex::new(exported.lifecycle),
        })
    }

    fn now_unix() -> i64 {
        crate::timeutil::now_unix()
    }

    /// Export the plugin state for persistence.
    pub fn export_state(&self) -> Result<Vec<u8>> {
        let state = self
            .state
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        let exported = ExportedPluginState {
            keys: state.keys.clone(),
            next_id: state.next_id,
            lifecycle: lifecycle.clone(),
        };
        serde_json::to_vec(&exported).map_err(|e| WscdError::Serialization(e.to_string()))
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
        // Confirmed against real YubiKey 5.8 hardware: the previewSign
        // extension's own UV-request flag is NOT sufficient proof of UV
        // on its own - a UV-enforcing authenticator silently drops the
        // extension's result without a real CTAP2 ClientPin exchange.
        // `generate_key`/`sign` do call `auth.request_pin()` (via
        // `preview_sign_protocol::make_credential`/`get_assertion`), but
        // that's WSCD-internal plumbing to the authenticator's own PIN,
        // not a *host*-mediated auth factor - from the host app's
        // perspective there's still nothing extra for it to prompt for.
        AuthMethod::None
    }

    async fn generate_key(
        &self,
        _algorithm: Algorithm,
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<WscdGeneratedKey> {
        progress
            .on_progress(OperationProgress::Started {
                operation: "generate_key".to_string(),
            })
            .await;

        // Generate a random user ID for the credential
        let user_id: Vec<u8> = {
            let mut buf = [0u8; 32];
            rand::fill(&mut buf);
            buf.to_vec()
        };

        let client_data_hash: Vec<u8> = {
            let mut buf = [0u8; 32];
            rand::fill(&mut buf);
            buf.to_vec()
        };

        progress
            .on_progress(OperationProgress::WaitingForUser)
            .await;

        // Call the host CTAP2 transport to create a credential and have
        // the authenticator generate a signing key on it. The algorithm
        // here is ARKG_P256_ESP256, NOT standard ES256 - previewSign's
        // generateKey ceremony is a distinct ARKG operation with its own
        // algorithm identifier (confirmed against real YubiKey 5.8
        // hardware; requesting ES256 here gets CTAP2_ERR_UNSUPPORTED_ALGORITHM).
        let result = preview_sign_protocol::make_credential(
            self.transport.as_ref(),
            auth,
            RAW_SIGN_RP_ID,
            &user_id,
            &client_data_hash,
            &GenerateKeyInput {
                algorithms: vec![ARKG_P256_ESP256],
            },
        )
        .await?;

        // previewSign's generateKey returns an "ARKG-pub" COSE_Key (kty
        // -65537 - see `crate::arkg`'s doc comment), not a usable EC2
        // public key directly - it must be derived. Fall back to
        // treating it as a plain EC2 key if some authenticator/config
        // ever returns one directly (defensive; not expected in
        // practice for this extension).
        let cose_value: ciborium::Value =
            ciborium::de::from_reader(result.generated_key.public_key_cose.as_slice())
                .map_err(|e| WscdError::Crypto(format!("invalid generated-key COSE CBOR: {e}")))?;
        let (pub_x, pub_y, arkg_kh_and_ctx) = match crate::arkg::parse_arkg_pub_seed(&cose_value) {
            Ok(seed) => {
                let mut ikm = [0u8; 32];
                rand::fill(&mut ikm);
                let (derived, kh) = crate::arkg::derive_public_key(&seed, &ikm, ARKG_DERIVE_CTX)?;
                let point = derived.as_affine().to_sec1_point(false);
                let x = point.x().expect("uncompressed point has x").to_vec();
                let y = point.y().expect("uncompressed point has y").to_vec();
                (x, y, Some((kh, ARKG_DERIVE_CTX.to_vec())))
            }
            Err(_) => {
                let (x, y) = preview_sign_protocol::decode_cose_ec2_public_key(
                    &result.generated_key.public_key_cose,
                )?;
                (x, y, None)
            }
        };

        let now = Self::now_unix();

        let kid = {
            let mut state = self
                .state
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;
            let kid = format!("fido-{}", state.next_id);
            state.next_id += 1;

            let stored = StoredFidoKey {
                kid: kid.clone(),
                credential_id: result.credential_id,
                key_handle: result.generated_key.key_handle,
                pub_x: pub_x.clone(),
                pub_y: pub_y.clone(),
                algorithm: result.generated_key.algorithm,
                attestation_object: result.generated_key.attestation_object,
                client_data_hash: client_data_hash.clone(),
                arkg_kh_and_ctx,
                created_at: now,
            };
            state.keys.push(stored);
            kid
        };

        progress.on_progress(OperationProgress::Complete).await;

        Ok(WscdGeneratedKey {
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
        auth: &dyn AuthCallback,
        progress: &dyn ProgressCallback,
    ) -> Result<Signature> {
        progress
            .on_progress(OperationProgress::Started {
                operation: "sign".to_string(),
            })
            .await;

        let (credential_id, key_handle, arkg_kh_and_ctx) = {
            let state = self
                .state
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;
            let key = Self::find_key(&state, kid)?;
            (
                key.credential_id.clone(),
                key.key_handle.clone(),
                key.arkg_kh_and_ctx.clone(),
            )
        };

        progress
            .on_progress(OperationProgress::WaitingForUser)
            .await;

        let challenge = {
            let mut buf = [0u8; 32];
            rand::fill(&mut buf);
            buf.to_vec()
        };

        // previewSign's signByCredential expects a fixed-size digest, not
        // arbitrary-length data - confirmed via live hardware testing: a
        // real YubiKey rejected the raw (397-byte) JWT signing input with
        // CTAP2 error 0x03 (invalid length). `data` here is whatever the
        // caller wants signed (e.g. a JWS signing input), unhashed - same
        // convention as the softkey plugin's `sign()`, whose underlying
        // ECDSA library hashes internally; this plugin must do that hashing
        // itself before handing bytes to the extension.
        let tbs = sha2::Sha256::digest(data).to_vec();

        let result = preview_sign_protocol::get_assertion(
            self.transport.as_ref(),
            auth,
            RAW_SIGN_RP_ID,
            &challenge,
            &credential_id,
            &SignInput {
                key_handle,
                tbs,
                // additionalArgs is a CBOR-encoded COSE Signing Arguments
                // map {3: alg, -1: kh, -2: ctx} - see
                // arkg::encode_arkg_sign_args's doc comment. This was a
                // known, explicitly-flagged gap (see StoredFidoKey's
                // arkg_kh_and_ctx doc comment): previously always None,
                // then briefly just the raw kh bytes, both of which a real
                // YubiKey rejected (the latter with
                // CTAP2_ERR_CBOR_UNEXPECTED_TYPE, since it expects to CBOR-
                // decode a map here) before this exact encoding was
                // confirmed against wallet-frontend's own reference
                // previewSign integration.
                additional_args: arkg_kh_and_ctx
                    .map(|(kh, ctx)| crate::arkg::encode_arkg_sign_args(ARKG_P256_ESP256, &kh, &ctx)),
            },
        )
        .await?;

        progress.on_progress(OperationProgress::Complete).await;

        Ok(Signature(preview_sign_protocol::der_signature_to_raw(
            &result.signature,
        )?))
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
            client_data_hash: key.client_data_hash.clone(),
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

    fn security_properties(&self, kid: &KeyId) -> Result<SecurityProperties> {
        let state = self
            .state
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        let _ = Self::find_key(&state, kid)?;
        // FIDO2 authenticator — hardware-backed key.
        // Certification could be derived from AAGUID → FIDO MDS lookup in future.
        Ok(SecurityProperties {
            key_storage: KeyStorageType::Hardware,
            user_authentication: vec![],
            certification: CertificationLevel::Baseline,
            amr: vec!["hwk".to_string(), "pop".to_string()],
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
        if request.factor_kind != FactorKind::RawSign {
            return Err(WscdError::Unsupported {
                plugin: self.id().to_string(),
                op: format!("register_lifecycle({:?})", request.factor_kind),
            });
        }

        let generated = self.generate_key(Algorithm::ES256, auth, progress).await?;
        let now = Self::now_unix();
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;

        // Re-registering an already-registered context (Enroll tapped again
        // without an intervening Destroy - confirmed to happen during real
        // testing, e.g. after a stuck busy flag made Destroy unreachable)
        // used to just overwrite `key_ids` with the newest key, silently
        // orphaning whatever key(s) the old context pointed at: they stayed
        // in `state.keys` forever since destroy_lifecycle only ever looks at
        // the CURRENT context's key_ids. Purge the old context's keys first
        // so re-registering behaves like an implicit destroy-then-register
        // and never leaks keys.
        if let Some(old_ctx) = lifecycle.get(&request.context_id) {
            let stale_ids = old_ctx.key_ids.clone();
            let mut state = self
                .state
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;
            state
                .keys
                .retain(|k| !stale_ids.iter().any(|kid| kid.as_str() == k.kid));
        }

        lifecycle.insert(
            request.context_id.clone(),
            LifecycleContext {
                factor_kind: request.factor_kind,
                state: LifecycleState::Registered,
                updated_at: now,
                key_ids: vec![generated.kid],
            },
        );

        Ok(RegistrationOutcome {
            context_id: request.context_id.clone(),
            state: LifecycleState::Registered,
        })
    }

    async fn activate_lifecycle(
        &self,
        request: &ActivateLifecycleRequest,
        _auth: &dyn AuthCallback,
        _progress: &dyn ProgressCallback,
    ) -> Result<ActivationOutcome> {
        let now = Self::now_unix();
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        let ctx = lifecycle
            .get_mut(&request.context_id)
            .ok_or_else(|| WscdError::KeyNotFound {
                kid: request.context_id.clone(),
            })?;
        ctx.state = LifecycleState::Active;
        ctx.updated_at = now;

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
        let generated = self.generate_key(Algorithm::ES256, auth, progress).await?;
        let now = Self::now_unix();
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        let ctx = lifecycle
            .get_mut(&request.context_id)
            .ok_or_else(|| WscdError::KeyNotFound {
                kid: request.context_id.clone(),
            })?;
        ctx.key_ids.push(generated.kid);
        ctx.state = LifecycleState::Registered;
        ctx.updated_at = now;

        Ok(RotationOutcome {
            context_id: request.context_id.clone(),
            state: LifecycleState::Registered,
        })
    }

    async fn destroy_lifecycle(
        &self,
        request: &DestroyLifecycleRequest,
        _auth: &dyn AuthCallback,
        _progress: &dyn ProgressCallback,
    ) -> Result<DestructionOutcome> {
        {
            let lifecycle = self
                .lifecycle
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;
            if !lifecycle.contains_key(&request.context_id) {
                return Err(WscdError::KeyNotFound {
                    kid: request.context_id.clone(),
                });
            }
        }

        // A PreviewSignPlugin instance is scoped to a single plugin_id and
        // this session's model is one active enrollment (context) per
        // plugin instance (register_lifecycle overwrites rather than
        // accumulates contexts) - so on destroy, every key this instance
        // holds belongs to the context being destroyed. Clearing all of
        // `state.keys` here, rather than just the current context's
        // key_ids, also sweeps up any key orphaned by a since-fixed bug in
        // register_lifecycle (re-enrolling without destroying first used to
        // leak the previous key forever, since destroy only ever looked at
        // the CURRENT context's key_ids).
        {
            let mut state = self
                .state
                .lock()
                .map_err(|e| WscdError::Plugin(e.to_string()))?;
            state.keys.clear();
        }

        let now = Self::now_unix();
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|e| WscdError::Plugin(e.to_string()))?;
        if let Some(ctx) = lifecycle.get_mut(&request.context_id) {
            ctx.state = LifecycleState::Destroyed;
            ctx.updated_at = now;
            ctx.key_ids.clear();
        }

        Ok(DestructionOutcome {
            context_id: request.context_id.clone(),
            state: LifecycleState::Destroyed,
            remote_performed: false,
        })
    }
}

#[cfg(test)]
mod state_persistence_tests {
    use super::*;

    struct UnusedTransport;

    #[async_trait]
    impl Ctap2Transport for UnusedTransport {
        async fn ctap2_send_command(&self, _command: &[u8]) -> Result<Vec<u8>> {
            panic!("transport should not be used by export_state/from_state/destroy_lifecycle");
        }
    }

    struct UnusedAuth;

    #[async_trait]
    impl AuthCallback for UnusedAuth {
        async fn request_pin(&self, _plugin_id: &str) -> Result<Vec<u8>> {
            panic!("auth should not be used by destroy_lifecycle");
        }
        async fn request_webauthn_assertion(
            &self,
            _challenge: &[u8],
            _rp_id: &str,
            _allowed_credentials: &[Vec<u8>],
        ) -> Result<Vec<u8>> {
            panic!("auth should not be used by destroy_lifecycle");
        }
    }

    fn sample_exported_state() -> ExportedPluginState {
        let mut lifecycle = HashMap::new();
        lifecycle.insert(
            "ctx-1".to_string(),
            LifecycleContext {
                factor_kind: FactorKind::RawSign,
                state: LifecycleState::Registered,
                updated_at: 1_700_000_000,
                key_ids: vec![KeyId("fido-0".to_string())],
            },
        );
        ExportedPluginState {
            keys: vec![StoredFidoKey {
                kid: "fido-0".to_string(),
                credential_id: vec![1, 2, 3],
                key_handle: vec![4, 5, 6],
                pub_x: vec![0u8; 32],
                pub_y: vec![0u8; 32],
                algorithm: -7,
                attestation_object: vec![7, 8, 9],
                client_data_hash: vec![10, 11, 12],
                arkg_kh_and_ctx: None,
                created_at: 1_700_000_000,
            }],
            next_id: 1,
            lifecycle,
        }
    }

    #[test]
    fn export_state_round_trips_keys_and_lifecycle() {
        let exported = sample_exported_state();
        let bytes = serde_json::to_vec(&exported).unwrap();
        let plugin = PreviewSignPlugin::from_state(Box::new(UnusedTransport), &bytes).unwrap();

        let state = plugin.state.lock().unwrap();
        assert_eq!(state.keys.len(), 1);
        assert_eq!(state.keys[0].kid, "fido-0");
        assert_eq!(state.next_id, 1);
        drop(state);

        let lifecycle = plugin.lifecycle.lock().unwrap();
        assert_eq!(lifecycle.len(), 1);
        assert_eq!(
            lifecycle["ctx-1"].key_ids,
            vec![KeyId("fido-0".to_string())]
        );
        drop(lifecycle);

        let re_exported_bytes = plugin.export_state().unwrap();
        let re_exported: ExportedPluginState = serde_json::from_slice(&re_exported_bytes).unwrap();
        assert_eq!(re_exported.keys.len(), 1);
        assert_eq!(re_exported.lifecycle.len(), 1);
    }

    #[test]
    fn old_state_without_lifecycle_field_still_loads() {
        // Simulates a blob exported before `lifecycle` existed on the wire.
        let legacy_json = r#"{"keys":[],"next_id":0}"#;
        let plugin =
            PreviewSignPlugin::from_state(Box::new(UnusedTransport), legacy_json.as_bytes())
                .unwrap();
        assert!(plugin.lifecycle.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn destroy_lifecycle_works_against_a_restored_plugin() {
        let exported = sample_exported_state();
        let bytes = serde_json::to_vec(&exported).unwrap();
        let plugin = PreviewSignPlugin::from_state(Box::new(UnusedTransport), &bytes).unwrap();

        let request = DestroyLifecycleRequest {
            plugin_id: "fido2".to_string(),
            context_id: "ctx-1".to_string(),
            mode: crate::types::DestroyMode::LocalOnly,
            reason: None,
        };
        let outcome = plugin
            .destroy_lifecycle(&request, &UnusedAuth, &crate::callbacks::NoopProgress)
            .await
            .expect("destroy_lifecycle should find the restored context");
        assert_eq!(outcome.state, LifecycleState::Destroyed);

        // The key that context owned should now be gone.
        let state = plugin.state.lock().unwrap();
        assert!(state.keys.is_empty());
    }
}
