//! CTAP2 `authenticatorClientPIN` / PinUvAuthProtocol (FIDO CTAP2.1 §6.5).
//!
//! Obtains a `pinUvAuthToken` from an authenticator's PIN, for use as UV
//! proof (`pinUvAuthParam`/`pinUvAuthProtocol`) on privileged CTAP2
//! commands (`authenticatorMakeCredential`, `authenticatorGetAssertion`).
//!
//! Needed because `previewSign`'s own UV-request flag (see
//! `preview_sign_protocol::build_generate_key_extension`) is NOT
//! sufficient on its own to prove UV to an authenticator that enforces
//! it - confirmed against real YubiKey 5.8 hardware: setting only the
//! extension's flag gets the base credential created, but the
//! authenticator silently omits the previewSign generateKey result from
//! its response. A cryptographically valid `pinUvAuthParam` is what
//! actually satisfies the authenticator's UV requirement.
//!
//! Implements both PinUvAuthProtocol versions (1: SHA-256-derived shared
//! secret; 2: HKDF-SHA-256-derived, per CTAP2.1 §6.5.6) - the protocol to
//! use is selected per-authenticator from `authenticatorGetInfo`.

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use ciborium::Value;
use hkdf::Hkdf;
// `KeyInit` comes from `hmac`, not from `cbc::cipher`: both re-export the
// same `crypto_common` trait today, so importing either one compiles, but
// taking it from the cipher crate to key an HMAC reads as an accident and
// breaks confusingly if the two ever diverge. `cbc` needs only `KeyIvInit`.
use hmac::{Hmac, KeyInit, Mac};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::elliptic_curve::Generate;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::callbacks::{AuthCallback, Ctap2Transport, PinRequestKind};
use crate::error::{PinFailure, Result, WscdError};
use crate::preview_sign_protocol::{encode_command, split_status};

const CTAP2_GET_INFO: u8 = 0x04;
const CTAP2_CLIENT_PIN: u8 = 0x06;

const SUBCMD_GET_KEY_AGREEMENT: i64 = 0x02;
const SUBCMD_SET_PIN: i64 = 0x03;
const SUBCMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS: i64 = 0x09;

/// `authenticatorMakeCredential` permission bit (`mc`), for
/// `getPinUvAuthTokenUsingPinWithPermissions`'s `permissions` (key 9).
pub const PERMISSION_MAKE_CREDENTIAL: u8 = 0x01;
/// `authenticatorGetAssertion` permission bit (`ga`).
pub const PERMISSION_GET_ASSERTION: u8 = 0x02;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Which PinUvAuthProtocol version is in use - the two differ in shared-
/// secret key derivation (SHA-256 vs HKDF-SHA-256) and `authenticate()`
/// output length (16 vs 32 bytes); see FIDO CTAP2.1 §6.5.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinUvAuthProtocol {
    One,
    Two,
}

impl PinUvAuthProtocol {
    fn as_int(self) -> i64 {
        match self {
            PinUvAuthProtocol::One => 1,
            PinUvAuthProtocol::Two => 2,
        }
    }

    /// Mainly useful to test mocks acting as the "authenticator" side,
    /// which receive the platform's chosen protocol as a plain integer
    /// off the wire rather than picking it via [`select_protocol`].
    pub fn from_int(n: i64) -> Option<Self> {
        match n {
            1 => Some(PinUvAuthProtocol::One),
            2 => Some(PinUvAuthProtocol::Two),
            _ => None,
        }
    }
}

/// A PIN/UV auth token obtained from an authenticator, ready to
/// [`authenticate`](Self::authenticate) a specific command's
/// `pinUvAuthParam`.
pub struct PinUvAuthSession {
    protocol: PinUvAuthProtocol,
    /// Decrypted `pinUvAuthToken` bytes (32 bytes).
    token: Vec<u8>,
}

impl Drop for PinUvAuthSession {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl PinUvAuthSession {
    /// Compute `pinUvAuthParam` for a command whose CTAP2 request is
    /// authenticated over `message` (e.g. `clientDataHash`) - FIDO
    /// CTAP2.1 §6.5.6's `authenticate(pinUvAuthToken, message)`. The
    /// `key` for this HMAC is always the token itself, for both protocol
    /// versions - only the OUTPUT length differs (16 bytes vs 32).
    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.token)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(message);
        let full = mac.finalize().into_bytes();
        match self.protocol {
            PinUvAuthProtocol::One => full[..16].to_vec(),
            PinUvAuthProtocol::Two => full.to_vec(),
        }
    }

    /// The `pinUvAuthProtocol` value (1 or 2) to attach alongside
    /// `pinUvAuthParam` on the authenticated command.
    pub fn protocol_int(&self) -> i64 {
        self.protocol.as_int()
    }
}

/// Run the full ClientPin exchange - `getInfo` (protocol selection),
/// `getKeyAgreement` (ECDH), then `getPinUvAuthTokenUsingPinWithPermissions`
/// (using `pin`) - and return a session that can authenticate one or more
/// subsequent commands scoped to `permissions`.
///
/// This only ever USES an existing PIN. To also set one on a fresh
/// authenticator, use [`acquire_pin_uv_auth_token`].
pub async fn get_pin_uv_auth_token(
    transport: &dyn Ctap2Transport,
    pin: &[u8],
    permissions: u8,
    rp_id: Option<&str>,
) -> Result<PinUvAuthSession> {
    let info = read_pin_info(transport).await?;
    token_with_pin(transport, info.protocol, pin, permissions, rp_id).await
}

/// Whether an authenticator has a PIN, from `getInfo` option `clientPin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinState {
    /// `clientPin: true` - a PIN is set; the user must enter it.
    Set,
    /// `clientPin: false` - PIN supported but not set; one must be set first.
    NotSet,
    /// `clientPin` absent - no ClientPin support; nothing is set.
    Unsupported,
}

/// What this module needs from `authenticatorGetInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatorPinInfo {
    pub protocol: PinUvAuthProtocol,
    pub pin_state: PinState,
    /// `minPINLength` in Unicode code points; 4 when the authenticator does
    /// not advertise it (CTAP2.1 default).
    pub min_pin_length: u32,
}

const DEFAULT_MIN_PIN_LENGTH: u32 = 4;
/// CTAP2.1 6.5.5.1: a PIN is at most 63 bytes of UTF-8.
const MAX_PIN_BYTES: usize = 63;
/// `newPinEnc` plaintext is the PIN zero-padded to 64 bytes.
const PADDED_PIN_BYTES: usize = 64;

/// Send `authenticatorGetInfo` once and read the PIN-relevant fields.
pub async fn read_pin_info(transport: &dyn Ctap2Transport) -> Result<AuthenticatorPinInfo> {
    let response = transport.ctap2_send_command(&[CTAP2_GET_INFO]).await?;
    let body = split_status(&response)?;
    parse_pin_info(body)
}

fn parse_pin_info(body: &[u8]) -> Result<AuthenticatorPinInfo> {
    let info: Value = ciborium::de::from_reader(body)
        .map_err(|e| WscdError::Crypto(format!("invalid getInfo CBOR: {e}")))?;
    let map = info
        .as_map()
        .ok_or_else(|| WscdError::Crypto("getInfo response is not a CBOR map".into()))?;
    let get = |key: i128| {
        map.iter()
            .find(|(k, _)| k.as_integer().map(i128::from) == Some(key))
            .map(|(_, v)| v)
    };

    // Defaults to protocol 1 if the field is absent (pre-2.1 authenticators
    // only ever supported protocol 1 and didn't advertise it).
    let protocol = get(6)
        .and_then(|v| v.as_array())
        .and_then(|protocols| {
            protocols
                .iter()
                .find_map(|v| match v.as_integer().map(i128::from) {
                    Some(1) => Some(PinUvAuthProtocol::One),
                    Some(2) => Some(PinUvAuthProtocol::Two),
                    _ => None,
                })
        })
        .unwrap_or(PinUvAuthProtocol::One);

    let pin_state = match get(4)
        .and_then(|v| v.as_map())
        .and_then(|opts| {
            opts.iter()
                .find(|(k, _)| k.as_text() == Some("clientPin"))
                .map(|(_, v)| v)
        })
        .and_then(|v| v.as_bool())
    {
        Some(true) => PinState::Set,
        Some(false) => PinState::NotSet,
        None => PinState::Unsupported,
    };

    let min_pin_length = get(0x0D)
        .and_then(|v| v.as_integer())
        .and_then(|i| u32::try_from(i128::from(i)).ok())
        .unwrap_or(DEFAULT_MIN_PIN_LENGTH);

    Ok(AuthenticatorPinInfo {
        protocol,
        pin_state,
        min_pin_length,
    })
}

/// Obtain a `pinUvAuthToken`, first SETTING the PIN when the authenticator
/// has none (`clientPin: false`).
///
/// One `getInfo` decides: `NotSet` asks the host to CHOOSE a PIN
/// ([`PinRequestKind::SetNewPin`]), validates it locally (nothing is sent
/// if it is too short/long - the caller can re-prompt), sends `setPIN`, then
/// runs the normal token exchange with a fresh key agreement. `Set` and
/// `Unsupported` ask the host to ENTER a PIN and behave exactly like
/// [`get_pin_uv_auth_token`].
pub async fn acquire_pin_uv_auth_token(
    transport: &dyn Ctap2Transport,
    auth: &dyn AuthCallback,
    plugin_id: &str,
    permissions: u8,
    rp_id: Option<&str>,
) -> Result<PinUvAuthSession> {
    let info = read_pin_info(transport).await?;
    match info.pin_state {
        PinState::NotSet => {
            let raw = auth
                .request_pin_for(
                    plugin_id,
                    PinRequestKind::SetNewPin {
                        min_length: info.min_pin_length,
                    },
                )
                .await?;
            let pin = validate_new_pin(&raw, info.min_pin_length)?;
            set_pin(transport, info.protocol, pin.as_bytes()).await?;
            token_with_pin(transport, info.protocol, pin.as_bytes(), permissions, rp_id).await
        }
        PinState::Set | PinState::Unsupported => {
            let raw = auth
                .request_pin_for(plugin_id, PinRequestKind::EnterPin)
                .await?;
            let pin = normalize_pin(&raw);
            token_with_pin(transport, info.protocol, &pin, permissions, rp_id).await
        }
    }
}

/// NFC-normalise `pin` when it is UTF-8 (CTAP2.1: PINs are UTF-8 NFC); else
/// return it unchanged so an odd-but-previously-working byte PIN still works.
fn normalize_pin(pin: &[u8]) -> Zeroizing<Vec<u8>> {
    match std::str::from_utf8(pin) {
        Ok(s) => {
            let nfc: Zeroizing<String> = Zeroizing::new(s.nfc().collect());
            Zeroizing::new(nfc.as_bytes().to_vec())
        }
        Err(_) => Zeroizing::new(pin.to_vec()),
    }
}

/// Check a to-be-set PIN against local limits and NFC-normalise it.
/// Never echoes the PIN.
fn validate_new_pin(pin: &[u8], min_length: u32) -> Result<Zeroizing<String>> {
    let text = std::str::from_utf8(pin).map_err(|_| PinFailure::InvalidEncoding)?;
    let normalized: Zeroizing<String> = Zeroizing::new(text.nfc().collect());
    if normalized.len() > MAX_PIN_BYTES {
        return Err(PinFailure::TooLong.into());
    }
    if normalized.chars().count() < min_length as usize {
        return Err(PinFailure::TooShort { min_length }.into());
    }
    Ok(normalized)
}

async fn token_with_pin(
    transport: &dyn Ctap2Transport,
    protocol: PinUvAuthProtocol,
    pin: &[u8],
    permissions: u8,
    rp_id: Option<&str>,
) -> Result<PinUvAuthSession> {
    let platform_secret = SecretKey::generate();
    let platform_public = platform_secret.public_key();

    let peer_public = get_key_agreement(transport, protocol).await?;
    let mut shared_point_x = ecdh_shared_x(&platform_secret, &peer_public)?;
    let mut aes_key = derive_aes_key(protocol, &shared_point_x);
    shared_point_x.zeroize();

    let mut pin_hash: [u8; 16] = {
        let digest = Sha256::digest(pin);
        digest[..16].try_into().expect("SHA-256 digest is 32 bytes")
    };
    let pin_hash_enc = encrypt(protocol, &aes_key, &pin_hash);
    pin_hash.zeroize();

    let token_enc = send_get_pin_token(
        transport,
        protocol,
        &platform_public,
        &pin_hash_enc,
        permissions,
        rp_id,
    )
    .await;
    let token = token_enc.and_then(|enc| decrypt(protocol, &aes_key, &enc));
    aes_key.zeroize();

    Ok(PinUvAuthSession {
        protocol,
        token: token?,
    })
}

/// `authenticatorClientPIN` `setPIN` (subCommand 0x03), CTAP2.1 6.5.5.4.
/// `pin` must already be validated/normalised (see [`validate_new_pin`]).
async fn set_pin(
    transport: &dyn Ctap2Transport,
    protocol: PinUvAuthProtocol,
    pin: &[u8],
) -> Result<()> {
    let platform_secret = SecretKey::generate();
    let platform_public = platform_secret.public_key();
    let peer_public = get_key_agreement(transport, protocol).await?;
    let mut shared_x = ecdh_shared_x(&platform_secret, &peer_public)?;

    let mut iv = [0u8; 16];
    rand::fill(&mut iv);
    let (new_pin_enc, pin_uv_auth_param) = set_pin_fields(protocol, &shared_x, pin, iv);
    shared_x.zeroize();

    let params = Value::Map(vec![
        (
            Value::Integer(1.into()),
            Value::Integer(protocol.as_int().into()),
        ),
        (
            Value::Integer(2.into()),
            Value::Integer(SUBCMD_SET_PIN.into()),
        ),
        (
            Value::Integer(3.into()),
            encode_platform_cose_key(&platform_public),
        ),
        (Value::Integer(4.into()), Value::Bytes(pin_uv_auth_param)),
        (Value::Integer(5.into()), Value::Bytes(new_pin_enc)),
    ]);
    let command = encode_command(CTAP2_CLIENT_PIN, &params);
    let response = transport.ctap2_send_command(&command).await?;
    split_client_pin_status(&response)?;
    Ok(())
}

/// Compute `(newPinEnc, pinUvAuthParam)` for setPIN from the ECDH x-coord.
/// Protocol 1: AES-256-CBC with a zero IV; protocol 2: `iv` prepended.
/// `pinUvAuthParam = authenticate(sharedSecret, newPinEnc)` - HMAC-SHA-256
/// keyed with the shared secret's HMAC key (protocol 1: the whole 32-byte
/// secret; protocol 2: the first 32 bytes, "CTAP2 HMAC key"), truncated to
/// 16 bytes for protocol 1, whole for protocol 2. Split out so a
/// known-answer test can pin it with a fixed IV.
fn set_pin_fields(
    protocol: PinUvAuthProtocol,
    shared_x: &[u8; 32],
    pin: &[u8],
    iv: [u8; 16],
) -> (Vec<u8>, Vec<u8>) {
    // Protocol 1 always uses a zero IV; only protocol 2 uses (and sends) `iv`.
    let iv = match protocol {
        PinUvAuthProtocol::One => [0u8; 16],
        PinUvAuthProtocol::Two => iv,
    };
    let mut padded = Zeroizing::new([0u8; PADDED_PIN_BYTES]);
    padded[..pin.len()].copy_from_slice(pin);

    let mut aes_key = derive_aes_key(protocol, shared_x);
    let mut hmac_key = derive_hmac_key(protocol, shared_x);

    let mut buf = padded.to_vec();
    let ct_len = Aes256CbcEnc::new_from_slices(&aes_key, &iv)
        .expect("32-byte key and 16-byte IV are always valid for AES-256-CBC")
        .encrypt_padded::<NoPadding>(&mut buf, PADDED_PIN_BYTES)
        .expect("64 bytes is a multiple of the AES block size")
        .len();
    buf.truncate(ct_len);
    let new_pin_enc = match protocol {
        PinUvAuthProtocol::One => buf,
        PinUvAuthProtocol::Two => {
            let mut out = iv.to_vec();
            out.extend_from_slice(&buf);
            out
        }
    };

    let mut mac =
        Hmac::<Sha256>::new_from_slice(&hmac_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(&new_pin_enc);
    let full = mac.finalize().into_bytes();
    let param = match protocol {
        PinUvAuthProtocol::One => full[..16].to_vec(),
        PinUvAuthProtocol::Two => full.to_vec(),
    };

    aes_key.zeroize();
    hmac_key.zeroize();
    (new_pin_enc, param)
}

/// Like [`split_status`], but maps the PIN-related CTAP2 status codes of a
/// ClientPin response to a typed [`PinFailure`].
fn split_client_pin_status(response: &[u8]) -> Result<&[u8]> {
    let failure = match response.first() {
        Some(0x31) => PinFailure::Invalid,
        Some(0x32) => PinFailure::Blocked,
        Some(0x34) => PinFailure::AuthBlocked,
        Some(0x35) => PinFailure::NotSet,
        Some(0x37) => PinFailure::PolicyViolation,
        _ => return split_status(response),
    };
    Err(failure.into())
}

async fn get_key_agreement(
    transport: &dyn Ctap2Transport,
    protocol: PinUvAuthProtocol,
) -> Result<PublicKey> {
    let params = Value::Map(vec![
        (
            Value::Integer(1.into()),
            Value::Integer(protocol.as_int().into()),
        ),
        (
            Value::Integer(2.into()),
            Value::Integer(SUBCMD_GET_KEY_AGREEMENT.into()),
        ),
    ]);
    let command = encode_command(CTAP2_CLIENT_PIN, &params);
    let response = transport.ctap2_send_command(&command).await?;
    let body = split_client_pin_status(&response)?;
    let value: Value = ciborium::de::from_reader(body)
        .map_err(|e| WscdError::Crypto(format!("invalid getKeyAgreement CBOR: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| WscdError::Crypto("getKeyAgreement response is not a CBOR map".into()))?;
    let cose_key = map
        .iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(1))
        .map(|(_, v)| v)
        .ok_or_else(|| {
            WscdError::Crypto("getKeyAgreement response missing key agreement key (key 1)".into())
        })?;
    decode_cose_ec2_public_key(cose_key)
}

/// Decode an EC2 COSE_Key CBOR *value* (not raw bytes - the ClientPin
/// response embeds it as a nested map, unlike the attestation object's
/// byte-string-wrapped credential public key) into a [`PublicKey`].
///
/// `pub` (rather than private) so test mocks acting as the "authenticator"
/// side of this exchange can decode the platform's public key too.
pub fn decode_cose_ec2_public_key(value: &Value) -> Result<PublicKey> {
    let map = value
        .as_map()
        .ok_or_else(|| WscdError::Crypto("COSE key is not a CBOR map".into()))?;
    let get_bytes = |label: i128| -> Option<Vec<u8>> {
        map.iter().find_map(|(k, v)| {
            if k.as_integer().map(i128::from) == Some(label) {
                v.as_bytes().cloned()
            } else {
                None
            }
        })
    };
    let x = get_bytes(-2).ok_or_else(|| WscdError::Crypto("COSE key missing x".into()))?;
    let y = get_bytes(-3).ok_or_else(|| WscdError::Crypto("COSE key missing y".into()))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(WscdError::Crypto(
            "COSE key x/y must be 32 bytes each for P-256".into(),
        ));
    }

    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    PublicKey::from_sec1_bytes(&sec1)
        .map_err(|e| WscdError::Crypto(format!("invalid P-256 point: {e}")))
}

/// Encode a P-256 public key as an EC2 COSE_Key CBOR value: `{1: 2 (kty
/// EC2), 3: -25 (alg ECDH-ES+HKDF-256), -1: 1 (crv P-256), -2: x, -3: y}`.
/// Used for the platform's own ephemeral key here; `pub` so test mocks
/// acting as the "authenticator" side can encode theirs the same way.
pub fn encode_platform_cose_key(public: &PublicKey) -> Value {
    let point = public.to_sec1_point(false);
    let x = point.x().expect("uncompressed point has x").to_vec();
    let y = point.y().expect("uncompressed point has y").to_vec();
    Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())),
        (Value::Integer(3.into()), Value::Integer((-25).into())),
        (Value::Integer((-1).into()), Value::Integer(1.into())),
        (Value::Integer((-2).into()), Value::Bytes(x)),
        (Value::Integer((-3).into()), Value::Bytes(y)),
    ])
}

/// `pub` so test mocks acting as the "authenticator" side can complete
/// the same ECDH using their own secret + the platform's public key.
pub fn ecdh_shared_x(secret: &SecretKey, peer_public: &PublicKey) -> Result<[u8; 32]> {
    let shared = diffie_hellman(secret.to_nonzero_scalar(), peer_public.as_affine());
    shared
        .raw_secret_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| WscdError::Crypto("ECDH shared secret is not 32 bytes".into()))
}

/// Derive the AES-256-CBC key used for `pinHashEnc`/token encryption:
/// protocol 1 uses `SHA-256(Z)` directly; protocol 2 uses HKDF-SHA-256
/// (`Extract` with a 32-byte zero salt, `Expand` with info
/// `"CTAP2 AES key"`) - CTAP2.1 §6.5.6. Protocol 2 also derives a
/// separate HMAC key, but this module never uses it directly: per
/// §6.5.6, `authenticate()`'s key is always the *token* itself, not the
/// shared secret, for either protocol version.
/// `pub` so test mocks acting as the "authenticator" side derive the
/// identical key from their half of the same ECDH exchange.
pub fn derive_aes_key(protocol: PinUvAuthProtocol, shared_x: &[u8; 32]) -> [u8; 32] {
    match protocol {
        PinUvAuthProtocol::One => Sha256::digest(shared_x).into(),
        PinUvAuthProtocol::Two => {
            let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared_x);
            let mut aes_key = [0u8; 32];
            hk.expand(b"CTAP2 AES key", &mut aes_key)
                .expect("32 bytes is a valid HKDF-SHA256 output length");
            aes_key
        }
    }
}

/// The HMAC key of the shared secret: protocol 1 reuses `SHA-256(Z)`;
/// protocol 2 derives a separate key with HKDF info `"CTAP2 HMAC key"`
/// (CTAP2.1 6.5.6). Used for setPIN's `pinUvAuthParam`.
pub fn derive_hmac_key(protocol: PinUvAuthProtocol, shared_x: &[u8; 32]) -> [u8; 32] {
    match protocol {
        PinUvAuthProtocol::One => Sha256::digest(shared_x).into(),
        PinUvAuthProtocol::Two => {
            let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared_x);
            let mut key = [0u8; 32];
            hk.expand(b"CTAP2 HMAC key", &mut key)
                .expect("32 bytes is a valid HKDF-SHA256 output length");
            key
        }
    }
}

/// `encrypt(key, demPlaintext)` - CTAP2.1 §6.5.6. Protocol 1: AES-256-CBC,
/// zero IV, no padding. Protocol 2: AES-256-CBC with a fresh random IV
/// prepended to the ciphertext. `pub` so test mocks acting as the
/// "authenticator" side can encrypt a `pinUvAuthToken` response.
pub fn encrypt(protocol: PinUvAuthProtocol, key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let iv = match protocol {
        PinUvAuthProtocol::One => [0u8; 16],
        PinUvAuthProtocol::Two => {
            let mut iv = [0u8; 16];
            rand::fill(&mut iv);
            iv
        }
    };
    let mut buf = plaintext.to_vec();
    let ct_len = Aes256CbcEnc::new_from_slices(key, &iv)
        .expect("32-byte key and 16-byte IV are always valid for AES-256-CBC")
        .encrypt_padded::<NoPadding>(&mut buf, plaintext.len())
        .expect("plaintext here is always a multiple of the AES block size")
        .len();
    buf.truncate(ct_len);

    match protocol {
        PinUvAuthProtocol::One => buf,
        PinUvAuthProtocol::Two => {
            let mut out = iv.to_vec();
            out.extend_from_slice(&buf);
            out
        }
    }
}

/// `decrypt(key, ciphertext)` - CTAP2.1 §6.5.6. Protocol 1: AES-256-CBC,
/// zero IV. Protocol 2: the leading 16 bytes of `ciphertext` are the IV.
/// `pub` so test mocks acting as the "authenticator" side can decrypt
/// `pinHashEnc` (not that a mock need actually validate a PIN).
pub fn decrypt(protocol: PinUvAuthProtocol, key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let (iv, ct): (&[u8], &[u8]) = match protocol {
        PinUvAuthProtocol::One => (&[0u8; 16], ciphertext),
        PinUvAuthProtocol::Two => {
            if ciphertext.len() < 16 {
                return Err(WscdError::Crypto(
                    "protocol 2 ciphertext shorter than one IV".into(),
                ));
            }
            ciphertext.split_at(16)
        }
    };
    let mut buf = ct.to_vec();
    let pt_len = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| WscdError::Crypto(format!("invalid AES key/IV: {e}")))?
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|e| WscdError::Crypto(format!("AES-CBC decrypt failed: {e}")))?
        .len();
    buf.truncate(pt_len);
    Ok(buf)
}

#[allow(clippy::too_many_arguments)]
async fn send_get_pin_token(
    transport: &dyn Ctap2Transport,
    protocol: PinUvAuthProtocol,
    platform_public: &PublicKey,
    pin_hash_enc: &[u8],
    permissions: u8,
    rp_id: Option<&str>,
) -> Result<Vec<u8>> {
    let mut params = vec![
        (
            Value::Integer(1.into()),
            Value::Integer(protocol.as_int().into()),
        ),
        (
            Value::Integer(2.into()),
            Value::Integer(SUBCMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS.into()),
        ),
        (
            Value::Integer(3.into()),
            encode_platform_cose_key(platform_public),
        ),
        (
            Value::Integer(6.into()),
            Value::Bytes(pin_hash_enc.to_vec()),
        ),
        (
            Value::Integer(9.into()),
            Value::Integer((permissions as i64).into()),
        ),
    ];
    if let Some(rp_id) = rp_id {
        params.push((Value::Integer(0x0A.into()), Value::Text(rp_id.into())));
    }

    let command = encode_command(CTAP2_CLIENT_PIN, &Value::Map(params));
    let response = transport.ctap2_send_command(&command).await?;
    let body = split_client_pin_status(&response)?;
    let value: Value = ciborium::de::from_reader(body)
        .map_err(|e| WscdError::Crypto(format!("invalid getPinUvAuthToken CBOR: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| WscdError::Crypto("getPinUvAuthToken response is not a CBOR map".into()))?;
    map.iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(2))
        .and_then(|(_, v)| v.as_bytes().cloned())
        .ok_or_else(|| {
            WscdError::Crypto("getPinUvAuthToken response missing pinUvAuthToken (key 2)".into())
        })
}

#[cfg(test)]
mod crypto_kats {
    //! Known-answer tests for the primitives this module builds on.
    //!
    //! The existing tests around ARKG and ClientPin are self-consistency
    //! checks — "derive twice, get the same answer", "encrypt then decrypt".
    //! Those pass even if a dependency upgrade silently changes what the
    //! primitives *compute*, which is exactly the failure that would break
    //! interoperability with a real authenticator while looking green here.
    //!
    //! Every expected value below was produced by an independent
    //! implementation (Python's `hashlib`/`hmac` and OpenSSL via
    //! `cryptography`), and the ones with published vectors were checked
    //! against them.

    use super::*;

    /// NIST SP 800-38A F.2.5, CBC-AES256.Encrypt — the first block of the
    /// published ciphertext is `f58c4c04d6e5f1ba779eabfb5f7bfbd6`.
    #[test]
    fn aes_256_cbc_matches_nist_sp800_38a() {
        let key = hex_lit("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv = hex_lit("000102030405060708090a0b0c0d0e0f");
        let pt = hex_lit(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        let mut buf = pt.clone();
        let len = Aes256CbcEnc::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded::<NoPadding>(&mut buf, pt.len())
            .unwrap()
            .len();
        buf.truncate(len);
        assert_eq!(
            hex::encode(&buf),
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d\
             39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"
                .replace(['\n', ' '], "")
        );
    }

    /// The same through this module's own `encrypt`, which pins the wrapper
    /// and not just the cipher. Protocol One uses a zero IV, so it is
    /// deterministic.
    #[test]
    fn protocol_one_encrypt_is_stable() {
        let key: [u8; 32] =
            hex_lit("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
                .try_into()
                .unwrap();
        let pt = hex_lit("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let ct = encrypt(PinUvAuthProtocol::One, &key, &pt);
        assert_eq!(
            hex::encode(&ct),
            "f3eed1bdb5d2a03c064b5a7e3db181f8e3c48b48365cfb14dc9aaa37b1abc15c"
        );
        assert_eq!(decrypt(PinUvAuthProtocol::One, &key, &ct).unwrap(), pt);
    }

    /// Pins the HKDF-SHA256 call in `derive_aes_key`.
    #[test]
    fn protocol_two_key_derivation_is_stable() {
        let mut shared_x = [0u8; 32];
        for (i, b) in shared_x.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(
            hex::encode(derive_aes_key(PinUvAuthProtocol::Two, &shared_x)),
            "0f6ff2ef211829c11638ef2893ea02edf195658c0572393e7680d93bc2b58d44"
        );
    }

    /// RFC 4231 test case 2 — pins HMAC-SHA256 itself, which both this
    /// module and `arkg` depend on.
    #[test]
    fn hmac_sha256_matches_rfc4231() {
        let mut mac = Hmac::<Sha256>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac.finalize().into_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// RFC 5869 test case 1 — pins HKDF-SHA256, which `arkg` uses for its
    /// own key derivation.
    #[test]
    fn hkdf_sha256_matches_rfc5869() {
        let ikm = [0x0bu8; 22];
        let salt = hex_lit("000102030405060708090a0b0c");
        let info = hex_lit("f0f1f2f3f4f5f6f7f8f9");
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::new(Some(&salt), &ikm)
            .expand(&info, &mut okm)
            .unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
                .replace(['\n', ' '], "")
        );
    }

    fn hex_lit(s: &str) -> Vec<u8> {
        hex::decode(s.replace(['\n', ' '], "")).expect("test vector is valid hex")
    }
}

#[cfg(test)]
mod rejection_tests {
    //! The paths that decide whether to trust what an authenticator sent.
    //!
    //! Everything here is reachable from a device on the other end of a
    //! BLE/NFC/USB link. The tests above prove the crypto computes the right
    //! answers; these prove it refuses the wrong inputs instead of computing
    //! something plausible from them.

    use super::*;

    fn cose_key(x: Vec<u8>, y: Vec<u8>) -> Value {
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-25).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (Value::Integer((-2).into()), Value::Bytes(x)),
            (Value::Integer((-3).into()), Value::Bytes(y)),
        ])
    }

    /// The key-agreement key is the peer half of an ECDH that derives the AES
    /// key protecting the PIN. Every rejection here is a case where accepting
    /// would mean deriving a shared secret from something that is not a valid
    /// P-256 point — coordinates of the wrong length would be concatenated
    /// into a malformed SEC1 encoding, and a point that is not on the curve
    /// is the classic invalid-curve attack setup.
    #[test]
    fn key_agreement_key_must_be_a_real_p256_point() {
        // A genuine key round-trips through this module's own encoder.
        let public = SecretKey::generate().public_key();
        assert_eq!(
            decode_cose_ec2_public_key(&encode_platform_cose_key(&public)).unwrap(),
            public
        );

        // Wrong coordinate lengths, including a truncated x with a correct y.
        for (xlen, ylen) in [(31usize, 32usize), (32, 31), (0, 32), (32, 0), (64, 64)] {
            assert!(
                decode_cose_ec2_public_key(&cose_key(vec![1u8; xlen], vec![2u8; ylen])).is_err(),
                "x={xlen} y={ylen} must be rejected"
            );
        }

        // Correct lengths, but not a point on the curve.
        assert!(decode_cose_ec2_public_key(&cose_key(vec![1u8; 32], vec![2u8; 32])).is_err());

        // Missing coordinates, and a value that is not a map at all.
        assert!(decode_cose_ec2_public_key(&Value::Map(vec![])).is_err());
        assert!(decode_cose_ec2_public_key(&Value::Bytes(vec![4u8; 65])).is_err());
    }

    /// Protocol 2 prepends a 16-byte IV to the ciphertext. A response shorter
    /// than that has no IV, and slicing one out anyway would read past the
    /// buffer; a body that is not a whole number of AES blocks cannot be a
    /// valid `pinUvAuthToken` either. Both are what a truncated or corrupted
    /// transport read looks like.
    #[test]
    fn protocol_two_decrypt_rejects_short_and_unaligned_ciphertext() {
        let key = [0x11u8; 32];
        for len in [0usize, 1, 15] {
            assert!(
                decrypt(PinUvAuthProtocol::Two, &key, &vec![0u8; len]).is_err(),
                "{len}-byte ciphertext has no room for an IV"
            );
        }
        // IV present but the ciphertext body is not block-aligned.
        assert!(decrypt(PinUvAuthProtocol::Two, &key, &[0u8; 16 + 5]).is_err());
        assert!(decrypt(PinUvAuthProtocol::One, &key, &[0u8; 5]).is_err());

        // A real protocol-2 ciphertext carries a fresh IV each time, so two
        // encryptions of the same plaintext must differ - a fixed IV would
        // leak that the same token was reissued.
        let a = encrypt(PinUvAuthProtocol::Two, &key, &[0x42u8; 32]);
        let b = encrypt(PinUvAuthProtocol::Two, &key, &[0x42u8; 32]);
        assert_eq!(a.len(), 16 + 32);
        assert_ne!(a, b, "protocol 2 must use a fresh IV per encryption");
        assert_eq!(
            decrypt(PinUvAuthProtocol::Two, &key, &a).unwrap(),
            [0x42; 32]
        );
        assert_eq!(
            decrypt(PinUvAuthProtocol::Two, &key, &b).unwrap(),
            [0x42; 32]
        );
    }

    /// `authenticate()` output length is protocol-dependent: 16 bytes for
    /// protocol 1, the full 32 for protocol 2 (CTAP2.1 §6.5.6). Sending the
    /// wrong length is an immediate `CTAP2_ERR_PIN_AUTH_INVALID` from real
    /// hardware, and the truncation is easy to lose in a refactor because
    /// both are prefixes of the same HMAC.
    #[test]
    fn pin_uv_auth_param_length_is_protocol_specific() {
        let token = vec![0x42u8; 32];
        let one = PinUvAuthSession {
            protocol: PinUvAuthProtocol::One,
            token: token.clone(),
        };
        let two = PinUvAuthSession {
            protocol: PinUvAuthProtocol::Two,
            token,
        };
        let message = [0x11u8; 32];

        let a = one.authenticate(&message);
        let b = two.authenticate(&message);
        assert_eq!(a.len(), 16);
        assert_eq!(b.len(), 32);
        assert_eq!(
            a,
            b[..16],
            "protocol 1 is protocol 2 truncated, not a different MAC"
        );
        assert_eq!(one.protocol_int(), 1);
        assert_eq!(two.protocol_int(), 2);

        // RFC 4231 test case 2, keyed the way §6.5.6 says: the key is the
        // token itself, never the shared secret.
        let session = PinUvAuthSession {
            protocol: PinUvAuthProtocol::Two,
            token: b"Jefe".to_vec(),
        };
        assert_eq!(
            hex::encode(session.authenticate(b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn protocol_numbers_outside_one_and_two_are_not_accepted() {
        assert_eq!(PinUvAuthProtocol::from_int(1), Some(PinUvAuthProtocol::One));
        assert_eq!(PinUvAuthProtocol::from_int(2), Some(PinUvAuthProtocol::Two));
        for n in [0i64, 3, -1, 255] {
            assert!(
                PinUvAuthProtocol::from_int(n).is_none(),
                "protocol {n} is not implemented and must not be silently downgraded"
            );
        }
    }
}

#[cfg(test)]
mod set_pin_tests {
    //! setPIN (CTAP2.1 6.5.5.4) and the set-then-use flow, against a mock
    //! authenticator that verifies the platform's bytes with its OWN
    //! computation (raw `p256`/`sha2`/`hkdf`/`hmac`/`cbc`, not this module's
    //! `derive_*`/`encrypt`/`decrypt`), plus known-answer vectors produced by
    //! Python `cryptography`.

    use super::*;
    use std::sync::Mutex;

    /// Vectors from an independent implementation (Python `cryptography`):
    /// Z.x = 00..1f, PIN "1234" zero-padded to 64 bytes, protocol 2 IV =
    /// 10..1f. Protocol 2's HMAC key is HKDF info "CTAP2 HMAC key"; the AES
    /// key is HKDF info "CTAP2 AES key".
    #[test]
    fn set_pin_fields_match_independent_vectors() {
        let mut z = [0u8; 32];
        for (i, b) in z.iter_mut().enumerate() {
            *b = i as u8;
        }
        let (enc1, par1) = set_pin_fields(PinUvAuthProtocol::One, &z, b"1234", [0u8; 16]);
        assert_eq!(
            hex::encode(&enc1),
            "8ee0268f5f6c7d12a576d8df40763c922707ab0de43b8e43620b8d64c915fb73\
             5ce6a227f45ac8a2a23b60d342d050d77fc5393988470a68e4ed9e9b85b1c980"
        );
        assert_eq!(hex::encode(&par1), "498ccd5054036100674d9d355bce94db");

        let mut iv = [0u8; 16];
        for (i, b) in iv.iter_mut().enumerate() {
            *b = 16 + i as u8;
        }
        let (enc2, par2) = set_pin_fields(PinUvAuthProtocol::Two, &z, b"1234", iv);
        assert_eq!(
            hex::encode(&enc2),
            "101112131415161718191a1b1c1d1e1f1716007b7f2fe70135a56e45b4a6f3f4\
             48eaef385fac0b98ecd68f57559e63656d1a027b41f3d597f537aa3ca9ec916f\
             3af876c2bdd0cb0dcd80a8285c6f7a8f"
        );
        assert_eq!(
            hex::encode(&par2),
            "2da90386a226dca26d46b9965aa9354b7835d15b3af8eb7fea2b4f92b6d3b795"
        );
    }

    struct MockAuthenticator {
        protocols: Vec<i64>,
        /// `None` => option absent.
        client_pin: Mutex<Option<bool>>,
        min_pin_length: Option<u32>,
        set_pin_status: u8,
        /// Verified-from-the-wire PIN (zero padding stripped) once setPIN ran.
        stored_pin: Mutex<Option<Vec<u8>>>,
        key_agreement_secret: Mutex<Option<SecretKey>>,
        /// Command bytes in order.
        log: Mutex<Vec<Vec<u8>>>,
        /// getKeyAgreement responses given (each must be a fresh key).
        agreement_keys: Mutex<Vec<Vec<u8>>>,
    }

    impl MockAuthenticator {
        fn new(protocol: i64, client_pin: Option<bool>) -> Self {
            Self {
                protocols: vec![protocol],
                client_pin: Mutex::new(client_pin),
                min_pin_length: None,
                set_pin_status: 0,
                stored_pin: Mutex::new(None),
                key_agreement_secret: Mutex::new(None),
                log: Mutex::new(vec![]),
                agreement_keys: Mutex::new(vec![]),
            }
        }
        fn subcommands(&self) -> Vec<(u8, Option<i64>)> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .map(|c| {
                    let sub = if c[0] == 0x06 {
                        let v: Value = ciborium::de::from_reader(&c[1..]).unwrap();
                        Some(field(&v, 2).as_integer().map(i128::from).unwrap() as i64)
                    } else {
                        None
                    };
                    (c[0], sub)
                })
                .collect()
        }
        fn count_set_pin(&self) -> usize {
            self.subcommands()
                .iter()
                .filter(|s| **s == (0x06, Some(3)))
                .count()
        }
    }

    fn field(v: &Value, key: i128) -> &Value {
        v.as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_integer().map(i128::from) == Some(key))
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("missing key {key}"))
    }

    fn ok(body: Option<Value>) -> Vec<u8> {
        let mut out = vec![0u8];
        if let Some(b) = body {
            ciborium::ser::into_writer(&b, &mut out).unwrap();
        }
        out
    }

    /// Independent derivation: (aes_key, hmac_key) from the ECDH x-coord.
    fn independent_keys(protocol: i64, z: &[u8]) -> ([u8; 32], [u8; 32]) {
        if protocol == 1 {
            let k: [u8; 32] = Sha256::digest(z).into();
            (k, k)
        } else {
            let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), z);
            let (mut a, mut h) = ([0u8; 32], [0u8; 32]);
            hk.expand(b"CTAP2 AES key", &mut a).unwrap();
            hk.expand(b"CTAP2 HMAC key", &mut h).unwrap();
            (a, h)
        }
    }

    fn independent_cbc_decrypt(protocol: i64, key: &[u8; 32], ct: &[u8]) -> Vec<u8> {
        let (iv, body) = if protocol == 1 {
            ([0u8; 16], ct)
        } else {
            (<[u8; 16]>::try_from(&ct[..16]).unwrap(), &ct[16..])
        };
        let mut buf = body.to_vec();
        Aes256CbcDec::new_from_slices(key, &iv)
            .unwrap()
            .decrypt_padded::<NoPadding>(&mut buf)
            .unwrap();
        buf
    }

    #[async_trait::async_trait]
    impl Ctap2Transport for MockAuthenticator {
        async fn ctap2_send_command(&self, command: &[u8]) -> Result<Vec<u8>> {
            self.log.lock().unwrap().push(command.to_vec());
            if command[0] == 0x04 {
                let mut options = vec![];
                if let Some(cp) = *self.client_pin.lock().unwrap() {
                    options.push((Value::Text("clientPin".into()), Value::Bool(cp)));
                }
                let mut info = vec![
                    (Value::Integer(4.into()), Value::Map(options)),
                    (
                        Value::Integer(6.into()),
                        Value::Array(
                            self.protocols
                                .iter()
                                .map(|p| Value::Integer((*p).into()))
                                .collect(),
                        ),
                    ),
                ];
                if let Some(m) = self.min_pin_length {
                    info.push((Value::Integer(0x0D.into()), Value::Integer(m.into())));
                }
                return Ok(ok(Some(Value::Map(info))));
            }
            assert_eq!(command[0], 0x06, "only getInfo/ClientPin expected");
            let p: Value = ciborium::de::from_reader(&command[1..]).unwrap();
            let protocol = field(&p, 1).as_integer().map(i128::from).unwrap() as i64;
            let sub = field(&p, 2).as_integer().map(i128::from).unwrap();
            match sub {
                2 => {
                    let secret = SecretKey::generate();
                    let cose = encode_platform_cose_key(&secret.public_key());
                    let mut raw = Vec::new();
                    ciborium::ser::into_writer(&cose, &mut raw).unwrap();
                    self.agreement_keys.lock().unwrap().push(raw);
                    *self.key_agreement_secret.lock().unwrap() = Some(secret);
                    Ok(ok(Some(Value::Map(vec![(Value::Integer(1.into()), cose)]))))
                }
                3 => {
                    if self.set_pin_status != 0 {
                        return Ok(vec![self.set_pin_status]);
                    }
                    let secret = self.key_agreement_secret.lock().unwrap().take().unwrap();
                    let platform = decode_cose_ec2_public_key(field(&p, 3)).unwrap();
                    let z = diffie_hellman(secret.to_nonzero_scalar(), platform.as_affine());
                    let (aes, hmac_key) = independent_keys(protocol, z.raw_secret_bytes());
                    let new_pin_enc = field(&p, 5).as_bytes().unwrap();
                    let param = field(&p, 4).as_bytes().unwrap();

                    let mut mac = Hmac::<Sha256>::new_from_slice(&hmac_key).unwrap();
                    mac.update(new_pin_enc);
                    let full = mac.finalize().into_bytes();
                    let want_len = if protocol == 1 { 16 } else { 32 };
                    assert_eq!(param.len(), want_len, "pinUvAuthParam length");
                    if param[..] != full[..want_len] {
                        return Ok(vec![0x33]); // PIN_AUTH_INVALID
                    }
                    let padded = independent_cbc_decrypt(protocol, &aes, new_pin_enc);
                    assert_eq!(padded.len(), 64, "newPinEnc plaintext is 64 bytes");
                    let end = padded.iter().position(|b| *b == 0).unwrap_or(64);
                    assert!(padded[end..].iter().all(|b| *b == 0), "zero padding");
                    *self.stored_pin.lock().unwrap() = Some(padded[..end].to_vec());
                    *self.client_pin.lock().unwrap() = Some(true);
                    Ok(ok(None))
                }
                9 => {
                    let Some(pin) = self.stored_pin.lock().unwrap().clone() else {
                        return Ok(vec![0x35]); // PIN_NOT_SET: the field bug
                    };
                    let secret = self.key_agreement_secret.lock().unwrap().take().unwrap();
                    let platform = decode_cose_ec2_public_key(field(&p, 3)).unwrap();
                    let z = diffie_hellman(secret.to_nonzero_scalar(), platform.as_affine());
                    let (aes, _) = independent_keys(protocol, z.raw_secret_bytes());
                    let hash_enc = field(&p, 6).as_bytes().unwrap();
                    let hash = independent_cbc_decrypt(protocol, &aes, hash_enc);
                    if hash[..] != Sha256::digest(&pin)[..16] {
                        return Ok(vec![0x31]);
                    }
                    let token = [0x77u8; 32];
                    let iv = if protocol == 1 { [0u8; 16] } else { [9u8; 16] };
                    let mut buf = token.to_vec();
                    Aes256CbcEnc::new_from_slices(&aes, &iv)
                        .unwrap()
                        .encrypt_padded::<NoPadding>(&mut buf, 32)
                        .unwrap();
                    let enc = if protocol == 1 {
                        buf
                    } else {
                        [iv.to_vec(), buf].concat()
                    };
                    Ok(ok(Some(Value::Map(vec![(
                        Value::Integer(2.into()),
                        Value::Bytes(enc),
                    )]))))
                }
                other => panic!("unexpected subCommand {other}"),
            }
        }
    }

    struct PinSource {
        pin: Vec<u8>,
        asked: Mutex<Vec<PinRequestKind>>,
    }
    impl PinSource {
        fn new(pin: &[u8]) -> Self {
            Self {
                pin: pin.to_vec(),
                asked: Mutex::new(vec![]),
            }
        }
    }
    #[async_trait::async_trait]
    impl AuthCallback for PinSource {
        async fn request_pin(&self, _: &str) -> Result<crate::types::Secret> {
            self.asked.lock().unwrap().push(PinRequestKind::EnterPin);
            Ok(crate::types::Secret(self.pin.clone()))
        }
        async fn request_pin_for(
            &self,
            _: &str,
            kind: PinRequestKind,
        ) -> Result<crate::types::Secret> {
            self.asked.lock().unwrap().push(kind);
            Ok(crate::types::Secret(self.pin.clone()))
        }
        async fn request_webauthn_assertion(
            &self,
            _: &str,
            _: &[u8],
            _: &str,
            _: &[Vec<u8>],
        ) -> Result<Vec<u8>> {
            unreachable!()
        }
    }

    async fn acquire(m: &MockAuthenticator, a: &PinSource) -> Result<PinUvAuthSession> {
        acquire_pin_uv_auth_token(m, a, "fido2", PERMISSION_MAKE_CREDENTIAL, Some("rp.test")).await
    }

    #[tokio::test]
    async fn fresh_key_gets_the_pin_set_then_token_for_both_protocols() {
        for protocol in [1i64, 2] {
            let m = MockAuthenticator::new(protocol, Some(false));
            let a = PinSource::new(b"1234");
            let session = acquire(&m, &a).await.expect("set then token");
            assert_eq!(session.token, vec![0x77u8; 32]);
            assert_eq!(
                m.stored_pin.lock().unwrap().as_deref(),
                Some(&b"1234"[..]),
                "authenticator received exactly the PIN the dialog returned"
            );
            // getInfo once, then keyAgreement+setPIN, then a FRESH
            // keyAgreement + token.
            assert_eq!(
                m.subcommands(),
                vec![
                    (0x04, None),
                    (0x06, Some(2)),
                    (0x06, Some(3)),
                    (0x06, Some(2)),
                    (0x06, Some(9)),
                ]
            );
            let keys = m.agreement_keys.lock().unwrap();
            assert_ne!(keys[0], keys[1], "key agreement re-done after setPIN");
            assert_eq!(
                *a.asked.lock().unwrap(),
                vec![PinRequestKind::SetNewPin { min_length: 4 }]
            );
        }
    }

    #[tokio::test]
    async fn existing_pin_is_entered_not_set() {
        let m = MockAuthenticator::new(2, Some(true));
        *m.stored_pin.lock().unwrap() = Some(b"1234".to_vec());
        let a = PinSource::new(b"1234");
        acquire(&m, &a).await.unwrap();
        assert_eq!(m.count_set_pin(), 0);
        assert_eq!(*a.asked.lock().unwrap(), vec![PinRequestKind::EnterPin]);
    }

    #[tokio::test]
    async fn authenticator_without_client_pin_option_never_gets_set_pin() {
        let m = MockAuthenticator::new(1, None);
        let a = PinSource::new(b"1234");
        // Behaves as before: asks to enter a PIN and tries the token; this
        // mock has no PIN so answers 0x35, surfaced as a typed error.
        let err = acquire(&m, &a).await.err().expect("no pin");
        assert!(matches!(err, WscdError::Pin(PinFailure::NotSet)));
        assert_eq!(m.count_set_pin(), 0);
        assert_eq!(*a.asked.lock().unwrap(), vec![PinRequestKind::EnterPin]);
    }

    #[tokio::test]
    async fn too_short_pin_is_refused_before_any_set_pin_is_sent() {
        let mut m = MockAuthenticator::new(2, Some(false));
        m.min_pin_length = Some(6);
        let a = PinSource::new(b"12345");
        let err = acquire(&m, &a).await.err().unwrap();
        assert!(matches!(
            err,
            WscdError::Pin(PinFailure::TooShort { min_length: 6 })
        ));
        assert_eq!(m.subcommands(), vec![(0x04, None)], "only getInfo was sent");
        assert_eq!(
            *a.asked.lock().unwrap(),
            vec![PinRequestKind::SetNewPin { min_length: 6 }],
            "the prompt carried the authenticator's minimum"
        );
        assert!(!err.to_string().contains("12345"));
    }

    #[test]
    fn local_pin_validation_counts_code_points_and_bytes() {
        // 4 code points but 8 bytes: accepted at min 4.
        assert!(validate_new_pin("åäöü".as_bytes(), 4).is_ok());
        assert!(matches!(
            validate_new_pin(b"abc", 4),
            Err(WscdError::Pin(PinFailure::TooShort { .. }))
        ));
        assert!(validate_new_pin(&[b'a'; 63], 4).is_ok());
        assert!(matches!(
            validate_new_pin(&[b'a'; 64], 4),
            Err(WscdError::Pin(PinFailure::TooLong))
        ));
        assert!(matches!(
            validate_new_pin(&[0xff, 0xfe, 0xfd, 0xfc], 4),
            Err(WscdError::Pin(PinFailure::InvalidEncoding))
        ));
        // NFD "é" (e + U+0301) is normalised to NFC before counting/sending.
        let nfd = "e\u{301}e\u{301}e\u{301}e\u{301}";
        assert_eq!(validate_new_pin(nfd.as_bytes(), 4).unwrap().len(), 8);
    }

    #[tokio::test]
    async fn authenticator_errors_map_to_typed_failures() {
        for (status, want) in [
            (0x37u8, PinFailure::PolicyViolation),
            (0x31, PinFailure::Invalid),
            (0x32, PinFailure::Blocked),
            (0x34, PinFailure::AuthBlocked),
            (0x35, PinFailure::NotSet),
        ] {
            let mut m = MockAuthenticator::new(1, Some(false));
            m.set_pin_status = status;
            let a = PinSource::new(b"1234");
            let err = acquire(&m, &a).await.err().unwrap();
            assert!(
                matches!(&err, WscdError::Pin(f) if *f == want),
                "0x{status:02x} -> {err:?}"
            );
            assert!(!err.to_string().contains("1234"));
            // Failed setPIN must not proceed to a token request.
            assert!(!m.subcommands().contains(&(0x06, Some(9))));
        }
    }
}
