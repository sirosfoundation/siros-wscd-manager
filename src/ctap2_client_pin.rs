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
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use ciborium::Value;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::elliptic_curve::Generate;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::callbacks::Ctap2Transport;
use crate::error::{Result, WscdError};
use crate::preview_sign_protocol::{encode_command, split_status};

const CTAP2_GET_INFO: u8 = 0x04;
const CTAP2_CLIENT_PIN: u8 = 0x06;

const SUBCMD_GET_KEY_AGREEMENT: i64 = 0x02;
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
pub async fn get_pin_uv_auth_token(
    transport: &dyn Ctap2Transport,
    pin: &[u8],
    permissions: u8,
    rp_id: Option<&str>,
) -> Result<PinUvAuthSession> {
    let protocol = select_protocol(transport).await?;

    let platform_secret = SecretKey::generate();
    let platform_public = platform_secret.public_key();

    let peer_public = get_key_agreement(transport, protocol).await?;
    let shared_point_x = ecdh_shared_x(&platform_secret, &peer_public)?;
    let aes_key = derive_aes_key(protocol, &shared_point_x);

    let pin_hash: [u8; 16] = {
        let digest = Sha256::digest(pin);
        digest[..16].try_into().expect("SHA-256 digest is 32 bytes")
    };
    let pin_hash_enc = encrypt(protocol, &aes_key, &pin_hash);

    let token_enc = send_get_pin_token(
        transport,
        protocol,
        &platform_public,
        &pin_hash_enc,
        permissions,
        rp_id,
    )
    .await?;
    let token = decrypt(protocol, &aes_key, &token_enc)?;

    Ok(PinUvAuthSession { protocol, token })
}

/// Send `authenticatorGetInfo` and pick the first PinUvAuthProtocol this
/// module implements (1 or 2) from the authenticator's advertised list
/// (`pinUvAuthProtocols`, key 6) - listed in the authenticator's order of
/// preference. Defaults to protocol 1 if the field is absent (pre-2.1
/// authenticators that only ever supported protocol 1 didn't advertise
/// it explicitly).
async fn select_protocol(transport: &dyn Ctap2Transport) -> Result<PinUvAuthProtocol> {
    let command = vec![CTAP2_GET_INFO];
    let response = transport.ctap2_send_command(&command).await?;
    let body = split_status(&response)?;
    let info: Value = ciborium::de::from_reader(body)
        .map_err(|e| WscdError::Crypto(format!("invalid getInfo CBOR: {e}")))?;
    let map = info
        .as_map()
        .ok_or_else(|| WscdError::Crypto("getInfo response is not a CBOR map".into()))?;

    let protocols = map
        .iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(6))
        .and_then(|(_, v)| v.as_array());

    let Some(protocols) = protocols else {
        return Ok(PinUvAuthProtocol::One);
    };

    for value in protocols {
        match value.as_integer().map(i128::from) {
            Some(1) => return Ok(PinUvAuthProtocol::One),
            Some(2) => return Ok(PinUvAuthProtocol::Two),
            _ => continue,
        }
    }
    Ok(PinUvAuthProtocol::One)
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
    let body = split_status(&response)?;
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
        .encrypt_padded_mut::<NoPadding>(&mut buf, plaintext.len())
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
        .decrypt_padded_mut::<NoPadding>(&mut buf)
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
    let body = split_status(&response)?;
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
