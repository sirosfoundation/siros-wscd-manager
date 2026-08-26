//! Shared protocol types and CBOR/COSE parsing for the WebAuthn "sign
//! extension" (draft v4: <https://yubicolabs.github.io/webauthn-sign-extension/4/>,
//! implemented by YubiKey firmware ≥5.8 under the extension identifier
//! `previewSign`).
//!
//! This module is the single place that understands the extension's wire
//! shapes. It is used by both [`crate::wasm_fido2`] (browser, via
//! `navigator.credentials`) and the native FFI transport bridge in
//! [`crate::ffi`] (raw CTAP2 over BLE/NFC/USB) — the two platforms differ in
//! how they *obtain* a public key or signature, but not in how those values
//! are shaped or decoded, so that decoding logic lives here exactly once.
//!
//! The native-transport request-building/response-parsing in this module
//! (everything below [`decode_cose_ec2_public_key`]/
//! [`extract_previewsign_signature`]) had its `generateKey` half CONFIRMED
//! against real hardware early on (a YubiKey 5.8 Early Access unit,
//! 2026-08-04), cross-checked against Yubico's own `python-fido2` library
//! (`fido2/ctap2/extensions.py`'s `PreviewSignExtension`). The raw wire
//! shape uses flat INTEGER CBOR keys - NOT the nested string-keyed
//! `{"generateKey": {"algorithms": [...]}}` shape the browser/WebAuthn JS
//! API exposes (that shape is client-side only; a real browser's own
//! WebAuthn client translates it to this before it ever reaches the
//! authenticator).
//!
//! The `signByCredential`/`get_assertion` half was NOT actually exercised
//! end-to-end against real hardware until 2026-08-10, when doing so
//! surfaced four real, independent bugs in this exact path: wrong
//! `authenticatorGetAssertion` CBOR parameter numbers (copy-pasted from
//! `authenticatorMakeCredential`'s different layout - see
//! [`build_get_assertion_request`]), an unhashed `tbs` (the extension
//! needs a SHA-256 digest, not raw signing input), a missing/then
//! incorrectly-encoded ARKG `additionalArgs` (see
//! [`crate::arkg::encode_arkg_sign_args`]), and a DER-vs-raw signature
//! encoding mismatch (see [`crate::plugins::preview_sign`]'s `sign()`). All
//! four are now fixed and the full ceremony verified end-to-end against a
//! real YubiKey and go-wallet-backend's own JWS verifier.

use ciborium::Value;

use crate::error::{Result, WscdError};

/// Input to a makeCredential ceremony's `generateKey` request: the set of
/// COSE algorithm identifiers the caller is willing to accept for the
/// signing key the authenticator will generate.
#[derive(Debug, Clone)]
pub struct GenerateKeyInput {
    pub algorithms: Vec<i64>,
}

/// The signing key an authenticator generated during `generateKey`.
#[derive(Debug, Clone)]
pub struct GeneratedKey {
    /// Opaque handle the authenticator uses to identify this signing key on
    /// later `sign` calls. Distinct from the WebAuthn credential ID.
    pub key_handle: Vec<u8>,
    /// Raw COSE_Key CBOR bytes for the generated public key.
    pub public_key_cose: Vec<u8>,
    /// COSE algorithm identifier of the generated key.
    pub algorithm: i64,
    /// Raw attestation object proving the key was generated on this
    /// authenticator.
    pub attestation_object: Vec<u8>,
}

/// Full result of a makeCredential ceremony that requested `generateKey`.
#[derive(Debug, Clone)]
pub struct MakeCredentialResult {
    /// The WebAuthn credential ID (`credential.rawId`) — used to scope a
    /// later `signByCredential` request. Distinct from the signing key's
    /// own `key_handle`.
    pub credential_id: Vec<u8>,
    pub generated_key: GeneratedKey,
}

/// Input to a getAssertion ceremony's `signByCredential` request for one
/// credential.
#[derive(Debug, Clone)]
pub struct SignInput {
    pub key_handle: Vec<u8>,
    /// The (possibly pre-hashed) to-be-signed bytes.
    pub tbs: Vec<u8>,
    /// COSE-encoded extra arguments some derived-key schemes (e.g. ARKG)
    /// need at signing time. `None` for plain, non-derived keys.
    pub additional_args: Option<Vec<u8>>,
}

/// Result of a getAssertion ceremony's `signByCredential` request.
#[derive(Debug, Clone)]
pub struct SignResult {
    pub signature: Vec<u8>,
}

/// Decode an EC2 COSE_Key (kty=2) into its (x, y) coordinates.
///
/// COSE_Key is a CBOR map with integer labels: 1=kty, 3=alg, -1=crv,
/// -2=x, -3=y (RFC 9053 §7.1).
pub fn decode_cose_ec2_public_key(cose_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let value: Value = ciborium::de::from_reader(cose_bytes)
        .map_err(|e| WscdError::Crypto(format!("invalid COSE key CBOR: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| WscdError::Crypto("COSE key is not a CBOR map".into()))?;

    let get_bytes = |label: i128| -> Option<Vec<u8>> {
        map.iter().find_map(|(k, v)| {
            let key_matches = k.as_integer().map(i128::from) == Some(label);
            if key_matches {
                v.as_bytes().cloned()
            } else {
                None
            }
        })
    };

    let x =
        get_bytes(-2).ok_or_else(|| WscdError::Crypto("COSE key missing x coordinate".into()))?;
    let y =
        get_bytes(-3).ok_or_else(|| WscdError::Crypto("COSE key missing y coordinate".into()))?;

    if x.is_empty() || y.is_empty() {
        return Err(WscdError::Crypto(
            "COSE key x/y coordinate must not be empty".into(),
        ));
    }
    if x.len() != y.len() {
        return Err(WscdError::Crypto(format!(
            "COSE key x/y coordinate length mismatch: x={} y={}",
            x.len(),
            y.len()
        )));
    }

    Ok((x, y))
}

/// Extract the `previewSign` signature (extension output key `6`) from a
/// getAssertion response's `authenticatorData`.
///
/// `authenticatorData` layout (WebAuthn §6.1): `rpIdHash(32) || flags(1) ||
/// signCount(4) || [extensions]`. Assertion responses never carry
/// `attestedCredentialData` (that's makeCredential-only), so extensions —
/// present when the ED flag (`0x80`) is set — start right after the fixed
/// 37-byte header. The extensions themselves are a CBOR map keyed by
/// extension identifier; `previewSign`'s value is itself a CBOR map whose
/// key `6` holds the raw signature bytes.
pub fn extract_previewsign_signature(authenticator_data: &[u8]) -> Result<Vec<u8>> {
    const HEADER_LEN: usize = 32 + 1 + 4;
    const AT_FLAG: u8 = 0x40;
    const ED_FLAG: u8 = 0x80;

    if authenticator_data.len() <= HEADER_LEN {
        return Err(WscdError::Crypto(
            "authenticatorData too short to contain extensions".into(),
        ));
    }
    let flags = authenticator_data[32];
    if flags & AT_FLAG != 0 {
        // Assertion (getAssertion) responses never carry attestedCredentialData;
        // if AT is set here, our fixed 37-byte offset for the start of
        // extensions would be wrong, so refuse to guess.
        return Err(WscdError::Crypto(
            "authenticatorData unexpectedly has AT flag set in an assertion response".into(),
        ));
    }
    if flags & ED_FLAG == 0 {
        return Err(WscdError::Crypto(
            "authenticatorData has no extensions (ED flag not set)".into(),
        ));
    }

    let ext_bytes = &authenticator_data[HEADER_LEN..];
    let value: Value = ciborium::de::from_reader(ext_bytes).map_err(|e| {
        WscdError::Crypto(format!("invalid authenticatorData extensions CBOR: {e}"))
    })?;
    let map = value.as_map().ok_or_else(|| {
        WscdError::Crypto("authenticatorData extensions is not a CBOR map".into())
    })?;

    let preview_sign = map
        .iter()
        .find_map(|(k, v)| {
            if k.as_text() == Some("previewSign") {
                Some(v)
            } else {
                None
            }
        })
        .ok_or_else(|| WscdError::Crypto("no previewSign extension in authenticatorData".into()))?;

    let inner_map = preview_sign.as_map().ok_or_else(|| {
        WscdError::Crypto("previewSign extension output is not a CBOR map".into())
    })?;

    inner_map
        .iter()
        .find_map(|(k, v)| {
            let key_matches = k.as_integer().map(i128::from) == Some(6);
            if key_matches {
                v.as_bytes().cloned()
            } else {
                None
            }
        })
        .ok_or_else(|| WscdError::Crypto("previewSign extension missing signature (key 6)".into()))
}

/// Convert an ECDSA signature from CTAP2's native ASN.1 DER encoding
/// (`SEQUENCE{INTEGER r, INTEGER s}`, what [`extract_previewsign_signature`]
/// returns) to the raw, fixed-size `r || s` concatenation JWS ES256
/// (RFC 7518 §3.4) requires.
///
/// Confirmed necessary via live hardware testing: a real YubiKey's
/// `signByCredential` response signature decoded as an unambiguous DER
/// SEQUENCE (leading bytes `0x30 0x45 0x02 0x20 ...`), and go-wallet-
/// backend's `crypto/ecdsa`-based JWS verifier rejected the un-converted
/// DER bytes as an invalid signature even though the device-side signing
/// itself succeeded. The softkey plugin's own `sign()` already returns raw
/// bytes (`p256::ecdsa::Signature::to_bytes()`'s own format) - this brings
/// previewSign's output in line with that same contract.
pub fn der_signature_to_raw(der: &[u8]) -> Result<Vec<u8>> {
    let sig = p256::ecdsa::Signature::from_der(der)
        .map_err(|e| WscdError::Crypto(format!("invalid DER signature from authenticator: {e}")))?;
    Ok(sig.to_bytes().to_vec())
}

// ─── Native-transport request building / response parsing ────────────────
//
// Everything below talks in terms of a single logical CTAP2 message: a
// leading command-code byte followed by CBOR params (request), or a
// leading status byte followed by CBOR body (response). Host transports
// (USB CTAPHID, NFC/NFCCTAP_MSG, BLE) own all their own framing around
// this - see [`crate::callbacks::Ctap2Transport::ctap2_send_command`].

const CTAP2_MAKE_CREDENTIAL: u8 = 0x01;
const CTAP2_GET_ASSERTION: u8 = 0x02;

/// ARKG_P256_ESP256, the previewSign/ARKG generateKey algorithm - a
/// distinct COSE identifier from standard ES256 (-7). Confirmed via
/// Yubico's own docs and `python-fido2`'s `ESP256_SPLIT_ARKG_PLACEHOLDER`.
pub const ARKG_P256_ESP256: i64 = -65539;

/// `EcsdsaBls12_381_BP1_Sha256_SEC1` — the previewSign `generateKey`
/// algorithm for BBS key binding keys.
///
/// A **placeholder** identifier, exactly like [`ARKG_P256_ESP256`]: it is
/// annotated `# Placeholder value` in `emlun/python-fido2`'s `cose.py`, is
/// not IANA-registered, and will change when it is. Supported on YubiKey
/// 5.8 alpha firmware, which added Schnorr signatures and the key types
/// they need.
pub const ECSDSA_BLS12381_BP1_SHA256_SEC1: i64 = -65609;

/// COSE curve identifier for BLS12-381 G1, and the placeholder some
/// prototype firmware uses instead.
///
/// `python-fido2`'s own verifier accepts either, so this does too.
const COSE_CRV_BLS12_381_G1: i64 = 13;
const COSE_CRV_BLS12_381_G1_PLACEHOLDER: i64 = -65601;

/// A compressed BLS12-381 G1 point, in octets.
pub const BLS12381_G1_COMPRESSED_LEN: usize = 48;

/// A Schnorr-over-G1 signature: two 32-octet scalars, `serialize([k_hat, c])`.
pub const BLS12381_SCHNORR_SIGNATURE_LEN: usize = 64;

/// Decodes the COSE_Key a BLS key binding `generateKey` returns.
///
/// Shaped unlike [`decode_cose_ec2_public_key`] on purpose: a G1 public key
/// is a **single compressed point** in COSE label `-2`, not an `(x, y)`
/// pair, so there is no `-3` to read and nothing to concatenate.
///
/// The curve is checked; `kty` deliberately is not. `python-fido2`'s own
/// `EcsdsaBls12_381_BP1_Sha256_SEC1.verify` checks only `-1`, and this
/// identifier space is prototype-grade — rejecting an unexpected `kty`
/// would be inventing strictness the reference implementation does not
/// have.
pub fn decode_cose_bls12381_g1_public_key(cose_bytes: &[u8]) -> Result<Vec<u8>> {
    let value: Value = ciborium::de::from_reader(cose_bytes)
        .map_err(|e| WscdError::Crypto(format!("invalid COSE key CBOR: {e}")))?;

    let map = value
        .as_map()
        .ok_or_else(|| WscdError::Crypto("COSE key is not a CBOR map".into()))?;

    let crv = get_value_by_int(map, -1)
        .and_then(|v| v.as_integer())
        .and_then(|i| i64::try_from(i).ok())
        .ok_or_else(|| WscdError::Crypto("COSE key has no curve (label -1)".into()))?;
    if crv != COSE_CRV_BLS12_381_G1 && crv != COSE_CRV_BLS12_381_G1_PLACEHOLDER {
        return Err(WscdError::Crypto(format!(
            "unexpected curve {crv} for a BLS12-381 G1 key (expected {COSE_CRV_BLS12_381_G1} or {COSE_CRV_BLS12_381_G1_PLACEHOLDER})"
        )));
    }

    let point = get_value_by_int(map, -2)
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| WscdError::Crypto("COSE key has no public point (label -2)".into()))?;
    if point.len() != BLS12381_G1_COMPRESSED_LEN {
        return Err(WscdError::Crypto(format!(
            "BLS12-381 G1 public key is {} octets, expected {BLS12381_G1_COMPRESSED_LEN}",
            point.len()
        )));
    }
    Ok(point.clone())
}

/// Validates a Schnorr-over-G1 signature's shape.
///
/// The counterpart of [`der_signature_to_raw`], which must **not** be
/// applied here: this algorithm returns two raw 32-octet scalars, not a DER
/// `SEQUENCE`, so DER parsing would fail on every valid signature.
pub fn validate_bls12381_schnorr_signature(sig: &[u8]) -> Result<Vec<u8>> {
    if sig.len() != BLS12381_SCHNORR_SIGNATURE_LEN {
        return Err(WscdError::Crypto(format!(
            "BLS12-381 Schnorr signature is {} octets, expected {BLS12381_SCHNORR_SIGNATURE_LEN}",
            sig.len()
        )));
    }
    Ok(sig.to_vec())
}

/// The largest `tbs` the prototype firmware accepts.
///
/// A BBS key binding challenge is a 48-octet point plus a 32-octet scalar =
/// 80 octets, which is over this — which is why the caller hands over a
/// SHA-256 digest instead (`zk-cred-bbs`'s `PROFILE.md` DELTA 3).
pub const PREVIEW_SIGN_MAX_TBS_LEN: usize = 64;

/// The exact `tbs` length a BBS key binding signature takes.
///
/// Both of the messages this algorithm ever signs are 32 octets, though for
/// different reasons: the *commitment* challenge is a bare BBS scalar, and
/// the *presentation* challenge is a SHA-256 digest of an 80-octet value
/// that would not otherwise fit under [`PREVIEW_SIGN_MAX_TBS_LEN`].
///
/// Requiring it exactly, rather than merely capping at the firmware ceiling,
/// is what turns "caller passed the wrong thing" into an error here instead
/// of a proof that fails verification much later with nothing to point at —
/// a 48-octet compressed point, say, is under the ceiling but is not a
/// challenge. Note this is a constraint of the BBS key binding *profile*,
/// not of Schnorr-over-G1 itself: relaxing it is a deliberate code change,
/// which is the point.
pub const BLS12381_KEYBIND_TBS_LEN: usize = 32;

/// Standard WebAuthn/CTAP2 algorithms for the OUTER credential's own
/// `pubKeyCredParams` - a DIFFERENT thing from the previewSign extension's
/// own `generateKey.algorithms` (which should be [`ARKG_P256_ESP256`]).
/// Matches the set a real `python-fido2` `Fido2Server` sends by default,
/// confirmed via a captured real request against this same hardware.
const DEFAULT_PUB_KEY_CRED_ALGS: &[i64] = &[-7, -8, -35, -36, -37, -257, -47, -48, -49, -50];

fn int_key(n: i64) -> Value {
    Value::Integer(n.into())
}

fn get_bytes_by_int(map: &[(Value, Value)], key: i64) -> Option<&Vec<u8>> {
    map.iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(key as i128))
        .and_then(|(_, v)| v.as_bytes())
}

fn get_value_by_int(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(key as i128))
        .map(|(_, v)| v)
}

fn get_value_by_text<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

/// Build the `previewSign.generateKey` CTAP2 extension input:
/// `{"previewSign": {3: [algorithms...], 4: flags}}`. `flags` is a
/// bitmask (`0b001`=UP, `0b101`=UP+UV) - this field is the ENTIRE UV
/// signaling mechanism for this extension. Do NOT also attach an outer
/// `pinUvAuthParam`/`pinUvAuthProtocol` for it - confirmed via real
/// hardware that doing so produces `CTAP2_ERR_PIN_AUTH_BLOCKED` even with
/// a cryptographically valid PIN/UV token.
fn build_generate_key_extension(algorithms: &[i64], require_uv: bool) -> Value {
    let algs = Value::Array(algorithms.iter().map(|a| int_key(*a)).collect());
    let flags: i64 = if require_uv { 0b101 } else { 0b001 };
    Value::Map(vec![(
        Value::Text("previewSign".into()),
        Value::Map(vec![(int_key(3), algs), (int_key(4), int_key(flags))]),
    )])
}

/// Build the `previewSign.signByCredential` CTAP2 extension input:
/// `{"previewSign": {2: key-handle, 6: tbs, 7?: additional-args}}`.
fn build_sign_by_credential_extension(sign: &SignInput) -> Value {
    let mut inner = vec![
        (int_key(2), Value::Bytes(sign.key_handle.clone())),
        (int_key(6), Value::Bytes(sign.tbs.clone())),
    ];
    if let Some(args) = &sign.additional_args {
        inner.push((int_key(7), Value::Bytes(args.clone())));
    }
    Value::Map(vec![(Value::Text("previewSign".into()), Value::Map(inner))])
}

/// Build a full `authenticatorMakeCredential` (0x01) command: leading
/// command byte + CBOR params map (keys 1-6). `pubKeyCredParams` (key 4)
/// uses the standard algorithm list, NOT `generate_key.algorithms` - see
/// [`DEFAULT_PUB_KEY_CRED_ALGS`]'s doc comment for why conflating the two
/// is wrong.
pub fn build_make_credential_request(
    rp_id: &str,
    user_id: &[u8],
    client_data_hash: &[u8],
    generate_key: &GenerateKeyInput,
    pin_uv_auth: Option<(&[u8], i64)>,
) -> Vec<u8> {
    let rp = Value::Map(vec![
        (Value::Text("id".into()), Value::Text(rp_id.into())),
        (Value::Text("name".into()), Value::Text(rp_id.into())),
    ]);
    let user = Value::Map(vec![
        (Value::Text("id".into()), Value::Bytes(user_id.to_vec())),
        (Value::Text("name".into()), Value::Text("wscd-user".into())),
        (
            Value::Text("displayName".into()),
            Value::Text("WSCD User".into()),
        ),
    ]);
    let pub_key_cred_params = Value::Array(
        DEFAULT_PUB_KEY_CRED_ALGS
            .iter()
            .map(|alg| {
                Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("alg".into()), int_key(*alg)),
                ])
            })
            .collect(),
    );
    let mut params = vec![
        (int_key(1), Value::Bytes(client_data_hash.to_vec())),
        (int_key(2), rp),
        (int_key(3), user),
        (int_key(4), pub_key_cred_params),
        (
            int_key(6),
            build_generate_key_extension(&generate_key.algorithms, true),
        ),
    ];
    if let Some((param, protocol)) = pin_uv_auth {
        params.push((int_key(8), Value::Bytes(param.to_vec())));
        params.push((int_key(9), int_key(protocol)));
    }
    encode_command(CTAP2_MAKE_CREDENTIAL, &Value::Map(params))
}

/// Build a full `authenticatorGetAssertion` (0x02) command.
pub fn build_get_assertion_request(
    rp_id: &str,
    challenge: &[u8],
    credential_id: &[u8],
    sign: &SignInput,
    pin_uv_auth: Option<(&[u8], i64)>,
) -> Vec<u8> {
    let allow_list = Value::Array(vec![Value::Map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("id".into()),
            Value::Bytes(credential_id.to_vec()),
        ),
    ])]);
    // authenticatorGetAssertion params (CTAP2.1 §6.2): 1=rpId,
    // 2=clientDataHash, 3=allowList, 4=extensions, 5=options,
    // 6=pinUvAuthParam, 7=pinUvAuthProtocol - a DIFFERENT layout from
    // authenticatorMakeCredential's (where extensions=6, pinUvAuthParam=8,
    // pinUvAuthProtocol=9), confirmed via live hardware testing: this
    // function previously reused MakeCredential's key numbers here,
    // which a real YubiKey correctly rejected as CTAP2 error 0x02
    // (invalid parameter) - the sign step failed every time, even
    // though key generation (MakeCredential) itself worked fine.
    let mut params = vec![
        (int_key(1), Value::Text(rp_id.into())),
        (int_key(2), Value::Bytes(challenge.to_vec())),
        (int_key(3), allow_list),
        (int_key(4), build_sign_by_credential_extension(sign)),
    ];
    if let Some((param, protocol)) = pin_uv_auth {
        params.push((int_key(6), Value::Bytes(param.to_vec())));
        params.push((int_key(7), int_key(protocol)));
    }
    encode_command(CTAP2_GET_ASSERTION, &Value::Map(params))
}

pub(crate) fn encode_command(command: u8, params: &Value) -> Vec<u8> {
    let mut buf = vec![command];
    ciborium::ser::into_writer(params, &mut buf).expect("CBOR encoding is infallible for Value");
    buf
}

fn encode_value(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).expect("CBOR encoding is infallible for Value");
    buf
}

/// Parsed `authenticatorMakeCredential` request fields - the inverse of
/// [`build_make_credential_request`]. Useful for a transport that
/// RECEIVES a raw command rather than sends one to real hardware (the
/// WASM browser transport, which decodes this to make the equivalent
/// `navigator.credentials.create()` call).
pub struct MakeCredentialRequest {
    pub rp_id: String,
    pub user_id: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub generate_key: GenerateKeyInput,
}

pub fn parse_make_credential_request(command: &[u8]) -> Result<MakeCredentialRequest> {
    if command.first() != Some(&CTAP2_MAKE_CREDENTIAL) {
        return Err(WscdError::Crypto(
            "not an authenticatorMakeCredential command".into(),
        ));
    }
    let params: Value = ciborium::de::from_reader(&command[1..])
        .map_err(|e| WscdError::Crypto(format!("invalid MakeCredential params CBOR: {e}")))?;
    let map = params
        .as_map()
        .ok_or_else(|| WscdError::Crypto("MakeCredential params is not a map".into()))?;

    let client_data_hash = get_bytes_by_int(map, 1)
        .ok_or_else(|| WscdError::Crypto("missing clientDataHash".into()))?
        .clone();
    let rp = get_value_by_int(map, 2)
        .and_then(|v| v.as_map())
        .ok_or_else(|| WscdError::Crypto("missing rp".into()))?;
    let rp_id = get_value_by_text(rp, "id")
        .and_then(|v| v.as_text())
        .ok_or_else(|| WscdError::Crypto("missing rp.id".into()))?
        .to_string();
    let user = get_value_by_int(map, 3)
        .and_then(|v| v.as_map())
        .ok_or_else(|| WscdError::Crypto("missing user".into()))?;
    let user_id = get_value_by_text(user, "id")
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| WscdError::Crypto("missing user.id".into()))?
        .clone();
    let extensions = get_value_by_int(map, 6)
        .and_then(|v| v.as_map())
        .ok_or_else(|| WscdError::Crypto("missing extensions".into()))?;
    let preview_sign = get_value_by_text(extensions, "previewSign")
        .and_then(|v| v.as_map())
        .ok_or_else(|| WscdError::Crypto("missing previewSign extension".into()))?;
    let algorithms = get_value_by_int(preview_sign, 3)
        .and_then(|v| v.as_array())
        .ok_or_else(|| WscdError::Crypto("missing generateKey algorithms".into()))?
        .iter()
        .filter_map(|v| v.as_integer().and_then(|i| i64::try_from(i).ok()))
        .collect();

    Ok(MakeCredentialRequest {
        rp_id,
        user_id,
        client_data_hash,
        generate_key: GenerateKeyInput { algorithms },
    })
}

/// Parsed `authenticatorGetAssertion` request fields - the inverse of
/// [`build_get_assertion_request`].
pub struct GetAssertionRequest {
    pub rp_id: String,
    pub challenge: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub sign: SignInput,
}

pub fn parse_get_assertion_request(command: &[u8]) -> Result<GetAssertionRequest> {
    if command.first() != Some(&CTAP2_GET_ASSERTION) {
        return Err(WscdError::Crypto(
            "not an authenticatorGetAssertion command".into(),
        ));
    }
    let params: Value = ciborium::de::from_reader(&command[1..])
        .map_err(|e| WscdError::Crypto(format!("invalid GetAssertion params CBOR: {e}")))?;
    let map = params
        .as_map()
        .ok_or_else(|| WscdError::Crypto("GetAssertion params is not a map".into()))?;

    let rp_id = get_value_by_int(map, 1)
        .and_then(|v| v.as_text())
        .ok_or_else(|| WscdError::Crypto("missing rpId".into()))?
        .to_string();
    let challenge = get_bytes_by_int(map, 2)
        .ok_or_else(|| WscdError::Crypto("missing challenge".into()))?
        .clone();
    let allow_list = get_value_by_int(map, 3)
        .and_then(|v| v.as_array())
        .ok_or_else(|| WscdError::Crypto("missing allowList".into()))?;
    let first = allow_list
        .first()
        .and_then(|v| v.as_map())
        .ok_or_else(|| WscdError::Crypto("empty allowList".into()))?;
    let credential_id = get_value_by_text(first, "id")
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| WscdError::Crypto("missing allowList[0].id".into()))?
        .clone();

    // GetAssertion's extensions live at key 4, NOT 6 (that's MakeCredential's
    // layout) - see build_get_assertion_request's doc comment.
    let extensions = get_value_by_int(map, 4)
        .and_then(|v| v.as_map())
        .ok_or_else(|| WscdError::Crypto("missing extensions".into()))?;
    let preview_sign = get_value_by_text(extensions, "previewSign")
        .and_then(|v| v.as_map())
        .ok_or_else(|| WscdError::Crypto("missing previewSign extension".into()))?;
    let key_handle = get_value_by_int(preview_sign, 2)
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| WscdError::Crypto("missing signByCredential keyHandle".into()))?
        .clone();
    let tbs = get_value_by_int(preview_sign, 6)
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| WscdError::Crypto("missing signByCredential tbs".into()))?
        .clone();
    let additional_args = get_value_by_int(preview_sign, 7)
        .and_then(|v| v.as_bytes())
        .cloned();

    Ok(GetAssertionRequest {
        rp_id,
        challenge,
        credential_id,
        sign: SignInput {
            key_handle,
            tbs,
            additional_args,
        },
    })
}

fn build_attested_auth_data(
    aaguid: &[u8; 16],
    cred_id: &[u8],
    cose_key_bytes: &[u8],
    signed_extensions: Option<Value>,
) -> Vec<u8> {
    let mut buf = vec![0u8; 32]; // rpIdHash - not validated by parsers on this side
    let mut flags = 0x40u8; // AT
    if signed_extensions.is_some() {
        flags |= 0x80; // ED
    }
    buf.push(flags);
    buf.extend_from_slice(&[0, 0, 0, 1]); // signCount
    buf.extend_from_slice(aaguid);
    let len = cred_id.len() as u16;
    buf.push((len >> 8) as u8);
    buf.push((len & 0xFF) as u8);
    buf.extend_from_slice(cred_id);
    buf.extend_from_slice(cose_key_bytes);
    if let Some(ext) = signed_extensions {
        ciborium::ser::into_writer(&ext, &mut buf).expect("CBOR encoding is infallible for Value");
    }
    buf
}

fn build_unattested_auth_data(signed_extensions: Option<Value>) -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    let flags: u8 = if signed_extensions.is_some() {
        0x80
    } else {
        0x00
    };
    buf.push(flags);
    buf.extend_from_slice(&[0, 0, 0, 1]);
    if let Some(ext) = signed_extensions {
        ciborium::ser::into_writer(&ext, &mut buf).expect("CBOR encoding is infallible for Value");
    }
    buf
}

/// A structurally-valid but otherwise meaningless EC2 COSE key, used to
/// fill the OUTER credential's `attestedCredentialData` when encoding a
/// synthetic response - nothing reads this back
/// ([`parse_make_credential_response`] discards the outer credential's
/// own public key, since callers only care about the previewSign-
/// generated key).
fn placeholder_cose_key() -> Vec<u8> {
    encode_value(&Value::Map(vec![
        (int_key(1), int_key(2)),
        (int_key(3), int_key(-7)),
        (int_key(-1), int_key(1)),
        (int_key(-2), Value::Bytes(vec![0u8; 32])),
        (int_key(-3), Value::Bytes(vec![0u8; 32])),
    ]))
}

/// Encode a full `authenticatorMakeCredential` response - the inverse of
/// [`parse_make_credential_response`]. Used by transports that don't talk
/// to real CTAP2 hardware but still need to hand back a CTAP2-shaped
/// response (the WASM browser transport, after calling
/// `navigator.credentials.create()`).
pub fn encode_make_credential_response(result: &MakeCredentialResult) -> Vec<u8> {
    let inner_auth_data = build_attested_auth_data(
        &[0u8; 16],
        &result.generated_key.key_handle,
        &result.generated_key.public_key_cose,
        None,
    );
    let inner_att_obj = Value::Map(vec![
        (int_key(1), Value::Text("none".into())),
        (int_key(2), Value::Bytes(inner_auth_data)),
        (int_key(3), Value::Map(vec![])),
    ]);
    let inner_bytes = encode_value(&inner_att_obj);

    let signed_extensions = Value::Map(vec![(
        Value::Text("previewSign".into()),
        Value::Map(vec![(int_key(3), int_key(result.generated_key.algorithm))]),
    )]);
    let outer_auth_data = build_attested_auth_data(
        &[0u8; 16],
        &result.credential_id,
        &placeholder_cose_key(),
        Some(signed_extensions),
    );
    let outer_att_obj = Value::Map(vec![
        (int_key(1), Value::Text("none".into())),
        (int_key(2), Value::Bytes(outer_auth_data)),
        (int_key(3), Value::Map(vec![])),
        (int_key(7), Value::Bytes(inner_bytes)),
    ]);

    let mut response = vec![0x00u8];
    response.extend(encode_value(&outer_att_obj));
    response
}

/// Encode a full `authenticatorGetAssertion` response - the inverse of
/// [`parse_get_assertion_response`].
pub fn encode_get_assertion_response(result: &SignResult) -> Vec<u8> {
    let signed_extensions = Value::Map(vec![(
        Value::Text("previewSign".into()),
        Value::Map(vec![(int_key(6), Value::Bytes(result.signature.clone()))]),
    )]);
    let auth_data = build_unattested_auth_data(Some(signed_extensions));
    let assert_obj = Value::Map(vec![(int_key(2), Value::Bytes(auth_data))]);

    let mut response = vec![0x00u8];
    response.extend(encode_value(&assert_obj));
    response
}

pub(crate) fn ctap2_status_name(status: u8) -> &'static str {
    match status {
        0x11 => "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
        0x12 => "CTAP2_ERR_INVALID_CBOR",
        0x14 => "CTAP2_ERR_MISSING_PARAMETER",
        0x19 => "CTAP2_ERR_UNSUPPORTED_EXTENSION",
        0x26 => "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
        0x27 => "CTAP2_ERR_OPERATION_DENIED",
        0x30 => "CTAP2_ERR_NOT_ALLOWED",
        0x31 => "CTAP2_ERR_PIN_INVALID",
        0x33 => "CTAP2_ERR_PIN_AUTH_INVALID",
        0x34 => "CTAP2_ERR_PIN_AUTH_BLOCKED",
        0x35 => "CTAP2_ERR_PIN_NOT_SET",
        0x36 => "CTAP2_ERR_PUAT_REQUIRED",
        0x37 => "CTAP2_ERR_PIN_POLICY_VIOLATION",
        _ => "unknown",
    }
}

pub(crate) fn split_status(response: &[u8]) -> Result<&[u8]> {
    let status = *response
        .first()
        .ok_or_else(|| WscdError::Crypto("empty CTAP2 response".into()))?;
    if status != 0x00 {
        return Err(WscdError::Crypto(format!(
            "CTAP2 error 0x{status:02x} ({})",
            ctap2_status_name(status)
        )));
    }
    Ok(&response[1..])
}

/// Parse `authData`'s `attestedCredentialData`
/// (`aaguid(16) || credIdLen(2) || credId(N) || credPubKey(COSE)`) into
/// the credential ID and the raw COSE_Key bytes (re-encoded rather than
/// hand-sliced, so this is exact regardless of what follows - a trailing
/// extensions map, if the ED flag is also set).
fn parse_attested_credential_data(auth_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Option<i64>)> {
    if auth_data.len() < 37 {
        return Err(WscdError::Crypto(format!(
            "authData too short: {}",
            auth_data.len()
        )));
    }
    let flags = auth_data[32];
    if flags & 0x40 == 0 {
        return Err(WscdError::Crypto(
            "authData does not contain attested credential data".into(),
        ));
    }

    let mut offset = 37 + 16; // header + aaguid
    if auth_data.len() < offset + 2 {
        return Err(WscdError::Crypto(
            "authData truncated before credIdLen".into(),
        ));
    }
    let cred_id_len = ((auth_data[offset] as usize) << 8) | (auth_data[offset + 1] as usize);
    offset += 2;
    if auth_data.len() < offset + cred_id_len {
        return Err(WscdError::Crypto("authData truncated before credId".into()));
    }
    let cred_id = auth_data[offset..offset + cred_id_len].to_vec();
    offset += cred_id_len;

    // The COSE key may be followed by an extensions map (ED flag also
    // set) - decode via a cursor so we consume exactly one CBOR item.
    let mut cursor = &auth_data[offset..];
    let cose_key: Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|e| WscdError::Crypto(format!("invalid COSE key CBOR: {e}")))?;
    let mut cose_bytes = Vec::new();
    ciborium::ser::into_writer(&cose_key, &mut cose_bytes)
        .expect("CBOR encoding is infallible for Value");

    let algorithm = cose_key
        .as_map()
        .and_then(|m| get_value_by_int(m, 3))
        .and_then(|v| v.as_integer())
        .map(i64::try_from)
        .and_then(std::result::Result::ok);

    Ok((cred_id, cose_bytes, algorithm))
}

/// Read the previewSign extension's signed output (`{3: algorithm}`) from
/// `authData`'s own extensions map, present when the ED flag (`0x80`) is
/// set. Returns `None` if absent - callers fall back to the COSE key's
/// own `alg` label.
fn extract_signed_previewsign_algorithm(auth_data: &[u8]) -> Option<i64> {
    if auth_data.len() <= 37 {
        return None;
    }
    let flags = auth_data[32];
    if flags & 0x80 == 0 {
        return None; // ED flag not set - no extensions
    }

    let mut offset = 37;
    if flags & 0x40 != 0 {
        offset += 16; // aaguid
        if auth_data.len() < offset + 2 {
            return None;
        }
        let cred_id_len = ((auth_data[offset] as usize) << 8) | (auth_data[offset + 1] as usize);
        offset += 2 + cred_id_len;
        if auth_data.len() <= offset {
            return None;
        }
        let mut cursor = &auth_data[offset..];
        let before = cursor.len();
        let _: Value = ciborium::de::from_reader(&mut cursor).ok()?;
        offset += before - cursor.len();
    }

    let extensions: Value = ciborium::de::from_reader(&auth_data[offset..]).ok()?;
    let map = extensions.as_map()?;
    let preview_sign_map = get_value_by_text(map, "previewSign")?.as_map()?;
    get_value_by_int(preview_sign_map, 3)
        .and_then(|v| v.as_integer())
        .and_then(|i| i64::try_from(i).ok())
}

/// Parse an `authenticatorMakeCredential` response into the real WebAuthn
/// credential ID plus the previewSign-generated signing key.
///
/// The generated key's own attestation is CTAP2.1's
/// `unsignedExtensionOutputs` mechanism (response key `6`, a map keyed by
/// extension name) - `{6: {"previewSign": {7: <attestation object
/// bytes>}}}` - NOT a flat integer key `7` on the outer response map, per
/// `python-fido2`'s real-hardware hardware test
/// (`tests/device/test_sign_extension_v4.py`,
/// `AttestationResponse.unsigned_extension_outputs`). Falls back to the
/// flat key 7 shape for compatibility with the original (pre-UV,
/// pre-ClientPin) 2026-08-04 hardware capture, in case some
/// configuration still returns it that way.
pub fn parse_make_credential_response(response: &[u8]) -> Result<MakeCredentialResult> {
    let body = split_status(response)?;
    let att_obj: Value = ciborium::de::from_reader(body)
        .map_err(|e| WscdError::Crypto(format!("invalid attestation object CBOR: {e}")))?;
    let att_obj_map = att_obj
        .as_map()
        .ok_or_else(|| WscdError::Crypto("attestation object is not a CBOR map".into()))?;

    let auth_data = get_bytes_by_int(att_obj_map, 2)
        .ok_or_else(|| WscdError::Crypto("missing authData in attestation object".into()))?;
    let (credential_id, _, _) = parse_attested_credential_data(auth_data)?;

    let unsigned_extension_output_att_obj = get_value_by_int(att_obj_map, 6)
        .and_then(|v| v.as_map())
        .and_then(|m| get_value_by_text(m, "previewSign"))
        .and_then(|v| v.as_map())
        .and_then(|m| get_bytes_by_int(m, 7));

    let generated_key_att_obj_bytes = unsigned_extension_output_att_obj
        .or_else(|| get_bytes_by_int(att_obj_map, 7))
        .ok_or_else(|| {
            WscdError::Crypto(
                "no previewSign generateKey result (checked unsignedExtensionOutputs' key 6 \
                 and the legacy flat key 7) - authenticator may not support the previewSign \
                 extension"
                    .into(),
            )
        })?;
    let generated_key_att_obj: Value =
        ciborium::de::from_reader(generated_key_att_obj_bytes.as_slice()).map_err(|e| {
            WscdError::Crypto(format!(
                "invalid generated-key attestation object CBOR: {e}"
            ))
        })?;
    let generated_key_auth_data = get_bytes_by_int(
        generated_key_att_obj.as_map().ok_or_else(|| {
            WscdError::Crypto("generated-key attestation object is not a map".into())
        })?,
        2,
    )
    .ok_or_else(|| {
        WscdError::Crypto("missing authData in generated-key attestation object".into())
    })?;
    let (key_handle, public_key_cose, algorithm_from_cose) =
        parse_attested_credential_data(generated_key_auth_data)?;

    // The generated key's COSE bytes may be either a plain EC2 key or a
    // composite ARKG-pub seed (kty=-65537) - only the caller
    // (plugins/preview_sign.rs's generate_key) knows how to tell those
    // apart and decode each correctly, so no shape validation happens here.

    let algorithm = extract_signed_previewsign_algorithm(auth_data)
        .or(algorithm_from_cose)
        .unwrap_or(-7);

    Ok(MakeCredentialResult {
        credential_id,
        generated_key: GeneratedKey {
            key_handle,
            public_key_cose,
            algorithm,
            attestation_object: generated_key_att_obj_bytes.clone(),
        },
    })
}

/// Parse an `authenticatorGetAssertion` response's signature out of the
/// previewSign extension output, via [`extract_previewsign_signature`].
pub fn parse_get_assertion_response(response: &[u8]) -> Result<SignResult> {
    let body = split_status(response)?;
    let assert_obj: Value = ciborium::de::from_reader(body)
        .map_err(|e| WscdError::Crypto(format!("invalid assertion response CBOR: {e}")))?;
    let auth_data = get_bytes_by_int(
        assert_obj
            .as_map()
            .ok_or_else(|| WscdError::Crypto("assertion response is not a map".into()))?,
        2,
    )
    .ok_or_else(|| WscdError::Crypto("missing authData in assertion response".into()))?;
    Ok(SignResult {
        signature: extract_previewsign_signature(auth_data)?,
    })
}

/// Perform a full `generateKey` ceremony over the given transport: obtain
/// a `pinUvAuthToken` from the user's PIN (via `auth.request_pin()`),
/// build the request, send it, and parse the result. This is the ONLY
/// place that needs to know both the wire shapes AND how to invoke a
/// transport - individual transports (USB/NFC/BLE) only ever see the raw
/// bytes of [`crate::callbacks::Ctap2Transport::ctap2_send_command`].
///
/// A real `pinUvAuthParam` (not just the `previewSign` extension's own
/// UV-request flag) is required - confirmed against real YubiKey 5.8
/// hardware: without it, a UV-enforcing authenticator creates the base
/// credential but silently omits the extension's generateKey result.
pub async fn make_credential(
    transport: &dyn crate::callbacks::Ctap2Transport,
    auth: &dyn crate::callbacks::AuthCallback,
    rp_id: &str,
    user_id: &[u8],
    client_data_hash: &[u8],
    generate_key: &GenerateKeyInput,
) -> Result<MakeCredentialResult> {
    let pin = auth.request_pin("fido2").await?;
    let pin_uv_auth = crate::ctap2_client_pin::get_pin_uv_auth_token(
        transport,
        &pin,
        crate::ctap2_client_pin::PERMISSION_MAKE_CREDENTIAL,
        Some(rp_id),
    )
    .await?;
    let pin_uv_auth_param = pin_uv_auth.authenticate(client_data_hash);
    let command = build_make_credential_request(
        rp_id,
        user_id,
        client_data_hash,
        generate_key,
        Some((&pin_uv_auth_param, pin_uv_auth.protocol_int())),
    );
    let response = transport.ctap2_send_command(&command).await?;
    parse_make_credential_response(&response)
}

/// Perform a full `signByCredential` ceremony over the given transport.
/// Like [`make_credential`], obtains a real `pinUvAuthToken` scoped to
/// `getAssertion` rather than relying on the extension's own UV flag.
pub async fn get_assertion(
    transport: &dyn crate::callbacks::Ctap2Transport,
    auth: &dyn crate::callbacks::AuthCallback,
    rp_id: &str,
    challenge: &[u8],
    credential_id: &[u8],
    sign: &SignInput,
) -> Result<SignResult> {
    let pin = auth.request_pin("fido2").await?;
    let pin_uv_auth = crate::ctap2_client_pin::get_pin_uv_auth_token(
        transport,
        &pin,
        crate::ctap2_client_pin::PERMISSION_GET_ASSERTION,
        Some(rp_id),
    )
    .await?;
    let pin_uv_auth_param = pin_uv_auth.authenticate(challenge);
    let command = build_get_assertion_request(
        rp_id,
        challenge,
        credential_id,
        sign,
        Some((&pin_uv_auth_param, pin_uv_auth.protocol_int())),
    );
    let response = transport.ctap2_send_command(&command).await?;
    parse_get_assertion_response(&response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cose_ec2_key(x: &[u8], y: &[u8]) -> Vec<u8> {
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

    #[test]
    fn decodes_ec2_public_key() {
        let x = vec![1u8; 32];
        let y = vec![2u8; 32];
        let bytes = cose_ec2_key(&x, &y);
        let (dx, dy) = decode_cose_ec2_public_key(&bytes).unwrap();
        assert_eq!(dx, x);
        assert_eq!(dy, y);
    }

    #[test]
    fn rejects_key_missing_coordinates() {
        let value = Value::Map(vec![(Value::Integer(1.into()), Value::Integer(2.into()))]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&value, &mut buf).unwrap();
        assert!(decode_cose_ec2_public_key(&buf).is_err());
    }

    #[test]
    fn rejects_empty_coordinate() {
        let bytes = cose_ec2_key(&[], &[2u8; 32]);
        assert!(decode_cose_ec2_public_key(&bytes).is_err());
    }

    #[test]
    fn rejects_mismatched_coordinate_lengths() {
        let bytes = cose_ec2_key(&[1u8; 32], &[2u8; 16]);
        assert!(decode_cose_ec2_public_key(&bytes).is_err());
    }

    fn authenticator_data_with_signature(sig: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 32]; // rpIdHash
        buf.push(0x80); // flags: ED set, AT clear
        buf.extend_from_slice(&[0, 0, 0, 1]); // signCount

        let extensions = Value::Map(vec![(
            Value::Text("previewSign".into()),
            Value::Map(vec![(Value::Integer(6.into()), Value::Bytes(sig.to_vec()))]),
        )]);
        ciborium::ser::into_writer(&extensions, &mut buf).unwrap();
        buf
    }

    #[test]
    fn extracts_signature_from_authenticator_data() {
        let sig = vec![9u8; 64];
        let auth_data = authenticator_data_with_signature(&sig);
        let extracted = extract_previewsign_signature(&auth_data).unwrap();
        assert_eq!(extracted, sig);
    }

    #[test]
    fn rejects_authenticator_data_without_ed_flag() {
        let mut buf = vec![0u8; 32];
        buf.push(0x00); // no ED flag
        buf.extend_from_slice(&[0, 0, 0, 1]);
        assert!(extract_previewsign_signature(&buf).is_err());
    }

    #[test]
    fn rejects_authenticator_data_with_at_flag_set() {
        let mut buf = vec![0u8; 32]; // rpIdHash
        buf.push(0x80 | 0x40); // flags: ED set AND AT set (unexpected in an assertion)
        buf.extend_from_slice(&[0, 0, 0, 1]); // signCount

        let extensions = Value::Map(vec![(
            Value::Text("previewSign".into()),
            Value::Map(vec![(
                Value::Integer(6.into()),
                Value::Bytes(vec![9u8; 64]),
            )]),
        )]);
        ciborium::ser::into_writer(&extensions, &mut buf).unwrap();

        assert!(extract_previewsign_signature(&buf).is_err());
    }

    #[test]
    fn der_signature_to_raw_matches_a_real_yubikey_response() {
        // Captured verbatim from a real signByCredential response's
        // previewSign extension output (2026-08-10) - an unambiguous DER
        // SEQUENCE{INTEGER r, INTEGER s}. go-wallet-backend's crypto/ecdsa
        // JWS verifier rejected this un-converted, confirming raw r||s is
        // required.
        let der = hex_decode(
            "304502205beb9ada92bb062a5980339f7984d1036c45201758414546c52b213f2d811bb8\
             022100ef598e4f6d3d99a42c6a798a6ff8686ee4d50230cdfdca9ced56cdaf287cb8e5",
        );
        let raw = der_signature_to_raw(&der).unwrap();

        assert_eq!(
            raw.len(),
            64,
            "P-256 raw signature must be exactly 64 bytes"
        );
        let expected_r =
            hex_decode("5beb9ada92bb062a5980339f7984d1036c45201758414546c52b213f2d811bb8");
        let expected_s =
            hex_decode("ef598e4f6d3d99a42c6a798a6ff8686ee4d50230cdfdca9ced56cdaf287cb8e5");
        assert_eq!(&raw[..32], expected_r.as_slice());
        assert_eq!(&raw[32..], expected_s.as_slice());
    }

    #[test]
    fn der_signature_to_raw_rejects_garbage() {
        assert!(der_signature_to_raw(&[0x01, 0x02, 0x03]).is_err());
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Golden byte test: this exact hex is the `previewSign` extension
    /// value captured from a REAL, working `python-fido2` request sent
    /// over USB CTAP2 HID to a physical YubiKey 5.8 EAP unit
    /// (2026-08-04), decoding to `{"previewSign": {3: [-65539], 4: 1}}`.
    /// Locks in the confirmed wire shape so a future refactor can't
    /// silently regress it back to the wrong nested string-keyed shape.
    #[test]
    fn generate_key_extension_matches_real_hardware_capture() {
        let expected = hex_decode("a16b707265766965775369676ea203813a000100020401");
        let mut actual = Vec::new();
        ciborium::ser::into_writer(
            &build_generate_key_extension(&[ARKG_P256_ESP256], false),
            &mut actual,
        )
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn generate_key_extension_sets_uv_flag_when_required() {
        let value = build_generate_key_extension(&[ARKG_P256_ESP256], true);
        let map = value.as_map().unwrap();
        let preview_sign = get_value_by_text(map, "previewSign")
            .unwrap()
            .as_map()
            .unwrap();
        let flags = get_value_by_int(preview_sign, 4)
            .unwrap()
            .as_integer()
            .unwrap();
        assert_eq!(i64::try_from(flags).unwrap(), 0b101);
    }

    #[test]
    fn make_credential_request_uses_arkg_algorithm_and_standard_pub_key_cred_params() {
        let request = build_make_credential_request(
            "example.com",
            b"user-id",
            &[0x11u8; 32],
            &GenerateKeyInput {
                algorithms: vec![ARKG_P256_ESP256],
            },
            None,
        );
        assert_eq!(request[0], CTAP2_MAKE_CREDENTIAL);
        let params: Value = ciborium::de::from_reader(&request[1..]).unwrap();
        let map = params.as_map().unwrap();

        // pubKeyCredParams (key 4) is the standard algorithm list, NOT
        // just the ARKG algorithm - a real, previously-conflated bug.
        let pub_key_cred_params = get_value_by_int(map, 4).unwrap().as_array().unwrap();
        assert_eq!(pub_key_cred_params.len(), DEFAULT_PUB_KEY_CRED_ALGS.len());

        // previewSign extension's OWN algorithms (key 6 -> previewSign -> 3)
        // is the ARKG algorithm alone.
        let extensions = get_value_by_int(map, 6).unwrap().as_map().unwrap();
        let preview_sign = get_value_by_text(extensions, "previewSign")
            .unwrap()
            .as_map()
            .unwrap();
        let algorithms = get_value_by_int(preview_sign, 3)
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(algorithms.len(), 1);
        assert_eq!(
            i64::try_from(algorithms[0].as_integer().unwrap()).unwrap(),
            ARKG_P256_ESP256
        );
    }

    #[test]
    fn get_assertion_request_uses_getassertion_param_numbers_not_makecredentials() {
        // Real-hardware regression test: this function previously reused
        // authenticatorMakeCredential's key numbers (extensions=6,
        // pinUvAuthParam=8, pinUvAuthProtocol=9) instead of
        // authenticatorGetAssertion's own layout (CTAP2.1 §6.2:
        // extensions=4, pinUvAuthParam=6, pinUvAuthProtocol=7) - a real
        // YubiKey correctly rejected the wrong numbering with CTAP2 error
        // 0x02 (invalid parameter), failing every sign attempt even though
        // key generation (MakeCredential) worked fine.
        let sign = SignInput {
            key_handle: vec![0xAA; 34],
            tbs: vec![0xBB; 32],
            additional_args: None,
        };
        let request = build_get_assertion_request(
            "example.com",
            &[0x22u8; 32],
            &[0x33u8; 16],
            &sign,
            Some((&[0x44u8; 32], 2)),
        );
        assert_eq!(request[0], CTAP2_GET_ASSERTION);
        let params: Value = ciborium::de::from_reader(&request[1..]).unwrap();
        let map = params.as_map().unwrap();

        let extensions = get_value_by_int(map, 4)
            .expect("extensions must be at key 4 for GetAssertion")
            .as_map()
            .unwrap();
        let preview_sign = get_value_by_text(extensions, "previewSign")
            .unwrap()
            .as_map()
            .unwrap();
        assert_eq!(
            get_value_by_int(preview_sign, 2)
                .unwrap()
                .as_bytes()
                .unwrap(),
            &sign.key_handle,
        );

        let pin_uv_auth_param = get_value_by_int(map, 6)
            .expect("pinUvAuthParam must be at key 6 for GetAssertion")
            .as_bytes()
            .unwrap();
        assert_eq!(pin_uv_auth_param, &[0x44u8; 32]);
        let pin_uv_auth_protocol = get_value_by_int(map, 7)
            .expect("pinUvAuthProtocol must be at key 7 for GetAssertion")
            .as_integer()
            .unwrap();
        assert_eq!(i64::try_from(pin_uv_auth_protocol).unwrap(), 2);

        // Round-trips through the reverse parser too.
        let parsed = parse_get_assertion_request(&request).unwrap();
        assert_eq!(parsed.sign.key_handle, sign.key_handle);
        assert_eq!(parsed.sign.tbs, sign.tbs);
    }

    fn synthetic_attested_auth_data(
        cred_id: &[u8],
        cose_key: &[u8],
        signed_extensions: Option<Value>,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 32]; // rpIdHash
        let mut flags = 0x40u8; // AT
        if signed_extensions.is_some() {
            flags |= 0x80; // ED
        }
        buf.push(flags);
        buf.extend_from_slice(&[0, 0, 0, 1]); // signCount
        buf.extend_from_slice(&[0u8; 16]); // aaguid
        let len = cred_id.len() as u16;
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
        buf.extend_from_slice(cred_id);
        buf.extend_from_slice(cose_key);
        if let Some(ext) = signed_extensions {
            ciborium::ser::into_writer(&ext, &mut buf).unwrap();
        }
        buf
    }

    #[test]
    fn parse_make_credential_response_roundtrip_legacy_flat_key7() {
        let cose_key = cose_ec2_key(&[1u8; 32], &[2u8; 32]);
        let generated_auth_data = synthetic_attested_auth_data(b"key-handle-1", &cose_key, None);
        let inner_att_obj = Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("none".into())),
            (Value::Integer(2.into()), Value::Bytes(generated_auth_data)),
            (Value::Integer(3.into()), Value::Map(vec![])),
        ]);
        let mut inner_bytes = Vec::new();
        ciborium::ser::into_writer(&inner_att_obj, &mut inner_bytes).unwrap();

        let signed_extensions = Value::Map(vec![(
            Value::Text("previewSign".into()),
            Value::Map(vec![(int_key(3), int_key(ARKG_P256_ESP256))]),
        )]);
        let outer_auth_data =
            synthetic_attested_auth_data(b"credential-id-1", &cose_key, Some(signed_extensions));
        let outer_att_obj = Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("none".into())),
            (Value::Integer(2.into()), Value::Bytes(outer_auth_data)),
            (Value::Integer(3.into()), Value::Map(vec![])),
            (Value::Integer(7.into()), Value::Bytes(inner_bytes)),
        ]);

        let mut response = vec![0x00u8];
        ciborium::ser::into_writer(&outer_att_obj, &mut response).unwrap();

        let result = parse_make_credential_response(&response).unwrap();
        assert_eq!(result.credential_id, b"credential-id-1");
        assert_eq!(result.generated_key.key_handle, b"key-handle-1");
        assert_eq!(result.generated_key.algorithm, ARKG_P256_ESP256);
    }

    /// The real, CTAP2.1-spec-correct shape: the generateKey attestation
    /// object lives inside `unsignedExtensionOutputs` (response key 6, a
    /// map keyed by extension name), not a flat key 7 on the outer
    /// response map - confirmed via `python-fido2`'s real-hardware test
    /// `tests/device/test_sign_extension_v4.py`
    /// (`AttestationResponse.unsigned_extension_outputs`).
    #[test]
    fn parse_make_credential_response_roundtrip_unsigned_extension_outputs() {
        let cose_key = cose_ec2_key(&[1u8; 32], &[2u8; 32]);
        let generated_auth_data = synthetic_attested_auth_data(b"key-handle-2", &cose_key, None);
        let inner_att_obj = Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("none".into())),
            (Value::Integer(2.into()), Value::Bytes(generated_auth_data)),
            (Value::Integer(3.into()), Value::Map(vec![])),
        ]);
        let mut inner_bytes = Vec::new();
        ciborium::ser::into_writer(&inner_att_obj, &mut inner_bytes).unwrap();

        let signed_extensions = Value::Map(vec![(
            Value::Text("previewSign".into()),
            Value::Map(vec![(int_key(3), int_key(ARKG_P256_ESP256))]),
        )]);
        let outer_auth_data =
            synthetic_attested_auth_data(b"credential-id-2", &cose_key, Some(signed_extensions));
        let unsigned_extension_outputs = Value::Map(vec![(
            Value::Text("previewSign".into()),
            Value::Map(vec![(Value::Integer(7.into()), Value::Bytes(inner_bytes))]),
        )]);
        let outer_att_obj = Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("none".into())),
            (Value::Integer(2.into()), Value::Bytes(outer_auth_data)),
            (Value::Integer(3.into()), Value::Map(vec![])),
            (Value::Integer(6.into()), unsigned_extension_outputs),
        ]);

        let mut response = vec![0x00u8];
        ciborium::ser::into_writer(&outer_att_obj, &mut response).unwrap();

        let result = parse_make_credential_response(&response).unwrap();
        assert_eq!(result.credential_id, b"credential-id-2");
        assert_eq!(result.generated_key.key_handle, b"key-handle-2");
        assert_eq!(result.generated_key.algorithm, ARKG_P256_ESP256);
    }

    #[test]
    fn parse_make_credential_response_rejects_nonzero_status() {
        let response = [0x34u8]; // CTAP2_ERR_PIN_AUTH_BLOCKED
        assert!(parse_make_credential_response(&response).is_err());
    }

    #[test]
    fn parse_get_assertion_response_roundtrip() {
        let signed_extensions = Value::Map(vec![(
            Value::Text("previewSign".into()),
            Value::Map(vec![(int_key(6), Value::Bytes(vec![9u8; 64]))]),
        )]);
        let mut auth_data = vec![0u8; 32];
        auth_data.push(0x80); // ED only
        auth_data.extend_from_slice(&[0, 0, 0, 1]);
        ciborium::ser::into_writer(&signed_extensions, &mut auth_data).unwrap();

        let assert_obj = Value::Map(vec![(int_key(2), Value::Bytes(auth_data))]);
        let mut response = vec![0x00u8];
        ciborium::ser::into_writer(&assert_obj, &mut response).unwrap();

        let result = parse_get_assertion_response(&response).unwrap();
        assert_eq!(result.signature, vec![9u8; 64]);
    }
}

#[cfg(test)]
mod bls_keybind_tests {
    use super::*;

    fn cose_key(crv: i64, point: Vec<u8>) -> Vec<u8> {
        let value = Value::Map(vec![
            (int_key(1), int_key(2)),
            (int_key(3), int_key(ECSDSA_BLS12381_BP1_SHA256_SEC1)),
            (int_key(-1), int_key(crv)),
            (Value::Integer((-2).into()), Value::Bytes(point)),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&value, &mut buf).unwrap();
        buf
    }

    #[test]
    fn decodes_a_g1_public_key() {
        let point = vec![0xa1u8; BLS12381_G1_COMPRESSED_LEN];
        let decoded = decode_cose_bls12381_g1_public_key(&cose_key(13, point.clone())).unwrap();
        assert_eq!(decoded, point);
    }

    /// python-fido2's own verifier accepts either the real curve id or the
    /// prototype placeholder, so this must too.
    #[test]
    fn accepts_the_placeholder_curve_id() {
        let point = vec![0xa1u8; BLS12381_G1_COMPRESSED_LEN];
        assert!(decode_cose_bls12381_g1_public_key(&cose_key(-65601, point)).is_ok());
    }

    #[test]
    fn rejects_a_different_curve() {
        // crv 1 is P-256: a key on the wrong curve must not be accepted as
        // a key binding key.
        let point = vec![0xa1u8; BLS12381_G1_COMPRESSED_LEN];
        assert!(decode_cose_bls12381_g1_public_key(&cose_key(1, point)).is_err());
    }

    #[test]
    fn rejects_a_wrong_length_point() {
        for len in [0, 32, 47, 49, 96] {
            assert!(
                decode_cose_bls12381_g1_public_key(&cose_key(13, vec![0u8; len])).is_err(),
                "{len}-octet point was accepted"
            );
        }
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(decode_cose_bls12381_g1_public_key(&[]).is_err());
        assert!(decode_cose_bls12381_g1_public_key(&[0x01, 0x02, 0x03]).is_err());
    }

    #[test]
    fn signature_must_be_two_raw_scalars() {
        let sig = vec![0x5au8; BLS12381_SCHNORR_SIGNATURE_LEN];
        assert_eq!(validate_bls12381_schnorr_signature(&sig).unwrap(), sig);
        for len in [0, 63, 65, 71] {
            assert!(
                validate_bls12381_schnorr_signature(&vec![0u8; len][..]).is_err(),
                "{len}-octet signature was accepted"
            );
        }
    }

    /// A DER-encoded ECDSA signature must not pass as a Schnorr one. Real
    /// DER signatures are typically 70-72 octets, but a short one can land
    /// on 64 - the length check alone would accept it, which is worth
    /// knowing rather than assuming otherwise.
    #[test]
    fn der_and_raw_are_not_interchangeable() {
        let der = [
            0x30, 0x44, 0x02, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        assert!(validate_bls12381_schnorr_signature(&der).is_err());
        assert!(der_signature_to_raw(&[0x5au8; 64]).is_err());
    }
}
