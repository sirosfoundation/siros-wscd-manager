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
//! [`extract_previewsign_signature`]) is CONFIRMED against real hardware
//! (a YubiKey 5.8 Early Access unit, 2026-08-04) - both the raw CTAP2 wire
//! shape and a full generateKey→derive→sign→verify ceremony, cross-checked
//! against Yubico's own `python-fido2` library
//! (`fido2/ctap2/extensions.py`'s `PreviewSignExtension`). The raw wire
//! shape uses flat INTEGER CBOR keys - NOT the nested string-keyed
//! `{"generateKey": {"algorithms": [...]}}` shape the browser/WebAuthn JS
//! API exposes (that shape is client-side only; a real browser's own
//! WebAuthn client translates it to this before it ever reaches the
//! authenticator).

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
    let params = Value::Map(vec![
        (int_key(1), Value::Bytes(client_data_hash.to_vec())),
        (int_key(2), rp),
        (int_key(3), user),
        (int_key(4), pub_key_cred_params),
        (
            int_key(6),
            build_generate_key_extension(&generate_key.algorithms, false),
        ),
    ]);
    encode_command(CTAP2_MAKE_CREDENTIAL, &params)
}

/// Build a full `authenticatorGetAssertion` (0x02) command.
pub fn build_get_assertion_request(
    rp_id: &str,
    challenge: &[u8],
    credential_id: &[u8],
    sign: &SignInput,
) -> Vec<u8> {
    let allow_list = Value::Array(vec![Value::Map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("id".into()),
            Value::Bytes(credential_id.to_vec()),
        ),
    ])]);
    let params = Value::Map(vec![
        (int_key(1), Value::Text(rp_id.into())),
        (int_key(2), Value::Bytes(challenge.to_vec())),
        (int_key(3), allow_list),
        (int_key(6), build_sign_by_credential_extension(sign)),
    ]);
    encode_command(CTAP2_GET_ASSERTION, &params)
}

fn encode_command(command: u8, params: &Value) -> Vec<u8> {
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

    let extensions = get_value_by_int(map, 6)
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

fn ctap2_status_name(status: u8) -> &'static str {
    match status {
        0x11 => "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
        0x12 => "CTAP2_ERR_INVALID_CBOR",
        0x14 => "CTAP2_ERR_MISSING_PARAMETER",
        0x19 => "CTAP2_ERR_UNSUPPORTED_EXTENSION",
        0x26 => "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
        0x30 => "CTAP2_ERR_NOT_ALLOWED",
        0x31 => "CTAP2_ERR_PIN_INVALID",
        0x33 => "CTAP2_ERR_PIN_AUTH_INVALID",
        0x34 => "CTAP2_ERR_PIN_AUTH_BLOCKED",
        _ => "unknown",
    }
}

fn split_status(response: &[u8]) -> Result<&[u8]> {
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
/// credential ID plus the previewSign-generated signing key. The
/// generated key's own attestation surfaces at unsigned extension output
/// key `7` (a nested attestation object) - confirmed via real hardware
/// and `python-fido2`'s `PreviewSignExtension.make_credential`.
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

    let generated_key_att_obj_bytes = get_bytes_by_int(att_obj_map, 7).ok_or_else(|| {
        WscdError::Crypto(
            "no previewSign generateKey result (response key 7 missing) - authenticator may \
             not support the previewSign extension"
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

    // Sanity-check the generated key's COSE bytes are well-formed EC2
    // before returning them - fail loudly and early rather than surface
    // an obscure error deep in a caller.
    decode_cose_ec2_public_key(&public_key_cose)?;

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

/// Perform a full `generateKey` ceremony over the given transport: build
/// the request, send it, and parse the result. This is the ONLY place
/// that needs to know both the wire shapes AND how to invoke a transport
/// - individual transports (USB/NFC/BLE) only ever see the raw bytes of
///   [`crate::callbacks::Ctap2Transport::ctap2_send_command`].
pub async fn make_credential(
    transport: &dyn crate::callbacks::Ctap2Transport,
    rp_id: &str,
    user_id: &[u8],
    client_data_hash: &[u8],
    generate_key: &GenerateKeyInput,
) -> Result<MakeCredentialResult> {
    let command = build_make_credential_request(rp_id, user_id, client_data_hash, generate_key);
    let response = transport.ctap2_send_command(&command).await?;
    parse_make_credential_response(&response)
}

/// Perform a full `signByCredential` ceremony over the given transport.
pub async fn get_assertion(
    transport: &dyn crate::callbacks::Ctap2Transport,
    rp_id: &str,
    challenge: &[u8],
    credential_id: &[u8],
    sign: &SignInput,
) -> Result<SignResult> {
    let command = build_get_assertion_request(rp_id, challenge, credential_id, sign);
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
    fn parse_make_credential_response_roundtrip() {
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
