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
//! Independently implemented from the published spec and from field names
//! observed in a real browser integration (wallet-frontend PR #22); no code
//! is copied from Yubico's `yubikit` reference client.

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
}
