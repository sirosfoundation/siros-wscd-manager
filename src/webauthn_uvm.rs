//! WebAuthn Level 2's "uvm" (user verification method) extension (§10.4),
//! shared by the two places this manager talks to a transport that
//! performs user verification itself rather than through this crate's own
//! `AuthCallback::request_pin`: the browser previewSign transport
//! ([`crate::wasm_fido2`]) and R2PS's WebAuthn auth mode
//! ([`crate::plugins::r2ps`]).
//!
//! # Why `uvm`, and what it does and does not prove (see issue #105)
//!
//! `uvm` is an AUTHENTICATOR extension, not a client extension: its output
//! (an array of up to 3 `[userVerificationMethod, keyProtectionType,
//! matcherProtectionType]` triples) is produced by the authenticator and
//! placed inside `authenticatorData`'s own extensions block - the same
//! bytes that are signed (for an assertion, the authenticator's signature
//! covers `authenticatorData || clientDataHash`). That is unlike a pure
//! client extension, whose output the browser alone vouches for via
//! `getClientExtensionResults()` with no authenticator involvement.
//!
//! This module parses `uvm` directly out of the raw `authenticatorData`
//! bytes - never from `getClientExtensionResults()` - for exactly that
//! reason: it keeps `uvm` at the same trust tier as the UV flag this crate
//! already relies on (`AUTH_DATA_FLAG_UV` in
//! `crate::preview_sign_protocol`, and `authenticator_data_uv_flag` in
//! `crate::plugins::r2ps`), which is also read directly from the same raw
//! bytes and never independently signature-verified by this crate. Neither
//! this module nor the existing UV-flag check re-verifies the assertion
//! signature against the credential's public key - that is a pre-existing
//! limit of both transports (see `wasm_fido2`'s module doc), not one this
//! module introduces or widens.
//!
//! **What `uvm` closes:** which TS12 category/method applied (issue #105's
//! "method unknown" half) - a real, authenticator-asserted answer instead
//! of an unverifiable claim the host makes up out of band
//! (`SignOptions::host_verified_factor`).
//!
//! **What `uvm` does NOT close:** freshness (issue #105's other half). CTAP2
//! lets a platform reuse a previously-obtained `pinUvAuthToken` for more
//! than one `authenticatorGetAssertion` within that token's permitted
//! lifetime/usage policy - an authenticator can legitimately report
//! `uv=1` and a valid `uvm` entry for a ceremony where the user did not
//! re-enter anything just now. `uvm` reports WHICH method verified the
//! user the last time it happened to run, never WHEN. This is exactly the
//! reasoning the `require_fresh_user_authentication` refusal in
//! `crate::plugins::preview_sign` and `crate::plugins::r2ps` already
//! documents (see their git history, commit "Refuse fresh-auth where
//! freshness cannot be guaranteed") - `uvm` does not change it, and this
//! module's classification is deliberately never consulted by that
//! refusal path.

use crate::factors::{AuthFactor, FactorCategory};

/// Authenticator-data flag: extension data present (bit 7).
const AUTH_DATA_FLAG_ED: u8 = 0x80;
/// Authenticator-data flag: attested credential data present (bit 6).
const AUTH_DATA_FLAG_AT: u8 = 0x40;
/// `rpIdHash(32) || flags(1) || signCount(4)`.
const AUTH_DATA_HEADER_LEN: usize = 32 + 1 + 4;

// FIDO Registry v2 "User Verification Methods" bit flags. Only the subset
// TS12's vocabulary can express is named; the rest (location, voice, hand,
// eye, pattern/passcode-EXTERNAL, NONE, ALL, ...) are deliberately left
// unnamed - [`classify_uvm_for_ts12`] maps them to `None`, never a guess.
const USER_VERIFY_FINGERPRINT_INTERNAL: u32 = 0x0000_0002;
const USER_VERIFY_PASSCODE_INTERNAL: u32 = 0x0000_0004;
const USER_VERIFY_FACEPRINT_INTERNAL: u32 = 0x0000_0010;
const USER_VERIFY_PATTERN_INTERNAL: u32 = 0x0000_0080;

/// One `uvm` entry: `[userVerificationMethod, keyProtectionType, matcherProtectionType]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UvmEntry {
    pub user_verification_method: u32,
    pub key_protection_type: u16,
    pub matcher_protection_type: u16,
}

/// Parse the `uvm` authenticator-extension output directly out of raw
/// `getAssertion` `authenticatorData` bytes.
///
/// Returns `None` - never an error - whenever `uvm` simply is not there:
/// no extensions block (ED flag clear), an assertion that unexpectedly
/// carries attested credential data (AT flag set - this function only
/// understands the assertion layout, where extensions start right at byte
/// 37), malformed CBOR, no `uvm` key, or an empty entry list. An
/// authenticator/browser that does not support `uvm` must look exactly
/// like one that was never asked, so callers fall back to today's
/// behaviour rather than erroring.
pub fn parse_uvm_extension(authenticator_data: &[u8]) -> Option<Vec<UvmEntry>> {
    let flags = *authenticator_data.get(32)?;
    if flags & AUTH_DATA_FLAG_ED == 0 || flags & AUTH_DATA_FLAG_AT != 0 {
        return None;
    }
    let ext_bytes = authenticator_data.get(AUTH_DATA_HEADER_LEN..)?;
    let value: ciborium::Value = ciborium::de::from_reader(ext_bytes).ok()?;
    let map = value.as_map()?;
    let uvm_value = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("uvm"))
        .map(|(_, v)| v)?;
    let entries_cbor = uvm_value.as_array()?;

    let as_u32 = |v: &ciborium::Value| -> Option<u32> {
        v.as_integer()
            .map(i128::from)
            .and_then(|n| u32::try_from(n).ok())
    };
    let as_u16 = |v: &ciborium::Value| -> Option<u16> {
        v.as_integer()
            .map(i128::from)
            .and_then(|n| u16::try_from(n).ok())
    };

    let mut entries = Vec::with_capacity(entries_cbor.len());
    for entry in entries_cbor {
        let triple = entry.as_array()?;
        if triple.len() != 3 {
            return None;
        }
        entries.push(UvmEntry {
            user_verification_method: as_u32(&triple[0])?,
            key_protection_type: as_u16(&triple[1])?,
            matcher_protection_type: as_u16(&triple[2])?,
        });
    }
    if entries.is_empty() {
        return None;
    }
    Some(entries)
}

/// Map `uvm` output to a TS12 factor - `None` whenever the mapping would be
/// a guess rather than a fact:
///
/// - more than one entry (the authenticator combined several methods for
///   this assertion; which one actually gated THIS signature is not
///   knowable, so none is reported rather than picking one arbitrarily);
/// - a method bit this TS12 vocabulary has no entry for;
/// - `USER_VERIFY_PRESENCE_INTERNAL` alone (a touch/tap, not a
///   verification - never a TS12 factor on its own).
///
/// A passcode/PIN typed into an authenticator's OWN input (not asked
/// through this crate's `AuthCallback::request_pin`, so its length is never
/// seen here - see module doc) can only be classified as Knowledge
/// `"other"`, the vocabulary's catch-all for a known category whose
/// specific class cannot be measured; a biometric on the authenticator maps
/// to the `_external` methods (the authenticator is external to the
/// wallet's own device - confirmed against `security/payment-sca-ts12.md`
/// §3.3, which reserves the `_device` methods for the wallet device's OWN
/// native biometric sensor, e.g. Android/iOS platform keystore).
pub fn classify_uvm_for_ts12(entries: &[UvmEntry]) -> Option<AuthFactor> {
    let entry = match entries {
        [entry] => entry,
        _ => return None,
    };
    let (category, method) = match entry.user_verification_method {
        USER_VERIFY_FINGERPRINT_INTERNAL => (FactorCategory::Inherence, "fingerprint_external"),
        USER_VERIFY_FACEPRINT_INTERNAL => (FactorCategory::Inherence, "face_external"),
        USER_VERIFY_PATTERN_INTERNAL => (FactorCategory::Knowledge, "pattern"),
        USER_VERIFY_PASSCODE_INTERNAL => (FactorCategory::Knowledge, "other"),
        _ => return None,
    };
    AuthFactor::new(category, method).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_data_with_extensions(
        ed: bool,
        at: bool,
        extensions: Option<ciborium::Value>,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 32]; // rpIdHash
        let mut flags = 0u8;
        if ed {
            flags |= AUTH_DATA_FLAG_ED;
        }
        if at {
            flags |= AUTH_DATA_FLAG_AT;
        }
        buf.push(flags);
        buf.extend_from_slice(&[0, 0, 0, 1]); // signCount
        if let Some(ext) = extensions {
            ciborium::ser::into_writer(&ext, &mut buf).unwrap();
        }
        buf
    }

    fn uvm_extensions(entries: &[(u32, u16, u16)]) -> ciborium::Value {
        let array = entries
            .iter()
            .map(|(m, k, mt)| {
                ciborium::Value::Array(vec![
                    ciborium::Value::Integer((*m).into()),
                    ciborium::Value::Integer((*k).into()),
                    ciborium::Value::Integer((*mt).into()),
                ])
            })
            .collect();
        ciborium::Value::Map(vec![(
            ciborium::Value::Text("uvm".into()),
            ciborium::Value::Array(array),
        )])
    }

    #[test]
    fn parses_a_single_uvm_entry() {
        let auth_data =
            auth_data_with_extensions(true, false, Some(uvm_extensions(&[(0x04, 1, 1)])));
        let entries = parse_uvm_extension(&auth_data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].user_verification_method, 0x04);
    }

    #[test]
    fn no_extensions_block_is_none_not_an_error() {
        let auth_data = auth_data_with_extensions(false, false, None);
        assert!(parse_uvm_extension(&auth_data).is_none());
    }

    #[test]
    fn an_assertion_with_at_flag_set_is_refused_not_misparsed() {
        // Assertions never carry attested credential data; if AT is set the
        // fixed byte-37 offset for extensions would be wrong.
        let auth_data =
            auth_data_with_extensions(true, true, Some(uvm_extensions(&[(0x04, 1, 1)])));
        assert!(parse_uvm_extension(&auth_data).is_none());
    }

    #[test]
    fn extensions_without_uvm_is_none() {
        let other = ciborium::Value::Map(vec![(
            ciborium::Value::Text("previewSign".into()),
            ciborium::Value::Map(vec![]),
        )]);
        let auth_data = auth_data_with_extensions(true, false, Some(other));
        assert!(parse_uvm_extension(&auth_data).is_none());
    }

    #[test]
    fn classifies_fingerprint_and_passcode() {
        let fp = classify_uvm_for_ts12(&[UvmEntry {
            user_verification_method: USER_VERIFY_FINGERPRINT_INTERNAL,
            key_protection_type: 1,
            matcher_protection_type: 1,
        }])
        .unwrap();
        assert_eq!(fp.category(), FactorCategory::Inherence);
        assert_eq!(fp.method(), "fingerprint_external");

        let pin = classify_uvm_for_ts12(&[UvmEntry {
            user_verification_method: USER_VERIFY_PASSCODE_INTERNAL,
            key_protection_type: 1,
            matcher_protection_type: 1,
        }])
        .unwrap();
        assert_eq!(pin.category(), FactorCategory::Knowledge);
        assert_eq!(pin.method(), "other");
    }

    #[test]
    fn presence_alone_is_never_a_factor() {
        assert!(classify_uvm_for_ts12(&[UvmEntry {
            user_verification_method: 0x0000_0001, // USER_VERIFY_PRESENCE_INTERNAL
            key_protection_type: 1,
            matcher_protection_type: 1,
        }])
        .is_none());
    }

    #[test]
    fn multiple_entries_are_ambiguous_and_unclassified() {
        let entries = [
            UvmEntry {
                user_verification_method: USER_VERIFY_FINGERPRINT_INTERNAL,
                key_protection_type: 1,
                matcher_protection_type: 1,
            },
            UvmEntry {
                user_verification_method: USER_VERIFY_PASSCODE_INTERNAL,
                key_protection_type: 1,
                matcher_protection_type: 1,
            },
        ];
        assert!(classify_uvm_for_ts12(&entries).is_none());
    }

    #[test]
    fn an_unmapped_method_bit_is_unclassified() {
        assert!(classify_uvm_for_ts12(&[UvmEntry {
            user_verification_method: 0x0000_0020, // USER_VERIFY_LOCATION_INTERNAL
            key_protection_type: 1,
            matcher_protection_type: 1,
        }])
        .is_none());
    }
}
