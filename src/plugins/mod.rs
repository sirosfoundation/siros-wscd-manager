#[cfg(feature = "plugin-fido2")]
pub mod preview_sign;
pub mod softkey;

#[cfg(feature = "plugin-r2ps")]
pub mod r2ps;

/// Derives a plugin key identifier from the key's public JWK: the RFC 7638
/// JWK thumbprint (SHA-256 over the canonical required members, base64url
/// without padding).
///
/// # Why a fingerprint, and why not a counter or a random id
///
/// Both the FIDO2 and softkey plugins used to mint identifiers from a
/// per-plugin counter (`fido-0`, `sw-1`, ...). A counter is a shared
/// allocator, and the key metadata it numbers is synchronised between every
/// device on an account - so two devices enrolling while unsynchronised both
/// start from the same value and mint the *same identifier for different
/// keys*: an id collision, one key silently unaddressable while still listed.
/// That was first replaced by 128 random bits behind a plugin prefix, which
/// removed the allocator.
///
/// A thumbprint keeps that property (no coordination, no allocator) and adds
/// two more. The identifier is *verifiable*: anyone holding the JWK can
/// recompute it, so a `kid` in a credential's key binding or in the
/// synchronised key metadata can be checked against the key it claims to
/// name instead of trusted. And it is what a JWK `kid` conventionally is
/// (RFC 7638 §3), so consumers that key on public-key fingerprints - the
/// wallet frontend among them - need no mapping. Plugin prefixes are gone:
/// two different keys cannot share a thumbprint, so the id spaces cannot
/// collide across plugins, and nothing parsed the prefix.
///
/// Identifiers minted under the earlier schemes stay valid: every plugin
/// keys its store by the stored string, and the manager's `key_bindings`
/// map does the same, so existing containers load unchanged. Only the
/// R2PS plugin keeps its own identifiers, which the remote service assigns.
pub(crate) fn jwk_thumbprint(jwk: &serde_json::Value) -> crate::error::Result<String> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use sha2::{Digest, Sha256};

    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| crate::error::WscdError::Plugin("JWK has no kty".into()))?;
    // RFC 7638 §3.2: the required members of the key type, in lexicographic
    // order, with no whitespace. Built by hand: serde_json's map may or may
    // not preserve insertion order depending on features pulled in by other
    // crates, and canonical form must not depend on that.
    let members: &[&str] = match kty {
        "EC" => &["crv", "kty", "x", "y"],
        "OKP" => &["crv", "kty", "x"],
        "RSA" => &["e", "kty", "n"],
        "oct" => &["k", "kty"],
        other => {
            return Err(crate::error::WscdError::Plugin(format!(
                "cannot compute a thumbprint for kty {other}"
            )))
        }
    };
    let mut canonical = String::from("{");
    for (i, name) in members.iter().enumerate() {
        let value = jwk.get(name).and_then(|v| v.as_str()).ok_or_else(|| {
            crate::error::WscdError::Plugin(format!("JWK of kty {kty} is missing {name}"))
        })?;
        if i > 0 {
            canonical.push(',');
        }
        // Member names and values are base64url / curve names / key types:
        // plain JSON strings with nothing to escape.
        canonical.push_str(&serde_json::to_string(name).expect("string"));
        canonical.push(':');
        canonical.push_str(&serde_json::to_string(value).expect("string"));
    }
    canonical.push('}');
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(Base64UrlUnpadded::encode_string(&digest))
}

#[cfg(test)]
mod kid_tests {
    use super::jwk_thumbprint;

    /// RFC 7638 §3.1's worked example, byte for byte.
    #[test]
    fn matches_the_rfc_7638_example() {
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        assert_eq!(
            jwk_thumbprint(&jwk).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    /// Only the required members count: `kid`, `alg`, `use` and ordering of
    /// the input make no difference, so two views of one key agree.
    #[test]
    fn ignores_optional_members_and_input_order() {
        let a = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB"});
        let b = serde_json::json!({"y": "BBBB", "alg": "ES256", "x": "AAAA", "kid": "old", "crv": "P-256", "kty": "EC", "use": "sig"});
        assert_eq!(jwk_thumbprint(&a).unwrap(), jwk_thumbprint(&b).unwrap());
        // 32 bytes, base64url unpadded.
        assert_eq!(jwk_thumbprint(&a).unwrap().len(), 43);
    }

    #[test]
    fn different_keys_differ_and_broken_jwks_are_errors() {
        let a = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB"});
        let b = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBC"});
        assert_ne!(jwk_thumbprint(&a).unwrap(), jwk_thumbprint(&b).unwrap());
        let okp = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "AAAA"});
        assert_eq!(jwk_thumbprint(&okp).unwrap().len(), 43);
        assert!(
            jwk_thumbprint(&serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AAAA"})).is_err()
        );
        assert!(jwk_thumbprint(&serde_json::json!({"crv": "P-256"})).is_err());
        assert!(jwk_thumbprint(&serde_json::json!({"kty": "PQC"})).is_err());
    }
}
