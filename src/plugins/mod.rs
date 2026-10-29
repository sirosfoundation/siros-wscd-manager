#[cfg(feature = "plugin-android-keystore")]
pub mod android_keystore;
#[cfg(feature = "plugin-apple-se")]
pub mod apple_secure_enclave;
#[cfg(feature = "plugin-fido2")]
pub mod fido2_sign;
pub mod softkey;

#[cfg(feature = "plugin-r2ps")]
pub mod r2ps;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{Result, WscdError};
use crate::types::{FactorKind, KeyId, LifecycleState, LifecycleStatus, RegistrationOutcome};

/// Per-context lifecycle bookkeeping shared by the softkey and fido2
/// plugins: which keys back a registered context, what TS12 factor it
/// registered with, and when it last changed state. Factored out of both
/// plugins (siros-wscd-manager#136) where it was declared and used
/// near-identically. R2PS keeps its own narrower, non-`Serialize` variant
/// of this type (it has no local `key_ids` - the keys it tracks live on
/// the remote HSM - and never persists its lifecycle map to a container
/// blob), so it is not shared here.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LifecycleContext {
    pub(crate) factor_kind: FactorKind,
    pub(crate) state: LifecycleState,
    pub(crate) updated_at: i64,
    pub(crate) key_ids: Vec<KeyId>,
}

/// Shared `lifecycle_status()` body for every plugin that keeps its
/// contexts in a `HashMap<String, _>` keyed by context id: look up
/// `context_id` and report its factor kind / state / timestamp, or
/// `KeyNotFound` if there is no such context. Takes the already-extracted
/// fields rather than a `&LifecycleContext` so R2PS's distinct lifecycle
/// context type (see [`LifecycleContext`]'s doc comment) can share this
/// too instead of needing its own copy of this logic.
pub(crate) fn lifecycle_status_fields(
    plugin_id: &str,
    context_id: &str,
    found: Option<(FactorKind, LifecycleState, i64)>,
) -> Result<LifecycleStatus> {
    let (factor_kind, state, updated_at) = found.ok_or_else(|| WscdError::KeyNotFound {
        kid: context_id.to_string(),
    })?;
    Ok(LifecycleStatus {
        context_id: context_id.to_string(),
        plugin_id: plugin_id.to_string(),
        factor_kind,
        state,
        updated_at,
    })
}

/// Shared `activate_lifecycle()` body for the softkey and fido2 plugins:
/// move the named context straight to `Active` and stamp `now`. Returns
/// `KeyNotFound` if the context doesn't exist.
pub(crate) fn activate_lifecycle_context(
    lifecycle: &mut HashMap<String, LifecycleContext>,
    context_id: &str,
    now: i64,
) -> Result<()> {
    let ctx = lifecycle
        .get_mut(context_id)
        .ok_or_else(|| WscdError::KeyNotFound {
            kid: context_id.to_string(),
        })?;
    ctx.state = LifecycleState::Active;
    ctx.updated_at = now;
    Ok(())
}

/// Shared `register_lifecycle()` tail for the softkey and fido2 plugins,
/// run after each has generated `new_kid` under its own key-generation
/// path (which differs per plugin and stays at the call site).
///
/// Re-registering an already-registered context (Enroll tapped again
/// without an intervening Destroy - confirmed to happen during real
/// testing, e.g. after a stuck busy flag made Destroy unreachable) used to
/// just overwrite `key_ids` with the newest key, silently orphaning
/// whatever key(s) the old context pointed at: they stayed in the
/// plugin's key store forever since `destroy_lifecycle` only ever looks at
/// the CURRENT context's `key_ids`. `purge_stale_keys` is called with the
/// old context's `key_ids` (if any) before they're overwritten, so the
/// caller can remove them from its own key store first and re-registering
/// behaves like an implicit destroy-then-register that never leaks keys.
pub(crate) fn register_lifecycle_context(
    lifecycle: &mut HashMap<String, LifecycleContext>,
    context_id: &str,
    factor_kind: FactorKind,
    new_kid: KeyId,
    now: i64,
    purge_stale_keys: impl FnOnce(&[KeyId]),
) -> RegistrationOutcome {
    if let Some(old_ctx) = lifecycle.get(context_id) {
        purge_stale_keys(&old_ctx.key_ids);
    }
    lifecycle.insert(
        context_id.to_string(),
        LifecycleContext {
            factor_kind,
            state: LifecycleState::Registered,
            updated_at: now,
            key_ids: vec![new_kid],
        },
    );
    RegistrationOutcome {
        context_id: context_id.to_string(),
        state: LifecycleState::Registered,
    }
}

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
