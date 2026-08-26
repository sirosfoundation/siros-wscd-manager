//! ARKG (Asynchronous Remote Key Generation) public-key derivation,
//! ARKG-P256 instantiation only
//! ([draft-bradleylundberg-cfrg-arkg-08](https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-08.html)).
//!
//! Ported from `wallet-common`'s TypeScript reference implementation
//! (`src/arkg/index.ts`, `hash_to_curve.ts`, `ec.ts` - Yubico/@emlun),
//! which is itself the basis for `wallet-frontend`'s previewSign
//! integration (PR #22 on sirosfoundation/wallet-frontend).
//!
//! Only [`derive_public_key`] is implemented - the platform (this SDK)
//! only ever needs a fresh, unlinkable *public* key to embed in an
//! issued credential; the corresponding *private* key derivation
//! (`ARKG-derive-private-key`, needing `derivePrivateKey`/`decaps`) is
//! the authenticator's own job, done internally when it later signs via
//! previewSign's `signByCredential` ceremony, keyed by the `kh` (key
//! handle) this module also returns.
//!
//! `previewSign`'s `generateKey` output is an "ARKG-pub" COSE_Key
//! (`kty = -65537`, see [`crate::preview_sign_protocol`]'s doc comment
//! for where this was confirmed against real hardware) - a composite key
//! containing two *nested* EC2 COSE_Keys, `pkBl` (blinding public key,
//! map key `-1`) and `pkKem` (KEM public key, map key `-2`). It is NOT a
//! usable public key on its own; deriving one requires this module.

use ciborium::Value;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use num_bigint::BigUint;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::elliptic_curve::PrimeField;
use p256::{NonZeroScalar, ProjectivePoint, PublicKey, Scalar};
use sha2::{Digest, Sha256};

use crate::ctap2_client_pin::decode_cose_ec2_public_key;
use crate::error::{Result, WscdError};

/// `COSE_KTY_ARKG_PUB` per the ARKG draft's COSE key type registration.
pub const COSE_KTY_ARKG_PUB: i64 = -65537;
/// `ARKG-P256` per <https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-08.html#name-arkg-p256>.
const COSE_ALG_ARKG_P256: i64 = -65700;
/// Deprecated/incorrect `alg` value some previewSign implementations
/// send instead of [`COSE_ALG_ARKG_P256`] - `wallet-common` warns and
/// treats it the same way, so we do too.
const COSE_ALG_ESP256_ARKG_DEPRECATED: i64 = -65539;

const CTX_MAX_LEN: usize = 64;

/// P-256 (secp256r1) prime-order subgroup order, big-endian.
const P256_ORDER_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// An ARKG-pub COSE_Key: the two nested P-256 public keys `previewSign`'s
/// `generateKey` actually returns (see this module's doc comment).
pub struct ArkgPublicSeed {
    pk_bl: PublicKey,
    pk_kem: PublicKey,
}

/// Parse an ARKG-pub COSE_Key CBOR *value* (a nested map, same convention
/// as [`crate::ctap2_client_pin::decode_cose_ec2_public_key`] - not raw
/// bytes) into its two component EC2 public keys.
pub fn parse_arkg_pub_seed(value: &Value) -> Result<ArkgPublicSeed> {
    let map = value
        .as_map()
        .ok_or_else(|| WscdError::Crypto("ARKG-pub COSE key is not a CBOR map".into()))?;

    let kty = map
        .iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(1))
        .and_then(|(_, v)| v.as_integer())
        .and_then(|i| i64::try_from(i).ok());
    if kty != Some(COSE_KTY_ARKG_PUB) {
        return Err(WscdError::Crypto(format!(
            "expected ARKG-pub COSE key (kty {COSE_KTY_ARKG_PUB}), got kty {kty:?}"
        )));
    }

    let alg = map
        .iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(3))
        .and_then(|(_, v)| v.as_integer())
        .and_then(|i| i64::try_from(i).ok());
    match alg {
        Some(COSE_ALG_ARKG_P256) | Some(COSE_ALG_ESP256_ARKG_DEPRECATED) => {}
        other => {
            return Err(WscdError::Crypto(format!(
                "unsupported ARKG-pub COSE key alg: {other:?}"
            )))
        }
    }

    let pk_bl_value = map
        .iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(-1))
        .map(|(_, v)| v)
        .ok_or_else(|| WscdError::Crypto("ARKG-pub COSE key missing pkBl (-1)".into()))?;
    let pk_kem_value = map
        .iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(-2))
        .map(|(_, v)| v)
        .ok_or_else(|| WscdError::Crypto("ARKG-pub COSE key missing pkKem (-2)".into()))?;

    Ok(ArkgPublicSeed {
        pk_bl: decode_cose_ec2_public_key(pk_bl_value)?,
        pk_kem: decode_cose_ec2_public_key(pk_kem_value)?,
    })
}

/// `ARKG-derive-public-key` - see
/// <https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-08.html#name-the-function-arkg-derive-pu>.
///
/// `ikm` should be fresh randomness (32 bytes is plenty) for every
/// credential; `ctx` is an application-chosen context string (max 64
/// bytes) - reusing the same `(ikm, ctx)` pair always derives the same
/// key (confirmed by this module's own tests), so `ikm` must be fresh
/// per credential to get the unlinkability ARKG is for.
///
/// Returns `(derived_public_key, key_handle)` - the key handle must be
/// stored alongside the credential and supplied back to the
/// authenticator at sign time, COSE-encoded together with `ctx` via
/// [`encode_arkg_sign_args`], as previewSign's `signByCredential`
/// `additionalArgs`, so it can re-derive the matching *private* key.
pub fn derive_public_key(
    seed: &ArkgPublicSeed,
    ikm: &[u8],
    ctx: &[u8],
) -> Result<(PublicKey, Vec<u8>)> {
    if ctx.len() > CTX_MAX_LEN {
        return Err(WscdError::Crypto(format!(
            "ARKG ctx too long: {} bytes (max {CTX_MAX_LEN})",
            ctx.len()
        )));
    }

    let ctx_kem = {
        let mut v = b"ARKG-Derive-Key-KEM.".to_vec();
        v.push(ctx.len() as u8);
        v.extend_from_slice(ctx);
        v
    };
    let ctx_bl = {
        let mut v = b"ARKG-Derive-Key-BL.".to_vec();
        v.push(ctx.len() as u8);
        v.extend_from_slice(ctx);
        v
    };

    let (tau, kh) = kem_encaps(&seed.pk_kem, ikm, &ctx_kem)?;
    let derived = bl_blind_public_key(&seed.pk_bl, &tau, &ctx_bl)?;
    Ok((derived, kh))
}

/// COSE Signing Arguments - see
/// <https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-09.html#name-cose-signing-arguments>.
/// Ported from `wallet-common`'s `cose.ts` `encodeArkgSignArgs` (the same
/// reference implementation this module's doc comment cites) - confirmed
/// via live hardware testing that `additionalArgs` must be this
/// CBOR-encoded map, not the raw `kh` bytes alone: a real YubiKey rejected
/// bare `kh` with CTAP2_ERR_CBOR_UNEXPECTED_TYPE (it expects to decode a
/// map here, keyed by `alg`/`kh`/`ctx`).
pub fn encode_arkg_sign_args(alg: i64, kh: &[u8], ctx: &[u8]) -> Vec<u8> {
    let map = Value::Map(vec![
        (Value::Integer(3.into()), Value::Integer(alg.into())),
        (Value::Integer((-1).into()), Value::Bytes(kh.to_vec())),
        (Value::Integer((-2).into()), Value::Bytes(ctx.to_vec())),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).expect("CBOR encoding is infallible for Value");
    buf
}

/// The ECDH KEM (`arkgEcdhKem`) wrapped in the HMAC-KEM combinator
/// (`arkgHmacKem`), specialized to P-256/SHA-256 - see
/// <https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-08.html#name-using-ecdh-as-the-kem> and
/// <https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-08.html#name-using-hmac-to-adapt-a-kem-w>.
/// Returns `(k, c)`: `k` is the shared secret ("tau" in the caller),
/// `c` is the encapsulation ciphertext (part of the key handle).
fn kem_encaps(pubk_kem: &PublicKey, ikm: &[u8], ctx: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    // `arkgEcdhKem`'s own dst_ext is "ARKG-P256"; arkgHmacKem wraps it
    // with dst_aug = "ARKG-ECDH." + dst_ext.
    const DST_AUG: &[u8] = b"ARKG-ECDH.ARKG-P256";

    // Inner ECDH-KEM's ephemeral deriveKeypair(ikm).
    let dst_kg = [b"ARKG-KEM-ECDH-KG.".as_slice(), DST_AUG].concat();
    let sk_prime = hash_to_scalar_field(ikm, &dst_kg);
    let sk_prime_nonzero =
        Option::<NonZeroScalar>::from(NonZeroScalar::new(sk_prime)).ok_or_else(|| {
            WscdError::Crypto("ARKG: derived zero scalar (retry with new ikm)".into())
        })?;
    let pk_prime_point = ProjectivePoint::GENERATOR * sk_prime;
    let c_prime = encode_uncompressed_point(&pk_prime_point);

    // k' = ECDH(sk', pubk_kem) - raw shared secret bytes.
    let shared = diffie_hellman(&sk_prime_nonzero, pubk_kem.as_affine());
    let k_prime: [u8; 32] = shared
        .raw_secret_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| WscdError::Crypto("ARKG: ECDH shared secret is not 32 bytes".into()))?;

    // HMAC-KEM wrap: derive a MAC key and the real shared secret from
    // k', both via HKDF-Expand with an empty salt (confirmed equivalent
    // to a hashLen-zero salt by wallet-common's own test) and distinct
    // domain-separated info strings.
    let mac_info = [b"ARKG-KEM-HMAC-mac.".as_slice(), DST_AUG, ctx].concat();
    let mut mac_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&[]), &k_prime)
        .expand(&mac_info, &mut mac_key)
        .map_err(|e| WscdError::Crypto(format!("ARKG HKDF (mac key) failed: {e}")))?;

    let mut mac =
        Hmac::<Sha256>::new_from_slice(&mac_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(&c_prime);
    let t = mac.finalize().into_bytes();
    let t16 = &t[..16];

    let shared_info = [b"ARKG-KEM-HMAC-shared.".as_slice(), DST_AUG, ctx].concat();
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&[]), &k_prime)
        .expand(&shared_info, &mut k)
        .map_err(|e| WscdError::Crypto(format!("ARKG HKDF (shared secret) failed: {e}")))?;

    let mut c = Vec::with_capacity(16 + c_prime.len());
    c.extend_from_slice(t16);
    c.extend_from_slice(&c_prime);

    Ok((k, c))
}

/// The EC-addition blinding scheme (`arkgBlEcAdd`)'s `blindPublicKey`,
/// specialized to P-256 - see
/// <https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-08.html#name-using-elliptic-curve-additi>.
fn bl_blind_public_key(pk_bl: &PublicKey, tau: &[u8], ctx: &[u8]) -> Result<PublicKey> {
    let dst = [b"ARKG-BL-EC.ARKG-P256".as_slice(), ctx].concat();
    let tau_prime = hash_to_scalar_field(tau, &dst);

    let pk_point = ProjectivePoint::from(*pk_bl.as_affine());
    let blinded = pk_point + ProjectivePoint::GENERATOR * tau_prime;
    let blinded_affine = blinded.to_affine();

    PublicKey::from_affine(blinded_affine)
        .map_err(|_| WscdError::Crypto("ARKG: blinded public key is the point at infinity".into()))
}

fn encode_uncompressed_point(point: &ProjectivePoint) -> Vec<u8> {
    let affine = point.to_affine();
    let sec1_point = affine.to_sec1_point(false);
    let mut out = vec![0x04u8];
    out.extend_from_slice(sec1_point.x().expect("uncompressed point has x"));
    out.extend_from_slice(sec1_point.y().expect("uncompressed point has y"));
    out
}

/// RFC 9380 `hash_to_field`, instantiated for suite
/// `P256_XMD:SHA-256_SSWU_RO_` with `p` set to the curve's *scalar*
/// order (not its coordinate field prime) - i.e. "hashing to the scalar
/// field" per
/// <https://www.rfc-editor.org/rfc/rfc9380#name-hashing-to-a-finite-field>,
/// with `count = 1`, `m = 1`, `L = 48`.
fn hash_to_scalar_field(msg: &[u8], dst: &[u8]) -> Scalar {
    const L: usize = 48;
    let uniform_bytes = expand_message_xmd(msg, dst, L);

    let order = BigUint::from_bytes_be(&P256_ORDER_BYTES);
    let e = BigUint::from_bytes_be(&uniform_bytes) % &order;

    let mut bytes32 = e.to_bytes_be();
    if bytes32.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes32.len()];
        padded.extend_from_slice(&bytes32);
        bytes32 = padded;
    }
    let field_bytes =
        p256::FieldBytes::try_from(bytes32.as_slice()).expect("bytes32 is exactly 32 bytes");
    // `e` is already reduced mod the order, so this is always canonical.
    Option::from(Scalar::from_repr(field_bytes)).expect("reduced scalar is always canonical")
}

/// RFC 9380 `expand_message_xmd`, instantiated with SHA-256
/// (`b_in_bytes = 32`, `s_in_bytes = 64`) - see
/// <https://www.rfc-editor.org/rfc/rfc9380#name-expand_message_xmd>.
fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    const B_IN_BYTES: usize = 32;
    const S_IN_BYTES: usize = 64;

    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    assert!(
        ell <= 255 && len_in_bytes <= 65535 && dst.len() <= 255,
        "expand_message_xmd: requested length too long"
    );

    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    let z_pad = vec![0u8; S_IN_BYTES];
    let l_i_b_str = (len_in_bytes as u16).to_be_bytes();

    let mut msg_prime = Vec::new();
    msg_prime.extend_from_slice(&z_pad);
    msg_prime.extend_from_slice(msg);
    msg_prime.extend_from_slice(&l_i_b_str);
    msg_prime.push(0u8);
    msg_prime.extend_from_slice(&dst_prime);

    let mut b: Vec<Vec<u8>> = vec![Vec::new(); ell + 1];
    b[0] = Sha256::digest(&msg_prime).to_vec();

    let mut b1_input = b[0].clone();
    b1_input.push(1u8);
    b1_input.extend_from_slice(&dst_prime);
    b[1] = Sha256::digest(&b1_input).to_vec();

    for i in 2..=ell {
        let xored: Vec<u8> = b[0]
            .iter()
            .zip(b[i - 1].iter())
            .map(|(a, c)| a ^ c)
            .collect();
        let mut input = xored;
        input.push(i as u8);
        input.extend_from_slice(&dst_prime);
        b[i] = Sha256::digest(&input).to_vec();
    }

    let mut uniform_bytes = Vec::with_capacity(ell * B_IN_BYTES);
    for entry in b.iter().skip(1) {
        uniform_bytes.extend_from_slice(entry);
    }
    uniform_bytes.truncate(len_in_bytes);
    uniform_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::Generate;
    use p256::SecretKey;

    fn random_public_seed() -> ArkgPublicSeed {
        ArkgPublicSeed {
            pk_bl: SecretKey::generate().public_key(),
            pk_kem: SecretKey::generate().public_key(),
        }
    }

    #[test]
    fn expand_message_xmd_produces_requested_length() {
        let out = expand_message_xmd(b"hello", b"test-dst", 48);
        assert_eq!(out.len(), 48);
        // Deterministic: same inputs, same output.
        assert_eq!(out, expand_message_xmd(b"hello", b"test-dst", 48));
        // Different message, different output.
        assert_ne!(out, expand_message_xmd(b"world", b"test-dst", 48));
    }

    #[test]
    fn hash_to_scalar_field_is_deterministic_and_canonical() {
        let a = hash_to_scalar_field(b"ikm", b"dst");
        let b = hash_to_scalar_field(b"ikm", b"dst");
        assert_eq!(a, b);
        let c = hash_to_scalar_field(b"different-ikm", b"dst");
        assert_ne!(a, c);
    }

    #[test]
    fn derive_public_key_is_deterministic_given_same_ikm_and_ctx() {
        let seed = random_public_seed();
        let ikm = b"fixed-test-ikm-not-random-here!";
        let ctx = b"test-context";

        let (pk1, kh1) = derive_public_key(&seed, ikm, ctx).unwrap();
        let (pk2, kh2) = derive_public_key(&seed, ikm, ctx).unwrap();

        assert_eq!(pk1.to_sec1_bytes(), pk2.to_sec1_bytes());
        assert_eq!(kh1, kh2);
    }

    #[test]
    fn derive_public_key_differs_with_different_ikm() {
        let seed = random_public_seed();
        let ctx = b"test-context";

        let (pk1, kh1) = derive_public_key(&seed, b"ikm-one-32-bytes-padding-here!!", ctx).unwrap();
        let (pk2, kh2) = derive_public_key(&seed, b"ikm-two-32-bytes-padding-here!!", ctx).unwrap();

        assert_ne!(pk1.to_sec1_bytes(), pk2.to_sec1_bytes());
        assert_ne!(kh1, kh2);
    }

    #[test]
    fn derive_public_key_rejects_ctx_longer_than_64_bytes() {
        let seed = random_public_seed();
        let ctx = vec![0u8; 65];
        assert!(derive_public_key(&seed, b"ikm", &ctx).is_err());
    }

    #[test]
    fn parse_arkg_pub_seed_rejects_wrong_kty() {
        let value = Value::Map(vec![(Value::Integer(1.into()), Value::Integer(2.into()))]);
        assert!(parse_arkg_pub_seed(&value).is_err());
    }

    #[test]
    fn encode_arkg_sign_args_matches_cose_signing_arguments_layout() {
        // Real-hardware regression test: this encoding (CBOR map
        // {3: alg, -1: kh, -2: ctx}, per the ARKG draft's "COSE Signing
        // Arguments" and wallet-common's encodeArkgSignArgs) is required -
        // a real YubiKey rejected a bare `kh` byte string with
        // CTAP2_ERR_CBOR_UNEXPECTED_TYPE.
        let kh = vec![0xAAu8; 81];
        let ctx = b"wsiros-wscd-preview-sign".to_vec();
        let encoded = encode_arkg_sign_args(-65539, &kh, &ctx);

        let value: Value = ciborium::de::from_reader(encoded.as_slice()).unwrap();
        let map = value.as_map().unwrap();

        let alg = map
            .iter()
            .find(|(k, _)| k.as_integer().map(i128::from) == Some(3))
            .and_then(|(_, v)| v.as_integer())
            .unwrap();
        assert_eq!(i64::try_from(alg).unwrap(), -65539);

        let decoded_kh = map
            .iter()
            .find(|(k, _)| k.as_integer().map(i128::from) == Some(-1))
            .and_then(|(_, v)| v.as_bytes())
            .unwrap();
        assert_eq!(decoded_kh, &kh);

        let decoded_ctx = map
            .iter()
            .find(|(k, _)| k.as_integer().map(i128::from) == Some(-2))
            .and_then(|(_, v)| v.as_bytes())
            .unwrap();
        assert_eq!(decoded_ctx, &ctx);
    }
}
