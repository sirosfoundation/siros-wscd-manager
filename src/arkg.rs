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

    fn hex_decode(s: &str) -> Vec<u8> {
        hex::decode(s.replace(['\n', ' '], "")).expect("test vector is valid hex")
    }

    /// Known-answer test: RFC 9380 Appendix K.1, `expand_message_xmd(SHA-256)`.
    ///
    /// The test above only asserts that this function is *deterministic* and
    /// injective-looking. That passes just as happily against a wrong
    /// implementation — a dropped `Z_pad`, a misordered `l_i_b_str`, a
    /// `DST_prime` missing its length byte, or a `b_0` chaining bug in the
    /// `i >= 2` loop are all perfectly deterministic. Any one of them still
    /// derives a public key the authenticator cannot re-derive the private
    /// half of, so every signature made against that credential fails, and
    /// nothing in this crate's own tests would have said so.
    ///
    /// The `len_in_bytes = 0x80` cases matter specifically: `L = 48` (what
    /// [`hash_to_scalar_field`] asks for) gives `ell = 2`, so the XOR-chaining
    /// loop runs — the 32-byte cases alone never enter it.
    #[test]
    fn expand_message_xmd_matches_rfc9380_appendix_k1() {
        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let cases: &[(&[u8], usize, &str)] = &[
            (
                b"",
                0x20,
                "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
            ),
            (
                b"abc",
                0x20,
                "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
            ),
            (
                b"abcdef0123456789",
                0x20,
                "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1",
            ),
            (
                b"",
                0x80,
                "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbe\
                 e0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18\
                 eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dc\
                 c541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
            ),
            (
                b"abc",
                0x80,
                "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a\
                 647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635\
                 bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00\
                 058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40",
            ),
            (
                b"abcdef0123456789",
                0x80,
                "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9\
                 ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4b\
                 c95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be1\
                 4cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df",
            ),
        ];

        for (msg, len, expected) in cases {
            assert_eq!(
                expand_message_xmd(msg, DST, *len),
                hex_decode(expected),
                "RFC 9380 K.1 vector failed for msg={:?} len_in_bytes={len:#x}",
                std::str::from_utf8(msg).unwrap(),
            );
        }
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

    /// The property the whole module exists to provide, and the only one
    /// that is not self-referential: the public key handed to the issuer must
    /// be the public half of the private key the *authenticator* will
    /// independently re-derive from `kh` at signing time.
    ///
    /// Everything else here checks that this code agrees with itself.
    /// Determinism holds for a wrong DST, a wrong HKDF salt, a `t`
    /// truncated to the wrong length, `c` assembled in the wrong order, or a
    /// `ctx` length prefix that never made it into the KEM info string — and
    /// every one of those produces a credential whose signatures fail
    /// verification on real hardware, with the failure surfacing at the
    /// verifier rather than here.
    ///
    /// So this test plays the authenticator's side: it runs
    /// `ARKG-derive-private-key` (draft-bradleylundberg-cfrg-arkg-08 §3.2)
    /// against the returned `kh`, written out from the draft rather than
    /// reusing this module's helpers, and checks two things — that the MAC
    /// tag in `kh` validates, and that `G * sk` is exactly the public key
    /// [`derive_public_key`] returned. It then signs with `sk` and verifies
    /// against that public key, which is the end-to-end statement a credential
    /// issuer is relying on.
    #[test]
    fn derived_public_key_is_the_public_half_of_the_authenticators_private_key() {
        use hmac::digest::Mac as _;
        use p256::ecdsa::signature::{Signer, Verifier};

        // The authenticator's long-term ARKG secrets; only their public
        // halves ever reach `derive_public_key`.
        let sk_bl = SecretKey::generate();
        let sk_kem = SecretKey::generate();
        let seed = ArkgPublicSeed {
            pk_bl: sk_bl.public_key(),
            pk_kem: sk_kem.public_key(),
        };

        let ikm = b"per-credential randomness";
        let ctx = b"siros-wscd-manager previewSign";
        let (derived_pk, kh) = derive_public_key(&seed, ikm, ctx).unwrap();

        // ── ARKG-derive-private-key, from the draft ──────────────────────
        const DST_AUG: &[u8] = b"ARKG-ECDH.ARKG-P256";
        let ctx_kem = [b"ARKG-Derive-Key-KEM.".as_slice(), &[ctx.len() as u8], ctx].concat();
        let ctx_bl = [b"ARKG-Derive-Key-BL.".as_slice(), &[ctx.len() as u8], ctx].concat();

        // `kh` is the KEM ciphertext `c = t[..16] || c'`, and `c'` is an
        // uncompressed SEC1 point (0x04 || x || y).
        assert_eq!(kh.len(), 16 + 65, "kh must be a 16-byte tag plus a point");
        let (tag, c_prime) = kh.split_at(16);
        let pk_prime = PublicKey::from_sec1_bytes(c_prime).expect("c' is a valid P-256 point");

        // k' = ECDH(sk_kem, pk')
        let k_prime = diffie_hellman(sk_kem.to_nonzero_scalar(), pk_prime.as_affine());
        let k_prime = k_prime.raw_secret_bytes();

        let expand = |info: &[u8]| -> [u8; 32] {
            let mut out = [0u8; 32];
            Hkdf::<Sha256>::new(Some(&[]), k_prime)
                .expand(info, &mut out)
                .unwrap();
            out
        };
        let mac_key = expand(&[b"ARKG-KEM-HMAC-mac.".as_slice(), DST_AUG, &ctx_kem].concat());
        let tau = expand(&[b"ARKG-KEM-HMAC-shared.".as_slice(), DST_AUG, &ctx_kem].concat());

        // The HMAC-KEM tag authenticates c'. A mismatch means the platform
        // and the authenticator disagree about the key handle, and the
        // authenticator would refuse to sign at all.
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&mac_key).unwrap();
        mac.update(c_prime);
        assert_eq!(
            &mac.finalize().into_bytes()[..16],
            tag,
            "the key handle's HMAC-KEM tag must validate against c'"
        );

        // sk = sk_bl + tau', tau' = hash_to_scalar_field(tau) over the
        // P-256 group order (SEC 2 §2.4.2), reduced here directly rather
        // than through this module's own helper.
        let order = BigUint::from_bytes_be(&hex_decode(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        ));
        let uniform = expand_message_xmd(
            &tau,
            &[b"ARKG-BL-EC.ARKG-P256".as_slice(), &ctx_bl].concat(),
            48,
        );
        let mut reduced = (BigUint::from_bytes_be(&uniform) % &order).to_bytes_be();
        while reduced.len() < 32 {
            reduced.insert(0, 0);
        }
        let tau_prime: Scalar = Option::from(Scalar::from_repr(
            p256::FieldBytes::try_from(reduced.as_slice()).unwrap(),
        ))
        .unwrap();
        let sk = *sk_bl.to_nonzero_scalar().as_ref() + tau_prime;

        assert_eq!(
            (ProjectivePoint::GENERATOR * sk).to_affine(),
            *derived_pk.as_affine(),
            "the authenticator's re-derived private key does not match the \
             public key the issuer was given"
        );

        // And the derived pair really signs and verifies, which is what the
        // credential ultimately depends on.
        let signing_key = p256::ecdsa::SigningKey::from(
            Option::<NonZeroScalar>::from(NonZeroScalar::new(sk)).unwrap(),
        );
        let signature: p256::ecdsa::Signature = signing_key.sign(b"key binding message");
        p256::ecdsa::VerifyingKey::from(derived_pk)
            .verify(b"key binding message", &signature)
            .expect(
                "a signature by the derived private key must verify under the derived public key",
            );
    }

    /// A different `ctx` must derive a different key even with the same
    /// `ikm`. `ctx` is domain separation: if it fell out of the KEM/BL info
    /// strings, two applications sharing an authenticator would derive
    /// colliding keys and neither this module's determinism tests nor the
    /// `ikm` test above would notice.
    #[test]
    fn derive_public_key_differs_with_different_ctx() {
        let seed = random_public_seed();
        let ikm = b"fixed-test-ikm";
        let (pk1, kh1) = derive_public_key(&seed, ikm, b"context-one").unwrap();
        let (pk2, kh2) = derive_public_key(&seed, ikm, b"context-two").unwrap();
        assert_ne!(pk1.to_sec1_bytes(), pk2.to_sec1_bytes());
        assert_ne!(kh1, kh2);
    }

    /// Exactly 64 bytes of `ctx` is the documented maximum and must be
    /// accepted; 65 is rejected by the test above. Pinning both sides makes
    /// an off-by-one in the bound a test failure rather than a credential
    /// that cannot be created for a legitimate context string.
    #[test]
    fn derive_public_key_accepts_ctx_at_exactly_the_limit() {
        let seed = random_public_seed();
        assert!(derive_public_key(&seed, b"ikm", &[0u8; 64]).is_ok());
    }

    #[test]
    fn parse_arkg_pub_seed_rejects_wrong_kty() {
        let value = Value::Map(vec![(Value::Integer(1.into()), Value::Integer(2.into()))]);
        assert!(parse_arkg_pub_seed(&value).is_err());
    }

    fn ec2_cose_value(public: &PublicKey) -> Value {
        use p256::elliptic_curve::sec1::ToSec1Point;
        let point = public.to_sec1_point(false);
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-7).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (
                Value::Integer((-2).into()),
                Value::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                Value::Integer((-3).into()),
                Value::Bytes(point.y().unwrap().to_vec()),
            ),
        ])
    }

    fn arkg_pub_cose_value(alg: i64, pk_bl: &PublicKey, pk_kem: &PublicKey) -> Value {
        Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Integer(COSE_KTY_ARKG_PUB.into()),
            ),
            (Value::Integer(3.into()), Value::Integer(alg.into())),
            (Value::Integer((-1).into()), ec2_cose_value(pk_bl)),
            (Value::Integer((-2).into()), ec2_cose_value(pk_kem)),
        ])
    }

    /// Rejection paths for a malformed ARKG-pub seed.
    ///
    /// This value comes straight off the wire from an authenticator, so every
    /// one of these shapes is reachable from a firmware bug, a truncated
    /// response, or a different extension answering. `parse_arkg_pub_seed`'s
    /// failure is not merely cosmetic: `PreviewSignPlugin::generate_key`
    /// treats *any* error here as "this must be a plain EC2 key" and falls
    /// through to the non-ARKG branch, so a parse that wrongly succeeds or
    /// wrongly fails changes which kind of key gets stored, silently.
    #[test]
    fn parse_arkg_pub_seed_rejects_malformed_seeds() {
        let pk_bl = SecretKey::generate().public_key();
        let pk_kem = SecretKey::generate().public_key();

        // The two algorithm identifiers real implementations send are both
        // accepted; anything else is not.
        for alg in [-65700, -65539] {
            assert!(parse_arkg_pub_seed(&arkg_pub_cose_value(alg, &pk_bl, &pk_kem)).is_ok());
        }
        for alg in [-7, -65538, 0] {
            assert!(
                parse_arkg_pub_seed(&arkg_pub_cose_value(alg, &pk_bl, &pk_kem)).is_err(),
                "alg {alg} must not be accepted as an ARKG-pub key"
            );
        }

        // Not a map at all.
        assert!(parse_arkg_pub_seed(&Value::Bytes(vec![1, 2, 3])).is_err());

        // Missing pkBl (-1) / pkKem (-2), and a nested key that is not a
        // valid P-256 point.
        let base = arkg_pub_cose_value(-65700, &pk_bl, &pk_kem);
        for drop_label in [-1i128, -2] {
            let map: Vec<_> = base
                .as_map()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.as_integer().map(i128::from) != Some(drop_label))
                .cloned()
                .collect();
            assert!(
                parse_arkg_pub_seed(&Value::Map(map)).is_err(),
                "a seed missing label {drop_label} must be rejected"
            );
        }
        let map: Vec<_> = base
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                if k.as_integer().map(i128::from) == Some(-1) {
                    (k.clone(), Value::Map(vec![]))
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect();
        assert!(parse_arkg_pub_seed(&Value::Map(map)).is_err());
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
