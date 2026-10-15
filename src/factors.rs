//! EC TS12 v1.0.1 section 3.6 authentication factors for a signing operation.
//!
//! The KB-JWT `amr` of an SCA presentation is an array of single-key objects
//! (`{"possession": "key_in_remote_wscd"}`), drawn from a fixed vocabulary,
//! spanning at least two DIFFERENT categories. The legacy
//! [`crate::types::SecurityProperties::amr`] (RFC 8176 strings, "last sign")
//! cannot express that, and is left alone so the generated bindings do not
//! change. This module is the additive replacement: factors are returned
//! TOGETHER with the signature they describe ([`SignOutcome`]), so they can
//! never describe an earlier or a concurrent sign.
//!
//! Rules every plugin follows:
//! - only report a factor that was actually applied for THIS sign;
//! - a plugin that cannot reach two categories says so explicitly
//!   ([`AuthFactors::shortfall`]) instead of guessing a factor;
//! - the PIN/passphrase class is MEASURED from the secret the user typed for
//!   this sign ([`classify_secret`]); when no secret was seen the class is
//!   unknown and no knowledge factor is reported.

use std::sync::Mutex;

use async_trait::async_trait;

use crate::callbacks::AuthCallback;
use crate::error::{Result, WscdError};
use crate::types::{Secret, Signature};

/// Authentication category (TS12 v1.0.1 section 3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FactorCategory {
    Knowledge,
    Possession,
    Inherence,
}

impl FactorCategory {
    /// The key of the single-key `amr` object.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Knowledge => "knowledge",
            Self::Possession => "possession",
            Self::Inherence => "inherence",
        }
    }

    /// The methods TS12 v1.0.1 section 3.6 defines for this category.
    /// Mirrors `AuthenticationFactor.METHODS` in the SDKs; keep in sync.
    pub fn methods(&self) -> &'static [&'static str] {
        match self {
            Self::Knowledge => &[
                "pin_less_than_6_digits",
                "pin_6_or_more_digits",
                "passphrase_less_than_8_chars",
                "passphrase_8_to_11_chars",
                "passphrase_12_or_more_chars",
                "pattern",
                "other",
            ],
            Self::Possession => &[
                "key_in_remote_wscd",
                "key_in_local_external_wscd",
                "key_in_local_internal_wscd",
                "key_in_local_native_wscd",
                "other",
            ],
            Self::Inherence => &[
                "fingerprint_device",
                "fingerprint_external",
                "face_device",
                "face_external",
                "other",
            ],
        }
    }
}

/// One `amr` entry. The method is validated against the TS12 vocabulary at
/// construction: an `amr` the verifier cannot interpret is worse than none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFactor {
    pub(crate) category: FactorCategory,
    pub(crate) method: String,
}

impl AuthFactor {
    pub fn category(&self) -> FactorCategory {
        self.category
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    /// The only public constructor: the method is validated.
    pub fn new(category: FactorCategory, method: &str) -> Result<Self> {
        if !category.methods().contains(&method) {
            return Err(WscdError::Plugin(format!(
                "'{method}' is not a TS12 {} method",
                category.as_str()
            )));
        }
        Ok(Self {
            category,
            method: method.to_string(),
        })
    }

    /// For the plugin-internal constants, which are in the vocabulary by
    /// construction (checked by a test over every constant used).
    pub(crate) fn known(category: FactorCategory, method: &'static str) -> Self {
        debug_assert!(category.methods().contains(&method));
        Self {
            category,
            method: method.to_string(),
        }
    }
}

/// The factors applied to ONE sign, and whether they are enough for SCA.
///
/// Never constructed with a guess: `factors` lists only what the plugin can
/// justify, and when they span fewer than two categories `shortfall` says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFactors {
    factors: Vec<AuthFactor>,
    shortfall: Option<String>,
}

impl AuthFactors {
    /// `shortfall` is only kept when the factors do not span two categories;
    /// a missing reason in that case is replaced by a generic one so the
    /// outcome is never silently short.
    pub fn new(factors: Vec<AuthFactor>, shortfall: Option<String>) -> Self {
        // Re-validate: a factor with a method outside the vocabulary must
        // never count towards the two categories. Unreachable from outside
        // the crate (the fields are private), so this guards in-crate misuse.
        let mut shortfall = shortfall;
        let mut unique: Vec<AuthFactor> = Vec::with_capacity(factors.len());
        for f in factors {
            if !f.category.methods().contains(&f.method.as_str()) {
                shortfall = Some(format!(
                    "'{}' is not a TS12 {} method and was not counted",
                    f.method,
                    f.category.as_str()
                ));
            } else if !unique.contains(&f) {
                unique.push(f);
            }
        }
        let mut result = Self {
            factors: unique,
            shortfall: None,
        };
        if !result.satisfies_two_categories() {
            result.shortfall = Some(shortfall.unwrap_or_else(|| {
                "fewer than two distinct authentication categories were applied".to_string()
            }));
        }
        result
    }

    /// No factor can be established, for `reason`.
    pub fn none(reason: impl Into<String>) -> Self {
        Self::new(Vec::new(), Some(reason.into()))
    }

    pub fn factors(&self) -> &[AuthFactor] {
        &self.factors
    }

    /// Why fewer than two categories were reached; `None` when they were.
    pub fn shortfall(&self) -> Option<&str> {
        self.shortfall.as_deref()
    }

    /// At least two DIFFERENT categories (TS12 section 3.6).
    pub fn satisfies_two_categories(&self) -> bool {
        let mut seen: Vec<FactorCategory> = Vec::new();
        for f in &self.factors {
            if !seen.contains(&f.category) {
                seen.push(f.category);
            }
        }
        seen.len() >= 2
    }
}

/// Per-sign options. The default is exactly the behaviour of a plain `sign`.
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    /// Require a NEW user authentication for this sign: a session or token
    /// cached from an earlier operation must not be reused. A plugin that
    /// cannot guarantee that refuses (`Unsupported`) BEFORE signing rather
    /// than sign without it; only a path that really performs a fresh
    /// PIN/UV in this call honours it. Default off.
    pub require_fresh_user_authentication: bool,
    /// A user-verification factor the HOST performed or observed for this
    /// sign (e.g. its biometric prompt). Consulted only when the plugin
    /// itself observed that user verification took place but cannot tell
    /// how (a WebAuthn assertion with the UV flag set, or a transport that
    /// runs the UV ceremony itself). It never overrides a factor the plugin
    /// measured, never adds a factor when no UV was observed, and is
    /// host-asserted: the plugin cannot verify it. Must be knowledge or
    /// inherence; possession is determined by the plugin.
    pub host_verified_factor: Option<AuthFactor>,
}

impl SignOptions {
    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(f) = &self.host_verified_factor {
            if f.category == FactorCategory::Possession {
                return Err(WscdError::Plugin(
                    "host_verified_factor must be a knowledge or inherence factor".to_string(),
                ));
            }
            // Re-check the vocabulary: the field is public.
            AuthFactor::new(f.category, &f.method)?;
        }
        Ok(())
    }
}

/// A signature together with the factors applied to produce it.
#[derive(Debug, Clone)]
pub struct SignOutcome {
    pub signature: Signature,
    pub factors: AuthFactors,
}

/// Side-effect-free answer to "could this key's plugin reach two categories
/// for a sign?", for asking BEFORE the user is shown a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactorCapability {
    /// Two categories are reachable with the plugin's own means (it will
    /// prompt for a PIN through `AuthCallback`, say).
    pub can_reach_two_categories: bool,
    /// The plugin reaches only possession alone, but would reach a second
    /// category if the host supplies [`SignOptions::host_verified_factor`].
    pub requires_host_verified_factor: bool,
    /// Why not, when `can_reach_two_categories` is false.
    pub reason: Option<String>,
}

impl FactorCapability {
    pub fn cannot(reason: impl Into<String>) -> Self {
        Self {
            can_reach_two_categories: false,
            requires_host_verified_factor: false,
            reason: Some(reason.into()),
        }
    }
    pub fn can() -> Self {
        Self {
            can_reach_two_categories: true,
            requires_host_verified_factor: false,
            reason: None,
        }
    }
    pub fn with_host_factor(reason: impl Into<String>) -> Self {
        Self {
            can_reach_two_categories: false,
            requires_host_verified_factor: true,
            reason: Some(reason.into()),
        }
    }
}

/// Measure the class of a secret the user typed, as a TS12 knowledge method.
///
/// All ASCII digits: a PIN, `pin_less_than_6_digits` / `pin_6_or_more_digits`
/// by length. Anything else is a passphrase, classed by character count
/// (8 and 12 are the vocabulary's boundaries). Returns `None` for an empty or
/// non-UTF-8 secret: the class is then unknown and must not be guessed.
pub fn classify_secret(secret: &[u8]) -> Option<&'static str> {
    let s = std::str::from_utf8(secret).ok()?;
    let n = s.chars().count();
    if n == 0 {
        return None;
    }
    Some(if s.chars().all(|c| c.is_ascii_digit()) {
        if n < 6 {
            "pin_less_than_6_digits"
        } else {
            "pin_6_or_more_digits"
        }
    } else if n < 8 {
        "passphrase_less_than_8_chars"
    } else if n < 12 {
        "passphrase_8_to_11_chars"
    } else {
        "passphrase_12_or_more_chars"
    })
}

/// Wraps an [`AuthCallback`], remembering what the user was asked for during
/// ONE sign. It keeps only the measured class of each PIN, never the PIN.
pub(crate) struct RecordingAuth<'a> {
    inner: &'a dyn AuthCallback,
    /// One entry per `request_pin` that returned a secret: its class, `None`
    /// when unclassifiable.
    pins: Mutex<Vec<Option<&'static str>>>,
}

impl<'a> RecordingAuth<'a> {
    pub(crate) fn new(inner: &'a dyn AuthCallback) -> Self {
        Self {
            inner,
            pins: Mutex::new(Vec::new()),
        }
    }

    /// `None`: no PIN was requested for this sign. `Some(None)`: one was but
    /// its class is unknown. `Some(Some(m))`: the last PIN's class.
    pub(crate) fn last_pin(&self) -> Option<Option<&'static str>> {
        self.pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last()
            .copied()
    }
}

#[async_trait]
impl AuthCallback for RecordingAuth<'_> {
    async fn request_pin(&self, plugin_id: &str) -> Result<Secret> {
        let secret = self.inner.request_pin(plugin_id).await?;
        self.pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(classify_secret(&secret));
        Ok(secret)
    }

    async fn request_webauthn_assertion(
        &self,
        plugin_id: &str,
        challenge: &[u8],
        rp_id: &str,
        allowed_credentials: &[Vec<u8>],
    ) -> Result<Vec<u8>> {
        self.inner
            .request_webauthn_assertion(plugin_id, challenge, rp_id, allowed_credentials)
            .await
    }
}

/// Factors for a plugin whose key is possessed and whose user verification is
/// either measured (`pin_class`) or only observable as having happened.
///
/// - `possession`: the possession method for the plugin's key.
/// - `pin`: `None` no PIN requested for this sign; `Some(None)` requested but
///   unclassifiable; `Some(Some(m))` measured class.
/// - `uv_observed_unspecified`: user verification was observed but its method
///   is not known from a PIN typed through this crate's own `AuthCallback`
///   (UV flag, or a UV-performing transport).
/// - `plugin_verified_factor`: a factor the PLUGIN ITSELF derived for this
///   sign from data the transport returned (e.g. a WebAuthn `uvm` extension
///   parsed out of the signed `authenticatorData` - see
///   `crate::webauthn_uvm`). This is at the same trust tier as the UV flag
///   the plugin already relies on, so it takes priority over
///   `options.host_verified_factor` (a claim the plugin can never verify) -
///   but it only ever plays the same role that field did: a second factor
///   for user verification the plugin OBSERVED but could not otherwise
///   name.
pub(crate) fn derive_factors(
    possession: &'static str,
    pin: Option<Option<&'static str>>,
    uv_observed_unspecified: bool,
    plugin_verified_factor: Option<&AuthFactor>,
    options: &SignOptions,
    no_second_factor_reason: &str,
) -> AuthFactors {
    let mut factors = vec![AuthFactor::known(FactorCategory::Possession, possession)];
    let mut shortfall = None;
    match pin {
        Some(Some(method)) => factors.push(AuthFactor::known(FactorCategory::Knowledge, method)),
        Some(None) => {
            shortfall = Some("the PIN entered for this sign could not be classified".to_string())
        }
        None if uv_observed_unspecified => {
            match plugin_verified_factor.or(options.host_verified_factor.as_ref()) {
                Some(f) => factors.push(f.clone()),
                None => {
                    shortfall = Some(
                        "user verification was performed but its method is not reported; \
                         the host must supply host_verified_factor"
                            .to_string(),
                    )
                }
            }
        }
        None => shortfall = Some(no_second_factor_reason.to_string()),
    }
    AuthFactors::new(factors, shortfall)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_classes_are_measured_at_the_vocabulary_boundaries() {
        assert_eq!(classify_secret(b"12345"), Some("pin_less_than_6_digits"));
        assert_eq!(classify_secret(b"123456"), Some("pin_6_or_more_digits"));
        assert_eq!(classify_secret(b"1234567890"), Some("pin_6_or_more_digits"));
        assert_eq!(
            classify_secret(b"abc123"),
            Some("passphrase_less_than_8_chars")
        );
        assert_eq!(
            classify_secret(b"abcdefg1"),
            Some("passphrase_8_to_11_chars")
        );
        assert_eq!(
            classify_secret(b"abcdefghij1"),
            Some("passphrase_8_to_11_chars")
        );
        assert_eq!(
            classify_secret(b"abcdefghijk1"),
            Some("passphrase_12_or_more_chars")
        );
        // Characters, not bytes: five 2-byte characters are still 5.
        assert_eq!(
            classify_secret("åäöåä".as_bytes()),
            Some("passphrase_less_than_8_chars")
        );
        // Unknown must stay unknown.
        assert_eq!(classify_secret(b""), None);
        assert_eq!(classify_secret(&[0xff, 0xfe]), None);
    }

    #[test]
    fn every_method_the_plugins_use_is_in_the_vocabulary() {
        for (c, m) in [
            (FactorCategory::Possession, "key_in_remote_wscd"),
            (FactorCategory::Possession, "key_in_local_external_wscd"),
            (FactorCategory::Knowledge, "pin_less_than_6_digits"),
            (FactorCategory::Knowledge, "pin_6_or_more_digits"),
            (FactorCategory::Knowledge, "passphrase_less_than_8_chars"),
            (FactorCategory::Knowledge, "passphrase_8_to_11_chars"),
            (FactorCategory::Knowledge, "passphrase_12_or_more_chars"),
        ] {
            AuthFactor::new(c, m).unwrap();
        }
        assert!(AuthFactor::new(FactorCategory::Knowledge, "key_in_remote_wscd").is_err());
        assert!(AuthFactor::new(FactorCategory::Inherence, "retina").is_err());
    }

    #[test]
    fn an_off_vocabulary_factor_is_not_counted() {
        let forged = AuthFactor {
            category: FactorCategory::Knowledge,
            method: "retina".to_string(),
        };
        let factors = AuthFactors::new(
            vec![
                AuthFactor::known(FactorCategory::Possession, "key_in_remote_wscd"),
                forged,
            ],
            None,
        );
        assert_eq!(factors.factors().len(), 1);
        assert!(!factors.satisfies_two_categories());
        assert!(factors.shortfall().unwrap().contains("retina"));
    }

    #[test]
    fn one_category_is_never_reported_as_satisfied() {
        let possession = AuthFactor::known(FactorCategory::Possession, "key_in_remote_wscd");
        let two_possessions = AuthFactors::new(
            vec![
                possession.clone(),
                AuthFactor::known(FactorCategory::Possession, "key_in_local_native_wscd"),
            ],
            None,
        );
        assert!(!two_possessions.satisfies_two_categories());
        assert!(two_possessions.shortfall().is_some());
        let both = AuthFactors::new(
            vec![
                possession,
                AuthFactor::known(FactorCategory::Knowledge, "pin_6_or_more_digits"),
            ],
            Some("stale".into()),
        );
        assert!(both.satisfies_two_categories());
        assert_eq!(both.shortfall(), None);
    }

    #[test]
    fn host_factor_is_ignored_unless_uv_was_observed_and_possession_is_refused() {
        let opts = SignOptions {
            host_verified_factor: Some(
                AuthFactor::new(FactorCategory::Inherence, "face_device").unwrap(),
            ),
            ..Default::default()
        };
        let unobserved = derive_factors("key_in_remote_wscd", None, false, None, &opts, "no UV");
        assert!(!unobserved.satisfies_two_categories());
        let observed = derive_factors("key_in_remote_wscd", None, true, None, &opts, "no UV");
        assert!(observed.satisfies_two_categories());
        // A measured PIN wins over the host's claim.
        let measured = derive_factors(
            "key_in_remote_wscd",
            Some(Some("pin_6_or_more_digits")),
            true,
            None,
            &opts,
            "no UV",
        );
        assert_eq!(measured.factors().len(), 2);
        assert_eq!(measured.factors()[1].method, "pin_6_or_more_digits");

        // A plugin-derived factor (e.g. from `uvm`) wins over the host's
        // unverifiable claim.
        let plugin_factor =
            AuthFactor::new(FactorCategory::Inherence, "fingerprint_external").unwrap();
        let plugin_derived = derive_factors(
            "key_in_remote_wscd",
            None,
            true,
            Some(&plugin_factor),
            &opts,
            "no UV",
        );
        assert_eq!(plugin_derived.factors()[1].method, "fingerprint_external");

        let bad = SignOptions {
            host_verified_factor: Some(AuthFactor::known(
                FactorCategory::Possession,
                "key_in_remote_wscd",
            )),
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }
}
