use thiserror::Error;

#[derive(Debug, Error)]
pub enum WscdError {
    #[error("no plugin found for key {kid}")]
    NoPlugin { kid: String },

    #[error("no default plugin configured for operation {op}")]
    NoDefault { op: String },

    #[error("plugin {plugin} does not support operation {op}")]
    Unsupported { plugin: String, op: String },

    #[error("key {kid} not found")]
    KeyNotFound { kid: String },

    #[error("authentication required")]
    AuthRequired,

    #[error("authentication cancelled by user")]
    AuthCancelled,

    #[error("key migration requires re-enrollment")]
    ReEnrollmentRequired { kid: String },

    #[error("plugin error: {0}")]
    Plugin(String),

    #[error("callback error: {0}")]
    Callback(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    /// A CTAP2 PIN operation (set or use) was refused, either locally
    /// before anything was sent or by the authenticator. Never carries PIN
    /// material.
    #[error("PIN error: {0}")]
    Pin(PinFailure),

    /// The Android Keystore refused a key generation request that asked for
    /// StrongBox specifically because this device has none (or cannot use
    /// it right now) - `AndroidKeyStoreBackend.StrongBoxUnavailable` on the
    /// Kotlin side. Distinct from [`WscdError::Plugin`] so
    /// `AndroidKeystorePlugin::generate_key`'s StrongBox→TEE best-effort
    /// fallback can match on it specifically, rather than falling back on
    /// every error a `generate` callback could raise (a real key-generation
    /// failure in the TEE itself must surface, not be swallowed as "no
    /// StrongBox, try the TEE" and retried into a second, equally-failing
    /// attempt).
    #[cfg(feature = "plugin-android-keystore")]
    #[error("StrongBox is unavailable on this device")]
    StrongBoxUnavailable,
}

/// Why a PIN could not be set or used. Typed so a host can re-prompt with
/// the right message instead of parsing strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PinFailure {
    /// Fewer Unicode code points than the authenticator's `minPinLength`.
    /// Detected locally; nothing was sent to the authenticator.
    #[error("PIN is shorter than the authenticator's minimum of {min_length} characters")]
    TooShort { min_length: u32 },
    /// More than 63 bytes of UTF-8. Detected locally.
    #[error("PIN is longer than 63 bytes")]
    TooLong,
    /// Not valid UTF-8. Detected locally.
    #[error("PIN is not valid UTF-8")]
    InvalidEncoding,
    /// CTAP2_ERR_PIN_POLICY_VIOLATION (0x37): refused by the authenticator's
    /// PIN policy (e.g. too simple, or too short for a policy the platform
    /// could not see).
    #[error("PIN violates the authenticator's PIN policy")]
    PolicyViolation,
    /// CTAP2_ERR_PIN_INVALID (0x31): wrong PIN.
    #[error("PIN is incorrect")]
    Invalid,
    /// CTAP2_ERR_PIN_BLOCKED (0x32): too many wrong PINs; authenticator
    /// needs a reset.
    #[error("PIN is blocked")]
    Blocked,
    /// CTAP2_ERR_PIN_AUTH_BLOCKED (0x34): too many consecutive failures
    /// this power cycle; reconnect the authenticator.
    #[error("PIN entry is temporarily blocked; reconnect the authenticator")]
    AuthBlocked,
    /// CTAP2_ERR_PIN_NOT_SET (0x35): the authenticator has no PIN.
    #[error("the authenticator has no PIN set")]
    NotSet,
}

pub type Result<T> = std::result::Result<T, WscdError>;

impl From<PinFailure> for WscdError {
    fn from(f: PinFailure) -> Self {
        WscdError::Pin(f)
    }
}
