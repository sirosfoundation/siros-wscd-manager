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
}

pub type Result<T> = std::result::Result<T, WscdError>;
