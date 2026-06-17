pub mod callbacks;
pub mod config;
pub mod error;
pub mod ffi;
pub mod manager;
pub mod plugins;
pub mod traits;
pub mod types;

uniffi::setup_scaffolding!();

pub use callbacks::{AuthCallback, Ctap2Transport, NoopProgress, ProgressCallback};
pub use config::WscdConfig;
pub use error::{Result, WscdError};
pub use manager::WscdManager;
pub use traits::WscdPlugin;
pub use types::{
    Algorithm, AttestationChain, AuthMethod, CertificationLevel, GeneratedKey, KeyId, KeyInfo,
    KeyStorageType, MigrationResult, OperationProgress, Secret, SecurityProperties, Signature,
};
