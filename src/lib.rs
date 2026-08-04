pub mod callbacks;
pub mod config;
pub mod error;
#[cfg(all(feature = "native", not(feature = "wasm")))]
pub mod ffi;
pub mod manager;
pub mod plugins;
#[cfg(feature = "plugin-fido2")]
pub mod preview_sign_protocol;
mod timeutil;
pub mod traits;
pub mod types;
#[cfg(feature = "wasm")]
pub mod wasm_ffi;
#[cfg(feature = "wasm")]
pub mod wasm_fido2;

#[cfg(all(feature = "native", not(feature = "wasm")))]
uniffi::setup_scaffolding!();

#[cfg(feature = "plugin-fido2")]
pub use callbacks::Ctap2Transport;
pub use callbacks::{AuthCallback, NoopProgress, ProgressCallback};
pub use config::WscdConfig;
pub use error::{Result, WscdError};
pub use manager::WscdManager;
pub use traits::WscdPlugin;
pub use types::{
    ActivateLifecycleRequest, ActivationOutcome, Algorithm, AttestationChain, AuthMethod,
    CertificationLevel, DestroyLifecycleRequest, DestroyMode, DestructionOutcome, FactorKind,
    GeneratedKey, KeyId, KeyInfo, KeyStorageType, LifecycleState, LifecycleStatus, MigrationResult,
    OperationProgress, RegisterLifecycleRequest, RegistrationOutcome, RotateLifecycleRequest,
    RotationOutcome, Secret, SecurityProperties, Signature,
};
