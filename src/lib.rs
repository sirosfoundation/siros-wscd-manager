pub mod callbacks;
pub mod config;
pub mod error;
#[cfg(feature = "native")]
pub mod ffi;
pub mod manager;
pub mod plugins;
pub mod traits;
pub mod types;
#[cfg(feature = "wasm")]
pub mod wasm_ffi;

#[cfg(feature = "native")]
uniffi::setup_scaffolding!();

pub use callbacks::{AuthCallback, Ctap2Transport, NoopProgress, ProgressCallback};
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
