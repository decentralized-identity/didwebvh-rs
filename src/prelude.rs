//! Convenience re-exports for common types.
//!
//! ```
//! use didwebvh_rs::prelude::*;
//! ```

pub use crate::DIDWebVHError;
pub use crate::DIDWebVHState;
pub use crate::KeyType;
pub use crate::Multibase;
pub use crate::Signer;
pub use crate::async_trait;
#[cfg(feature = "cli")]
pub use crate::cli_create::{
    InteractiveCreateConfig, InteractiveCreateResult, interactive_create_did,
};
#[cfg(feature = "cli")]
pub use crate::cli_update::{
    InteractiveUpdateConfig, InteractiveUpdateResult, UpdateOperation, UpdateSecrets,
    interactive_update_did,
};
pub use crate::create::{CreateDIDConfig, create_did};
pub use crate::log_entry::LogEntryMethods;
pub use crate::parameters::Parameters;
#[cfg(feature = "network")]
pub use crate::resolve::ResolveOptions;
pub use crate::update::{UpdateDIDConfig, update_did};
pub use crate::witness::Witnesses;
pub use crate::witness::proofs::WitnessProofCollection;
