//! Convenience re-exports for common types.
//!
//! ```no_run
//! use didwebvh_rs::prelude::*;
//! ```
//!
//! The prelude intentionally re-exports third-party types (`Signer`,
//! `KeyType`, `Secret`, `async_trait`) directly from their source crates
//! rather than through the `didwebvh_rs` root. This keeps the top-level
//! public API small and forces downstream code that cares about
//! affinidi-data-integrity / affinidi-secrets-resolver version skew to see
//! those dependencies in its `Cargo.lock`.

pub use affinidi_data_integrity::signer::Signer;
pub use affinidi_secrets_resolver::secrets::{KeyType, Secret};
pub use async_trait::async_trait;

pub use crate::DIDWebVHError;
pub use crate::DIDWebVHState;
pub use crate::Multibase;
pub use crate::TruncationReason;
pub use crate::ValidationReport;
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
pub use crate::did_key::generate_did_key;
pub use crate::log_entry::LogEntryMethods;
pub use crate::parameters::Parameters;
#[cfg(feature = "network")]
pub use crate::resolve::ResolveOptions;
pub use crate::update::{UpdateDIDConfig, update_did};
pub use crate::witness::Witnesses;
pub use crate::witness::proofs::WitnessProofCollection;
