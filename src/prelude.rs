//! Convenience re-exports for common types.
//!
//! ```
//! use didwebvh_rs::prelude::*;
//! ```

pub use crate::DIDWebVHError;
pub use crate::DIDWebVHState;
pub use crate::create::{CreateDIDConfig, create_did};
pub use crate::log_entry::LogEntryMethods;
pub use crate::parameters::Parameters;
pub use crate::witness::Witnesses;
pub use crate::witness::proofs::WitnessProofCollection;
