/*!
*   Handling of witnessing changes to the log entries
*/

use affinidi_data_integrity::crypto_suites::CryptoSuite;

use crate::{DIDWebVHError, Multibase};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

pub mod proofs;
pub mod validate;

/// Runtime options for verifying witness proofs.
///
/// didwebvh 1.0 §"The Witness Proofs File" mandates that witness Data
/// Integrity proofs use the `eddsa-jcs-2022` cryptosuite with
/// `proofPurpose` of `assertionMethod`. `WitnessVerifyOptions` lets a
/// caller additively widen the accepted cryptosuite set (for example, to
/// interop with a non-spec implementation that emits PQC-signed witness
/// proofs) without forcing a feature-flag rebuild.
///
/// `#[non_exhaustive]` so future fields (e.g. expiry windows, allowed
/// `proofPurpose` values) don't break callers.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct WitnessVerifyOptions {
    /// Cryptosuites accepted for witness proofs in addition to the spec
    /// default `eddsa-jcs-2022`. Empty by default — strict spec mode.
    pub extra_allowed_suites: Vec<CryptoSuite>,
}

impl WitnessVerifyOptions {
    /// Strict spec-compliant defaults (only `eddsa-jcs-2022`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a cryptosuite to the accepted list.
    #[must_use]
    pub fn with_extra_allowed_suite(mut self, suite: CryptoSuite) -> Self {
        self.extra_allowed_suites.push(suite);
        self
    }

    /// Returns true if the supplied suite is accepted under these options.
    ///
    /// Checks the spec-mandated `eddsa-jcs-2022` first, then any additional
    /// suites the caller opted into.
    pub fn suite_is_allowed(&self, suite: CryptoSuite) -> bool {
        suite == CryptoSuite::EddsaJcs2022 || self.extra_allowed_suites.contains(&suite)
    }
}

/// Witness nodes
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum Witnesses {
    /// Active witness configuration with a threshold and list of witness nodes.
    Value {
        /// Minimum number of witness proofs required for acceptance.
        threshold: u32,
        /// List of configured witness nodes.
        witnesses: Vec<Witness>,
    },
    // WARN: This must always go last, otherwise it will become the default as it matches on
    // anything
    /// No witnesses are configured.
    Empty {},
}

impl Witnesses {
    /// Create a new [`WitnessesBuilder`] for constructing a [`Witnesses`] value.
    pub fn builder() -> WitnessesBuilder {
        WitnessesBuilder {
            threshold: 1,
            witnesses: Vec::new(),
        }
    }

    /// Are any witnesses configured?
    pub fn is_empty(&self) -> bool {
        match self {
            Witnesses::Empty {} => true,
            Witnesses::Value { witnesses, .. } => witnesses.is_empty(),
        }
    }

    /// Checks Witnesses parameters for errors
    pub fn validate(&self) -> Result<(), DIDWebVHError> {
        if self.is_empty() {
            return Err(DIDWebVHError::ValidationError(
                "Witnesses are enabled, but no witness nodes are specified! Can not be empty!"
                    .to_string(),
            ));
        }

        match self {
            Witnesses::Value {
                threshold,
                witnesses,
            } => {
                if threshold < &1 {
                    return Err(DIDWebVHError::ValidationError(
                        "Witness threshold must be 1 or more".to_string(),
                    ));
                } else if witnesses.len() < *threshold as usize {
                    return Err(DIDWebVHError::ValidationError(format!(
                        "Number of Witnesses ({}) is less than the threshold ({})",
                        witnesses.len(),
                        threshold
                    )));
                }
            }
            _ => {
                return Err(DIDWebVHError::ValidationError(
                    "Empty Witness Parameter config found, but it wasn't detected. INTERNAL ERROR STATE"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Returns witnesses if they exist
    pub fn witnesses(&self) -> Option<&[Witness]> {
        match self {
            Witnesses::Empty {} => None,
            Witnesses::Value { witnesses, .. } => Some(witnesses),
        }
    }

    /// Returns threshold if it exists
    pub fn threshold(&self) -> Option<u32> {
        match self {
            Witnesses::Empty {} => None,
            Witnesses::Value { threshold, .. } => Some(*threshold),
        }
    }
}

/// Single Witness Node
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Witness {
    /// Multibase-encoded public key identifying this witness node.
    pub id: Multibase,
}

impl Display for Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl Witness {
    /// Returns the witness ID as a `did:key:` DID.
    ///
    /// Handles both formats: if the stored ID already starts with `did:key:`,
    /// it is returned as-is; otherwise the prefix is prepended.
    pub fn as_did(&self) -> String {
        let id = self.id.as_str();
        if id.starts_with("did:key:") {
            id.to_string()
        } else {
            ["did:key:", id].concat()
        }
    }

    /// Returns the witness ID as a `did:key:z6...#z6...` verification method reference.
    ///
    /// The fragment is the raw multibase key (without the `did:key:` prefix).
    pub fn as_did_key(&self) -> String {
        let did = self.as_did();
        let raw_key = did.strip_prefix("did:key:").unwrap_or(did.as_str());
        [&did, "#", raw_key].concat()
    }
}

/// Builder for constructing a [`Witnesses`] configuration.
///
/// Defaults to a threshold of 1. Use [`build()`](Self::build) to validate
/// and produce the final [`Witnesses`] value.
pub struct WitnessesBuilder {
    threshold: u32,
    witnesses: Vec<Witness>,
}

impl WitnessesBuilder {
    /// Set the minimum number of witness proofs required.
    pub fn threshold(mut self, t: u32) -> Self {
        self.threshold = t;
        self
    }

    /// Add a single witness by its multibase-encoded public key.
    pub fn witness(mut self, id: Multibase) -> Self {
        self.witnesses.push(Witness { id });
        self
    }

    /// Add multiple witnesses from an iterator of multibase-encoded public keys.
    pub fn witnesses(mut self, ids: impl IntoIterator<Item = Multibase>) -> Self {
        self.witnesses
            .extend(ids.into_iter().map(|id| Witness { id }));
        self
    }

    /// Build and validate the [`Witnesses`] configuration.
    ///
    /// Returns an error if the threshold is zero or exceeds the number of witnesses.
    pub fn build(self) -> Result<Witnesses, DIDWebVHError> {
        let w = Witnesses::Value {
            threshold: self.threshold,
            witnesses: self.witnesses,
        };
        w.validate()?;
        Ok(w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Multibase;

    /// Tests that validating an empty `Witnesses::Empty` variant returns an error.
    ///
    /// When witness configuration is explicitly enabled but contains no witness nodes,
    /// validation must fail. This prevents a DID WebVH log from claiming witness support
    /// while having no actual witnesses to attest to log entry changes.
    #[test]
    fn test_validate_empty_error() {
        let w = Witnesses::Empty {};
        assert!(w.validate().is_err());
    }

    /// Tests that a threshold of zero is rejected during validation.
    ///
    /// Even when witness nodes are present, a threshold of zero would mean no witness
    /// signatures are required, effectively bypassing the witness mechanism entirely.
    /// DID WebVH requires a threshold of at least 1 to ensure that witness attestation
    /// is meaningful and provides actual security guarantees.
    #[test]
    fn test_validate_threshold_zero_error() {
        let w = Witnesses::Value {
            threshold: 0,
            witnesses: vec![Witness {
                id: Multibase::new("w1"),
            }],
        };
        assert!(w.validate().is_err());
    }

    /// Tests that validation fails when the threshold exceeds the number of witnesses.
    ///
    /// If the threshold is higher than the available witness count, it becomes impossible
    /// to ever collect enough witness proofs to satisfy the requirement. This would make
    /// the DID permanently unable to process new log entries, so it must be caught early
    /// during configuration validation.
    #[test]
    fn test_validate_threshold_exceeds_witnesses_error() {
        let w = Witnesses::Value {
            threshold: 3,
            witnesses: vec![Witness {
                id: Multibase::new("w1"),
            }],
        };
        let err = w.validate().unwrap_err();
        assert!(err.to_string().contains("less than the threshold"));
    }

    /// Tests that a valid witness configuration passes validation successfully.
    ///
    /// A configuration with a threshold of 1 and one witness node represents the
    /// simplest valid witness setup. This confirms that well-formed configurations
    /// are accepted, ensuring DID WebVH log entries can proceed with proper witness
    /// attestation.
    #[test]
    fn test_validate_ok() {
        let w = Witnesses::Value {
            threshold: 1,
            witnesses: vec![Witness {
                id: Multibase::new("w1"),
            }],
        };
        assert!(w.validate().is_ok());
    }

    /// Tests the `witnesses()` and `threshold()` accessor methods for both variants.
    ///
    /// The `Empty` variant must return `None` for both accessors, while the `Value`
    /// variant must return the configured witness list and threshold. Callers depend
    /// on these accessors to inspect witness parameters when constructing and verifying
    /// DID WebVH log entries, so correct behavior for both variants is essential.
    #[test]
    fn test_witnesses_accessors() {
        let empty = Witnesses::Empty {};
        assert!(empty.witnesses().is_none());
        assert!(empty.threshold().is_none());

        let value = Witnesses::Value {
            threshold: 2,
            witnesses: vec![
                Witness {
                    id: Multibase::new("w1"),
                },
                Witness {
                    id: Multibase::new("w2"),
                },
            ],
        };
        assert_eq!(value.witnesses().unwrap().len(), 2);
        assert_eq!(value.threshold(), Some(2));
    }

    /// Tests `as_did()` with a raw multibase key (prepends `did:key:` prefix).
    #[test]
    fn test_witness_as_did_from_raw_key() {
        let w = Witness {
            id: Multibase::new("z6Mktest"),
        };
        assert_eq!(w.as_did(), "did:key:z6Mktest");
    }

    /// Tests `as_did()` with a full `did:key:` DID (returns as-is, no double prefix).
    #[test]
    fn test_witness_as_did_from_full_did() {
        let w = Witness {
            id: Multibase::new("did:key:z6Mktest"),
        };
        assert_eq!(w.as_did(), "did:key:z6Mktest");
    }

    /// Tests `as_did_key()` with a raw multibase key.
    #[test]
    fn test_witness_as_did_key_from_raw_key() {
        let w = Witness {
            id: Multibase::new("z6Mktest"),
        };
        assert_eq!(w.as_did_key(), "did:key:z6Mktest#z6Mktest");
    }

    /// Tests `as_did_key()` with a full `did:key:` DID (extracts raw key for fragment).
    #[test]
    fn test_witness_as_did_key_from_full_did() {
        let w = Witness {
            id: Multibase::new("did:key:z6Mktest"),
        };
        assert_eq!(w.as_did_key(), "did:key:z6Mktest#z6Mktest");
    }

    /// Tests the `Display` trait implementation for `Witness`.
    ///
    /// The display output should be the raw witness ID (the multibase-encoded public key)
    /// without any DID prefix. This is important for logging, debugging, and serialization
    /// contexts where the compact identifier form is preferred over the full DID URI.
    #[test]
    fn test_witness_display() {
        let w = Witness {
            id: Multibase::new("z6Mktest"),
        };
        assert_eq!(format!("{}", w), "z6Mktest");
    }

    /// Tests the `is_empty()` method across all meaningful states.
    ///
    /// Covers three cases: the `Empty` variant (always empty), a `Value` variant with
    /// an empty witness list (logically empty despite being the `Value` variant), and a
    /// `Value` variant with witnesses (not empty). Correctly detecting emptiness is
    /// critical because DID WebVH validation logic uses `is_empty()` as a guard before
    /// performing witness-related checks on log entries.
    #[test]
    fn test_is_empty() {
        assert!(Witnesses::Empty {}.is_empty());
        assert!(
            Witnesses::Value {
                threshold: 0,
                witnesses: vec![]
            }
            .is_empty()
        );
        assert!(
            !Witnesses::Value {
                threshold: 1,
                witnesses: vec![Witness {
                    id: Multibase::new("w1")
                }],
            }
            .is_empty()
        );
    }

    // ===== WitnessesBuilder tests =====

    #[test]
    fn builder_valid_single_witness() {
        let w = Witnesses::builder()
            .threshold(1)
            .witness(Multibase::new("z6Mktest"))
            .build();
        assert!(w.is_ok());
        let w = w.unwrap();
        assert_eq!(w.threshold(), Some(1));
        assert_eq!(w.witnesses().unwrap().len(), 1);
    }

    #[test]
    fn builder_valid_multiple_witnesses() {
        let w = Witnesses::builder()
            .threshold(2)
            .witnesses(vec![
                Multibase::new("z6Mk1"),
                Multibase::new("z6Mk2"),
                Multibase::new("z6Mk3"),
            ])
            .build();
        assert!(w.is_ok());
        assert_eq!(w.unwrap().witnesses().unwrap().len(), 3);
    }

    #[test]
    fn builder_threshold_zero_error() {
        let result = Witnesses::builder()
            .threshold(0)
            .witness(Multibase::new("z6Mk1"))
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_threshold_exceeds_witnesses_error() {
        let result = Witnesses::builder()
            .threshold(3)
            .witness(Multibase::new("z6Mk1"))
            .build();
        assert!(result.is_err());
    }
}
