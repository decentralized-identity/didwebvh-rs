/*!
*   Handling of witnessing changes to the log entries
*/

use crate::{DIDWebVHError, Multibase};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

pub mod proofs;
pub mod validate;

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
    /// Returns the witness ID as a did:key
    /// Use [`Self::as_did_key`] if you want the DID#Key value
    pub fn as_did(&self) -> String {
        ["did:key:", self.id.as_str()].concat()
    }

    /// Returns the witness ID as a did:key:z6...#z6...
    /// Use [`Self::as_did`] if you want just the base DID
    pub fn as_did_key(&self) -> String {
        [&self.as_did(), "#", self.id.as_str()].concat()
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

    /// Tests that `as_did()` correctly formats a witness ID as a `did:key:` DID.
    ///
    /// Witness nodes are identified by their public key multibase encoding. The
    /// `as_did()` method prepends the `did:key:` prefix to produce a valid DID
    /// identifier. This is used when referencing witnesses in DID WebVH log entries
    /// and during proof verification.
    #[test]
    fn test_witness_as_did() {
        let w = Witness {
            id: Multibase::new("z6Mktest"),
        };
        assert_eq!(w.as_did(), "did:key:z6Mktest");
    }

    /// Tests that `as_did_key()` formats a witness ID as a full `did:key:` DID with fragment.
    ///
    /// The full DID key format (`did:key:z6...#z6...`) is required when referencing
    /// specific verification methods in DID documents. Witness proof verification uses
    /// this format to identify the exact key that produced a signature, linking the
    /// proof back to the correct witness node.
    #[test]
    fn test_witness_as_did_key() {
        let w = Witness {
            id: Multibase::new("z6Mktest"),
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
}
