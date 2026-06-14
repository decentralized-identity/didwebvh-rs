/*!
*   Handling of witnessing changes to the log entries
*/

use affinidi_data_integrity::crypto_suites::CryptoSuite;

use crate::{DIDWebVHError, Multibase};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::SerializeStruct,
};
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

    /// Enforce the structural constraints from didwebvh 1.0 §"The Witness
    /// Proofs File" on a witness [`affinidi_data_integrity::DataIntegrityProof`]: the cryptosuite
    /// must be accepted (either the spec default `eddsa-jcs-2022` or a
    /// caller-opted-in extra) and `proofPurpose` must be `assertionMethod`.
    ///
    /// Cryptographic signature verification is intentionally NOT performed
    /// here — this is the cheap pre-check that runs before signature
    /// verification inside [`crate::log_entry::LogEntry::validate_witness_proof`].
    /// Expose it publicly so a caller doing its own witness plumbing can
    /// enforce the same shape constraints without going through a full
    /// `validate()` pass.
    pub fn check_proof_shape(
        &self,
        proof: &affinidi_data_integrity::DataIntegrityProof,
    ) -> Result<(), DIDWebVHError> {
        crate::log_entry::enforce_witness_proof_shape(proof, self)
    }
}

/// Witness nodes
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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
                // Reject duplicate witness IDs. validate_log_entry() iterates the
                // configured witness list and counts one match per entry, so a list
                // like [W1, W1, W1] with threshold 3 would let a single proof from
                // W1 satisfy the threshold — defeating the whole point of requiring
                // multiple independent witnesses.
                let mut seen = std::collections::HashSet::with_capacity(witnesses.len());
                for w in witnesses {
                    // Compare on the canonical `did:key:` form so that a bare
                    // multibase key and its `did:key:`-prefixed equivalent are
                    // recognized as the same witness (they serialize identically).
                    if !seen.insert(w.as_did()) {
                        return Err(DIDWebVHError::ValidationError(format!(
                            "Witness ({}) appears more than once in the witness list",
                            w.id
                        )));
                    }
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
///
/// Per didwebvh 1.0 § "Witnesses" the `id` of a witness MUST be a `did:key`
/// identifier (e.g. `did:key:z6Mk...`), NOT a bare multibase key. To guarantee
/// spec-compliant output regardless of how a caller constructs the value, the
/// `id` is canonicalized to `did:key:` form on both serialization and
/// deserialization (see the hand-written [`Serialize`]/[`Deserialize`] impls
/// below). Use [`Witness::new`] to build one with the same canonicalization.
///
/// Canonicalization is a no-op for an already-`did:key:` id, so logs produced
/// by spec-compliant implementations round-trip byte-for-byte and their
/// `entryHash` continues to verify.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Witness {
    /// `did:key` identifier of this witness node.
    pub id: Multibase,
}

impl Display for Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// Canonicalize a witness identifier to `did:key:` form.
///
/// A bare multibase key (`z6Mk...`) gets the `did:key:` prefix prepended; an
/// id that already starts with `did:key:` is returned unchanged.
fn canonicalize_witness_id(id: &str) -> String {
    if id.starts_with("did:key:") {
        id.to_string()
    } else {
        ["did:key:", id].concat()
    }
}

impl Serialize for Witness {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Always emit the spec-mandated `did:key:` form, even if `id` was
        // constructed from a bare multibase key via a struct literal.
        let mut state = serializer.serialize_struct("Witness", 1)?;
        state.serialize_field("id", &self.as_did())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Witness {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct RawWitness {
            id: String,
        }
        let raw = RawWitness::deserialize(deserializer)?;
        if raw.id.is_empty() {
            return Err(D::Error::custom("witness id must not be empty"));
        }
        Ok(Witness::new(raw.id))
    }
}

impl Witness {
    /// Construct a witness from any key identifier, canonicalizing it to the
    /// spec-mandated `did:key:` form.
    ///
    /// Accepts either a bare multibase key (`z6Mk...`, the `did:key:` prefix is
    /// prepended) or a full `did:key:z6Mk...` identifier (kept as-is).
    pub fn new(id: impl Into<String>) -> Self {
        Witness {
            id: Multibase::new(canonicalize_witness_id(&id.into())),
        }
    }

    /// Returns the witness ID as a `did:key:` DID.
    ///
    /// Handles both formats: if the stored ID already starts with `did:key:`,
    /// it is returned as-is; otherwise the prefix is prepended.
    pub fn as_did(&self) -> String {
        canonicalize_witness_id(self.id.as_str())
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

    /// Add a single witness by its key identifier.
    ///
    /// The id is canonicalized to `did:key:` form (a bare multibase key gets
    /// the `did:key:` prefix prepended).
    pub fn witness(mut self, id: Multibase) -> Self {
        self.witnesses.push(Witness::new(id.into_inner()));
        self
    }

    /// Add multiple witnesses from an iterator of key identifiers.
    ///
    /// Each id is canonicalized to `did:key:` form.
    pub fn witnesses(mut self, ids: impl IntoIterator<Item = Multibase>) -> Self {
        self.witnesses
            .extend(ids.into_iter().map(|id| Witness::new(id.into_inner())));
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

    /// Tests that a witness list containing the same witness ID more than once is
    /// rejected. Duplicates would otherwise let a single witness's proof be counted
    /// multiple times toward the threshold during validation.
    #[test]
    fn test_validate_duplicate_witnesses_error() {
        let w = Witnesses::Value {
            threshold: 2,
            witnesses: vec![
                Witness {
                    id: Multibase::new("w1"),
                },
                Witness {
                    id: Multibase::new("w1"),
                },
            ],
        };
        let err = w.validate().unwrap_err();
        assert!(err.to_string().contains("more than once"));
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

    /// Issue #42: a `Witness` built from a bare multibase key must serialize
    /// its `id` as a `did:key:` identifier (spec § "Witnesses"), not the raw
    /// multikey.
    #[test]
    fn test_witness_serializes_id_as_did_key() {
        let w = Witness {
            id: Multibase::new("z6Mkrv5Cm2XCLumMPTqooLTCw6YDf421d7VdTziwrZ8vNf4L"),
        };
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(
            json,
            r#"{"id":"did:key:z6Mkrv5Cm2XCLumMPTqooLTCw6YDf421d7VdTziwrZ8vNf4L"}"#
        );
    }

    /// An already-`did:key:` id serializes unchanged (no double prefix), so
    /// spec-compliant logs round-trip byte-for-byte and `entryHash` still verifies.
    #[test]
    fn test_witness_did_key_id_serializes_unchanged() {
        let w = Witness::new("did:key:z6Mktest");
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, r#"{"id":"did:key:z6Mktest"}"#);
    }

    /// Deserializing canonicalizes a bare multibase id to `did:key:` form, and
    /// the value then round-trips stably.
    #[test]
    fn test_witness_deserialize_canonicalizes_raw_id() {
        let w: Witness = serde_json::from_str(r#"{"id":"z6Mktest"}"#).unwrap();
        assert_eq!(w.id.as_str(), "did:key:z6Mktest");
        // Re-serialize is stable.
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, r#"{"id":"did:key:z6Mktest"}"#);
    }

    /// An empty witness id is rejected at deserialization.
    #[test]
    fn test_witness_deserialize_rejects_empty_id() {
        let err = serde_json::from_str::<Witness>(r#"{"id":""}"#).unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    /// `Witness::new` canonicalizes both bare and prefixed ids.
    #[test]
    fn test_witness_new_canonicalizes() {
        assert_eq!(Witness::new("z6Mktest").id.as_str(), "did:key:z6Mktest");
        assert_eq!(
            Witness::new("did:key:z6Mktest").id.as_str(),
            "did:key:z6Mktest"
        );
    }

    /// A bare multibase witness and its `did:key:`-prefixed equivalent are
    /// treated as duplicates (they serialize identically).
    #[test]
    fn test_validate_duplicate_witnesses_mixed_form_error() {
        let w = Witnesses::Value {
            threshold: 1,
            witnesses: vec![
                Witness {
                    id: Multibase::new("z6Mktest"),
                },
                Witness {
                    id: Multibase::new("did:key:z6Mktest"),
                },
            ],
        };
        let err = w.validate().unwrap_err();
        assert!(err.to_string().contains("more than once"));
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
