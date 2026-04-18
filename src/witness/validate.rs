/*!
*   Validating LogEntries using Witness Proofs
*
*   # Witness proof version semantics
*
*   A witness proof attests that a witness observed a particular version of the DID log.
*   During validation, proofs are matched against log entries with the following rules:
*
*   - **Future proofs** (proof version > highest published version) are **skipped** entirely,
*     preventing premature acceptance of proofs for unpublished entries.
*   - **Older proofs** (proof version > current entry version, but within published range)
*     **still count** toward the threshold. This supports efficient batched witnessing
*     where a single proof covers a range of entries.
*   - **Current proofs** (proof version == current entry version) are **cryptographically
*     verified** against the log entry data before counting.
*
*   This design means a resolver cannot be tricked by proofs referencing unpublished
*   future entries, while still allowing witnesses to attest in batches rather than
*   per-entry.
*/

use crate::{
    DIDWebVHError, log_entry_state::LogEntryState, witness::proofs::WitnessProofCollection,
};
use tracing::{debug, warn};

impl WitnessProofCollection {
    /// Validates if a LogEntry was correctly witnessed
    /// highest_version_number is required so we don't mistakenly use future witness proofs
    /// for unpublished LogEntries
    pub fn validate_log_entry(
        &mut self,
        log_entry: &LogEntryState,
        highest_version_number: u32,
    ) -> Result<(), DIDWebVHError> {
        // Determine witnesses for this LogEntry
        let Some(witnesses) = &log_entry.validated_parameters.active_witness else {
            // There are no active witnesses for this LogEntry
            return Ok(());
        };

        let Some(witness_nodes) = witnesses.witnesses() else {
            // There are no active witnesses for this LogEntry
            return Ok(());
        };

        // Get the version_number for this LogEntry
        let version_number = log_entry.log_entry.get_version_id_fields()?.0;

        // For each witness, check if there is a proof available
        let mut valid_proofs = 0;
        for w in witness_nodes {
            let did_key_vm = w.as_did_key();
            let Some((_, oldest_id, proof)) = self.witness_version.get(&did_key_vm) else {
                // No proof available for this witness, threshold will catch if too few proofs
                debug!("No Witness proofs exist for witness ({})", w.id);
                continue;
            };

            debug!(
                "oldest_id ({}) >  highest_version_number ({})",
                oldest_id, highest_version_number
            );
            if oldest_id > &highest_version_number {
                // This proof is for a future LogEntry, skip it
                debug!(
                    "LogEntry ({}): Skipping witness proof from {} (oldest: {oldest_id}, highest: {})",
                    log_entry.get_version_id(),
                    w.id,
                    highest_version_number
                );
                continue;
            }

            debug!(
                "oldest_id ({}) >  version_number ({})",
                oldest_id, version_number
            );
            if oldest_id > &version_number {
                // This proof is older than the current LogEntry, skip it
                debug!(
                    "LogEntry ({}): Skipping witness proof from {} (oldest: {oldest_id})",
                    log_entry.get_version_id(),
                    w.id,
                );
                // Still counts as a valid proof
                valid_proofs += 1;
                continue;
            } else {
                // witness proof is for this verion of the LogEntry
                // Validate the LogEntry against the proof
                log_entry
                    .log_entry
                    .validate_witness_proof(proof)
                    .map_err(|e| {
                        DIDWebVHError::WitnessProofError(format!(
                            "LogEntry ({}): Witness proof validation failed: {}",
                            log_entry.get_version_id(),
                            e
                        ))
                    })?;
                valid_proofs += 1;
                debug!(
                    "LogEntry ({}): Witness proof ({}) verified ok",
                    log_entry.get_version_id(),
                    w.id
                );
            }
        }

        let Some(threshold) = witnesses.threshold() else {
            // No threshold set, so we consider this as a state error
            return Err(DIDWebVHError::ValidationError(
                "Witness threshold not defined when witnessing seems to be enabled!".to_string(),
            ));
        };

        if valid_proofs < threshold {
            // Not enough valid proofs to consider this LogEntry as witnessed
            warn!(
                "LogEntry ({}): Witness threshold ({threshold}) not met. Only ({valid_proofs} valid proofs!",
                log_entry.get_version_id(),
            );
            Err(DIDWebVHError::WitnessProofError(format!(
                "Witness proof threshold ({threshold}) was not met. Only ({valid_proofs}) proofs were validated",
            )))
        } else {
            debug!(
                "LogEntry ({}): Witness proofs fully passed",
                log_entry.get_version_id()
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
    use chrono::Utc;
    use serde_json::json;

    use crate::{
        Multibase,
        log_entry::{LogEntry, spec_1_0::LogEntry1_0},
        log_entry_state::{LogEntryState, LogEntryValidationStatus},
        parameters::{Parameters, spec_1_0::Parameters1_0},
        witness::proofs::WitnessProofCollection,
        witness::{Witness, Witnesses},
    };

    /// Tests that validation succeeds when `active_witness` is `None`.
    ///
    /// This represents the case where no witness configuration exists at all in the
    /// DID document parameters. The `active_witness` field is `None`, meaning
    /// witnessing was never configured for this DID. Validation should return `Ok`
    /// immediately because there is nothing to verify.
    ///
    /// This matters for DID WebVH because witnessing is optional. DIDs that do not
    /// use witnesses must still pass validation without error.
    #[test]
    fn test_no_witnesses_configured() {
        let mut proofs = WitnessProofCollection::default();

        let log_entry = LogEntryState {
            version_number: 1,
            log_entry: LogEntry::Spec1_0(LogEntry1_0 {
                proof: vec![],
                parameters: Parameters1_0::default(),
                version_id: "1-abcd".to_string(),
                version_time: Utc::now().fixed_offset(),
                state: json!({}),
            }),
            validated_parameters: Parameters {
                active_witness: None,
                ..Default::default()
            },
            validation_status: LogEntryValidationStatus::Ok,
        };

        proofs
            .validate_log_entry(&log_entry, 1)
            .expect("Couldn't validate witness proofs");
    }

    /// Creates a `LogEntryState` pre-configured with a given witness setup.
    ///
    /// Parses the version number from the `version_id` string (e.g. "3-hash" yields
    /// version number 3). The resulting entry has empty proofs, default parameters
    /// (aside from `active_witness`), and an `Ok` validation status. This helper
    /// exists so individual tests can focus on witness validation logic without
    /// duplicating `LogEntryState` construction boilerplate.
    fn make_witnessed_entry(version_id: &str, witnesses: Witnesses) -> LogEntryState {
        LogEntryState {
            version_number: version_id
                .split_once('-')
                .map(|(n, _)| n.parse().unwrap())
                .unwrap_or(1),
            log_entry: LogEntry::Spec1_0(LogEntry1_0 {
                proof: vec![],
                parameters: Parameters1_0::default(),
                version_id: version_id.to_string(),
                version_time: Utc::now().fixed_offset(),
                state: json!({}),
            }),
            validated_parameters: Parameters {
                active_witness: Some(Arc::new(witnesses)),
                ..Default::default()
            },
            validation_status: LogEntryValidationStatus::Ok,
        }
    }

    /// Tests that validation succeeds when `active_witness` is `Some(Witnesses::Empty{})`.
    ///
    /// Unlike `test_no_witnesses_configured` where `active_witness` is `None` (witnessing
    /// was never configured), here `active_witness` is `Some` but wraps the
    /// `Witnesses::Empty{}` variant. This means a witness parameter was present in the
    /// DID log but contained no actual witness nodes. The `witnesses()` method on
    /// `Witnesses::Empty{}` returns `None`, so validation exits early with `Ok`.
    ///
    /// This distinction matters because `None` vs `Some(Empty)` represent different
    /// states in the DID document lifecycle: `None` means witnessing is entirely absent,
    /// while `Some(Empty)` means a witness block existed but was empty (e.g. witnesses
    /// were cleared in a parameter update). Both must pass validation, but through
    /// different code paths.
    #[test]
    fn test_witnesses_empty_variant_returns_ok() {
        let mut proofs = WitnessProofCollection::default();
        let entry = make_witnessed_entry("1-abcd", Witnesses::Empty {});
        // Witnesses::Empty{} → witnesses() returns None → returns Ok
        proofs
            .validate_log_entry(&entry, 1)
            .expect("Empty witnesses should return Ok");
    }

    /// Tests that validation fails when witness proofs are missing for configured witnesses.
    ///
    /// Two witnesses are configured with a threshold of 1, but no proofs are added to
    /// the `WitnessProofCollection`. Because zero valid proofs is below the threshold,
    /// validation must return a threshold error.
    ///
    /// This matters for DID WebVH because it ensures that a resolver cannot accept a
    /// log entry as valid when the required witness attestations are absent.
    #[test]
    fn test_witness_proof_missing_for_witness() {
        let mut proofs = WitnessProofCollection::default();
        let witnesses = Witnesses::Value {
            threshold: 1,
            witnesses: vec![
                Witness {
                    id: Multibase::new("z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7lL8N8AC4Pp6"),
                },
                Witness {
                    id: Multibase::new("z6MkqUa1LbqZ7EpevqrFC7XHAWM8CE49AKFWVjyu543NfVAp"),
                },
            ],
        };
        let entry = make_witnessed_entry("1-abcd", witnesses);
        // No proofs added — threshold is 1, so this should fail
        let err = proofs.validate_log_entry(&entry, 1).unwrap_err();
        assert!(err.to_string().contains("threshold"));
    }

    /// Tests that witness proofs referencing a future log entry version are skipped.
    ///
    /// A proof is added for version 5 but the `highest_version_number` is 1. The
    /// validation logic detects that the proof's `oldest_id` exceeds the highest
    /// published version and skips it. With no remaining valid proofs, the threshold
    /// of 1 is not met and validation fails.
    ///
    /// This matters for DID WebVH because it prevents premature acceptance of witness
    /// proofs that attest to log entries not yet published, which could be used in a
    /// replay or pre-computation attack.
    #[test]
    fn test_witness_proof_from_future_skipped() {
        use crate::test_utils::make_test_proof;
        let mut proofs = WitnessProofCollection::default();
        let raw_key = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7lL8N8AC4Pp6";
        let witness_id = format!("did:key:{raw_key}");
        let vm = format!("{witness_id}#{raw_key}");
        let proof = make_test_proof(&vm);
        // Add proof for version 5 (future relative to highest_version_number=1)
        proofs.add_proof("5-future", &proof, false).unwrap();

        let witnesses = Witnesses::Value {
            threshold: 1,
            witnesses: vec![Witness {
                id: Multibase::new(&witness_id),
            }],
        };
        let entry = make_witnessed_entry("1-abcd", witnesses);
        // highest_version_number=1, proof is for version 5 → skipped → threshold not met
        let err = proofs.validate_log_entry(&entry, 1).unwrap_err();
        assert!(err.to_string().contains("threshold"));
    }

    /// Tests that a witness proof for a version newer than the current entry still
    /// counts as valid when it is within the published range.
    ///
    /// A proof is added for version 3. The current entry is version 1 and the
    /// `highest_version_number` is 5. Because `oldest_id` (3) is within the published
    /// range (at most 5) but is greater than the current version (1), the proof takes
    /// the "older proof" branch and is counted as valid. The threshold of 1 is met.
    ///
    /// This matters for DID WebVH because witness proofs may cover a range of versions.
    /// A proof attesting to a later (but still published) version should still satisfy
    /// the witness requirement for earlier entries, supporting efficient batched
    /// witnessing.
    #[test]
    fn test_witness_proof_older_than_current_counts() {
        use crate::test_utils::make_test_proof;
        let mut proofs = WitnessProofCollection::default();
        let raw_key = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7lL8N8AC4Pp6";
        let witness_id = format!("did:key:{raw_key}");
        let vm = format!("{witness_id}#{raw_key}");
        let proof = make_test_proof(&vm);
        // Add proof for version 3 — version_number is 1, oldest_id (3) > version_number (1)
        // But oldest_id (3) <= highest_version_number (5) → still counts as valid
        proofs.add_proof("3-hash", &proof, false).unwrap();

        let witnesses = Witnesses::Value {
            threshold: 1,
            witnesses: vec![Witness {
                id: Multibase::new(&witness_id),
            }],
        };
        let entry = make_witnessed_entry("1-abcd", witnesses);
        // highest_version_number=5, proof is for version 3
        // oldest_id(3) <= highest(5) but oldest_id(3) > version_number(1) → counts as valid
        proofs
            .validate_log_entry(&entry, 5)
            .expect("Older proof should still count as valid");
    }

    /// Tests the happy path where a valid, cryptographically signed witness proof
    /// meets the configured threshold.
    ///
    /// A real Ed25519 key pair is generated, a proof is signed over the log entry
    /// data, and added to the collection. With one valid proof and a threshold of 1,
    /// validation succeeds. This is the only test that exercises the actual
    /// `validate_witness_proof` signature verification path.
    ///
    /// This matters for DID WebVH because it validates the end-to-end witness proof
    /// flow: key generation, proof signing, proof storage, lookup, cryptographic
    /// verification, and threshold checking.
    #[tokio::test]
    async fn test_witness_threshold_met() {
        let mut proofs = WitnessProofCollection::default();
        // Use a real signing key for the witness proof
        let secret = affinidi_secrets_resolver::secrets::Secret::generate_ed25519(None, None);
        let pk = secret.get_public_keymultibase().unwrap();

        // Set the secret id so the signed proof's verification_method matches
        // the lookup key format: "did:key:{pk}#{pk}"
        let mut witness_secret = secret.clone();
        witness_secret.id = format!("did:key:{pk}#{pk}");

        let signed_proof = DataIntegrityProof::sign(
            &json!({"versionId": "1-abcd"}),
            &witness_secret,
            SignOptions::new(),
        )
        .await
        .unwrap();
        proofs.add_proof("1-abcd", &signed_proof, false).unwrap();

        // The validate_log_entry lookup key is: w.id + "#" + w.id[8..]
        // With w.id = "did:key:{pk}", split_at(8) gives ("did:key:", pk)
        // So lookup = "did:key:{pk}" + "#" + pk = "did:key:{pk}#{pk}" ✓
        let witness_id = format!("did:key:{pk}");
        let witnesses = Witnesses::Value {
            threshold: 1,
            witnesses: vec![Witness {
                id: Multibase::new(witness_id),
            }],
        };
        let entry = make_witnessed_entry("1-abcd", witnesses);

        proofs
            .validate_log_entry(&entry, 1)
            .expect("Threshold should be met");
    }

    /// Tests that validation fails when the number of valid proofs is below the
    /// configured threshold.
    ///
    /// Two witnesses are configured with a threshold of 2, but no proofs are provided.
    /// With zero valid proofs, the threshold check fails and a `WitnessProofError` is
    /// returned containing the word "threshold".
    ///
    /// This matters for DID WebVH because the threshold mechanism is a core security
    /// property: it ensures that a minimum number of independent witnesses must attest
    /// to a log entry before it is considered valid.
    #[test]
    fn test_witness_threshold_not_met() {
        let mut proofs = WitnessProofCollection::default();
        let witnesses = Witnesses::Value {
            threshold: 2,
            witnesses: vec![
                Witness {
                    id: Multibase::new("z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7lL8N8AC4Pp6"),
                },
                Witness {
                    id: Multibase::new("z6MkqUa1LbqZ7EpevqrFC7XHAWM8CE49AKFWVjyu543NfVAp"),
                },
            ],
        };
        let entry = make_witnessed_entry("1-abcd", witnesses);
        // No proofs → 0 valid, threshold is 2
        let err = proofs.validate_log_entry(&entry, 1).unwrap_err();
        assert!(err.to_string().contains("threshold"));
    }

    /// Tests the edge case where a threshold of zero allows validation to pass even
    /// with no proofs.
    ///
    /// A single witness is configured but the threshold is set to 0. Since
    /// `valid_proofs (0) < threshold (0)` is false, validation succeeds. This exercises
    /// the boundary condition of the threshold comparison.
    ///
    /// This matters for DID WebVH because it confirms the threshold logic handles the
    /// zero boundary correctly. While a threshold of zero is unlikely in production, the
    /// validation code must behave predictably for all values.
    #[test]
    fn test_witness_no_threshold_error() {
        // This tests the edge case where witnesses() returns Some but threshold() returns None
        // Can only happen with Witnesses::Empty {} that somehow passes the witnesses() check
        // In practice, this path is guarded, but we test the error path
        let mut proofs = WitnessProofCollection::default();
        let witnesses = Witnesses::Value {
            threshold: 0,
            witnesses: vec![Witness {
                id: Multibase::new("z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7lL8N8AC4Pp6"),
            }],
        };
        let entry = make_witnessed_entry("1-abcd", witnesses);
        // threshold is 0, so valid_proofs(0) < threshold(0) is false → passes threshold check
        // But threshold() returns Some(0), not None, so the "no threshold" path isn't hit
        // We need to test that 0 valid proofs still pass with threshold 0
        proofs
            .validate_log_entry(&entry, 1)
            .expect("0 threshold with 0 proofs should pass");
    }
}
