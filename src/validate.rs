/*!
*   Highest level validation logic for a webvh entry
*
*   Step 1: Load LogEntries and validate each LogEntry
*   Step 2: Get the highest LogEntry versionId
*   Step 3: Load the Witness proofs and generate Witness State
*   Step 4: Validate LogEntry Witness Proofs against each other
*   Step 5: Fully validated WebVH DID result
*/

use chrono::{Duration, Utc};
use tracing::{debug, error};

use crate::{
    DIDWebVHError, DIDWebVHState,
    log_entry_state::{LogEntryState, LogEntryValidationStatus},
};

/// Why log-entry validation stopped before consuming every loaded entry.
///
/// Returned inside [`ValidationReport::truncated`] when entries loaded into
/// [`DIDWebVHState`] past `at_version_id` failed verification. The chain up to
/// and including `at_version_id`'s predecessor is still usable (the last-known-good
/// entries); everything at and after `at_version_id` has been dropped from
/// [`DIDWebVHState::log_entries`].
///
/// The inner error is stringified rather than carried as [`DIDWebVHError`]
/// because the latter is not `Clone` (it wraps non-cloneable `reqwest` and
/// `serde_json` errors in some variants); surfacing the message preserves
/// diagnostics without forcing a clone bound on the error type.
#[derive(Debug, Clone)]
pub struct TruncationReason {
    /// `versionId` of the entry at which validation stopped.
    pub at_version_id: String,
    /// Rendered error message from the failing entry's verification.
    pub error: String,
}

/// Summary of a call to [`DIDWebVHState::validate`].
///
/// Always carries the `versionId` of the last-known-good entry in `ok_until`.
/// If `truncated` is `Some`, entries past that point failed verification and
/// were dropped — callers MUST decide whether that is acceptable for their
/// use case (a resolver should typically reject, a debugger may tolerate).
///
/// The `#[must_use]` attribute forces callers to acknowledge truncation
/// rather than silently ignoring a partially-validated log — this replaces
/// the pre-0.5.0 behaviour where `validate()` returned `Ok(())` after
/// silently truncating.
#[must_use = "a ValidationReport may contain a truncation that the caller must handle"]
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// `versionId` of the last log entry that validated successfully.
    pub ok_until: String,
    /// `Some` if verification stopped before the loaded log ended.
    pub truncated: Option<TruncationReason>,
}

impl ValidationReport {
    /// Returns `Err` if the report indicates any truncation.
    ///
    /// Convenience for the common "strict resolver" case — a caller that
    /// wants `Ok(())` only when every loaded entry validated can write
    /// `state.validate()?.assert_complete()?`.
    pub fn assert_complete(self) -> Result<(), DIDWebVHError> {
        if let Some(reason) = &self.truncated {
            let version = crate::log_entry::parse_version_id_fields(&reason.at_version_id)
                .map(|(n, _)| n)
                .unwrap_or(0);
            return Err(DIDWebVHError::validation(
                format!(
                    "Log truncated at {}: {}. Last valid entry: {}.",
                    reason.at_version_id, reason.error, self.ok_until
                ),
                version,
            ));
        }
        Ok(())
    }
}

impl DIDWebVHState {
    /// Validates all LogEntries and their witness proofs.
    ///
    /// Walks the log entry chain in order, verifying each entry's signature and
    /// parameter transitions. If a later entry fails, entries from that point on
    /// are dropped from `self.log_entries` and the failure is reported via
    /// [`ValidationReport::truncated`] — callers that want to reject partial
    /// chains should call [`ValidationReport::assert_complete`]. After log
    /// entry validation, witness proofs are verified against the configured
    /// threshold for each surviving entry.
    ///
    /// Sets `self.validated = true` and computes `self.expires` on success.
    /// Returns an error only if the *first* entry is invalid (no fallback
    /// possible) or if witness-proof validation fails.
    pub fn validate(&mut self) -> Result<ValidationReport, DIDWebVHError> {
        // Validate each LogEntry
        let mut previous_entry: Option<&LogEntryState> = None;
        let mut truncated: Option<TruncationReason> = None;

        for entry in self.log_entries.iter_mut() {
            match entry.verify_log_entry(previous_entry) {
                Ok(()) => (),
                Err(e) => {
                    error!(
                        "There was an issue with LogEntry: {}! Reason: {e}",
                        entry.get_version_id()
                    );
                    if previous_entry.is_some() {
                        // Record truncation and fall back to last known good.
                        truncated = Some(TruncationReason {
                            at_version_id: entry.get_version_id().to_string(),
                            error: e.to_string(),
                        });
                        break;
                    }
                    return Err(DIDWebVHError::validation(
                        format!("No valid LogEntry found! Reason: {e}"),
                        entry.version_number,
                    ));
                }
            }
            // Check if this valid LogEntry has been deactivated, if so then ignore any other
            // Entries
            if let Some(deactivated) = entry.validated_parameters.deactivated
                && deactivated
            {
                // Deactivated, return the current LogEntry and MetaData
                self.deactivated = true;
            }

            // Set the next previous records
            previous_entry = Some(entry);

            if self.deactivated {
                // If we have a deactivated entry, we stop processing further entries
                break;
            }
        }

        // Cleanup any LogEntries that are after deactivated or invalid after last ok LogEntry
        self.log_entries
            .retain(|entry| entry.validation_status == LogEntryValidationStatus::LogEntryOnly);
        if self.log_entries.is_empty() {
            return Err(DIDWebVHError::ValidationError(
                "No validated LogEntries exist".to_string(),
            ));
        }

        // Step 1: COMPLETED. LogEntries are verified and only contains good Entries

        // Step 2: Get the highest validated version number
        let highest_version_number = self
            .log_entries
            .last()
            .expect("guarded by empty check above")
            .get_version_number();
        debug!("Latest LogEntry ID = ({})", highest_version_number);

        // Step 3: Recalculate witness proofs based on the highest LogEntry version
        self.witness_proofs
            .generate_proof_state(highest_version_number)?;

        // Step 4: Validate the witness proofs
        for log_entry in self.log_entries.iter_mut() {
            debug!("Witness Proof Validating: {}", log_entry.get_version_id());
            self.witness_proofs
                .validate_log_entry(log_entry, highest_version_number)?;
            log_entry.validation_status = LogEntryValidationStatus::Ok;
        }

        // Set to validated and timestamp
        self.validated = true;
        let last_log_entry = self
            .log_entries
            .last()
            .expect("guarded by empty check above");
        self.scid = if let Some(scid) = &last_log_entry.validated_parameters.scid {
            scid.to_string()
        } else {
            return Err(DIDWebVHError::ValidationError(
                "No SCID found in last LogEntry".to_string(),
            ));
        };
        let ttl = if let Some(ttl) = last_log_entry.validated_parameters.ttl {
            if ttl == 0 { 3600_u32 } else { ttl }
        } else {
            // Use default TTL of 1 hour
            3600_u32
        };

        self.expires = Utc::now().fixed_offset() + Duration::seconds(ttl as i64);

        let ok_until = last_log_entry.get_version_id().to_string();
        Ok(ValidationReport {
            ok_until,
            truncated,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        DIDWebVHState, Multibase,
        log_entry_state::{LogEntryState, LogEntryValidationStatus},
        parameters::Parameters,
        test_utils::{did_doc_with_key, generate_signing_key},
    };
    use chrono::{Duration, Utc};
    use serde_json::json;
    use std::sync::Arc;

    /// Creates a valid, signed `DIDWebVHState` containing exactly one log entry.
    ///
    /// An optional `ttl` parameter allows TTL-specific tests to reuse this helper
    /// instead of duplicating the setup. After creation, the validation status is
    /// reset to `NotValidated` so that `validate()` can be exercised from scratch.
    async fn create_single_entry_state(ttl: Option<u32>) -> DIDWebVHState {
        let base_time = (Utc::now() - Duration::seconds(10)).fixed_offset();
        let key = generate_signing_key();
        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(
                key.get_public_keymultibase().unwrap(),
            )])),
            portable: Some(false),
            ttl,
            ..Default::default()
        };
        let doc = did_doc_with_key("did:webvh:{SCID}:localhost%3A8000", &key);

        let mut state = DIDWebVHState::default();
        state
            .create_log_entry(Some(base_time), &doc, &params, &key)
            .await
            .expect("Failed to create first entry");
        // Reset validation status to NotValidated so validate() can run
        for entry in &mut state.log_entries {
            entry.validation_status = LogEntryValidationStatus::NotValidated;
        }
        state
    }

    /// Tests that a single valid, signed log entry passes full validation.
    ///
    /// After validation the state should be marked as validated and the SCID
    /// (Self-Certifying Identifier) should be populated. This is the baseline
    /// happy-path test -- if a single well-formed entry cannot be validated,
    /// no WebVH DID resolution can succeed.
    #[tokio::test]
    async fn test_validate_single_valid_entry() {
        let mut state = create_single_entry_state(None).await;
        let report = state.validate().expect("Validation should pass");
        assert!(report.truncated.is_none());
        assert!(state.validated);
        assert!(!state.scid.is_empty());
    }

    /// Tests that a deactivated DID stops log entry processing at the deactivation point.
    ///
    /// When a log entry sets `deactivated: true`, the validator must stop processing
    /// any subsequent entries and mark the overall state as deactivated. Both the
    /// initial entry and the deactivation entry should be retained (2 entries total).
    /// This matters because a deactivated DID must not accept further updates, and
    /// resolvers need to know the DID is no longer active.
    #[tokio::test]
    async fn test_validate_deactivated_stops_processing() {
        let base_time = (Utc::now() - Duration::seconds(100)).fixed_offset();
        let key = generate_signing_key();
        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(
                key.get_public_keymultibase().unwrap(),
            )])),
            portable: Some(false),
            ..Default::default()
        };
        let doc = did_doc_with_key("did:webvh:{SCID}:localhost%3A8000", &key);

        let mut state = DIDWebVHState::default();
        state
            .create_log_entry(Some(base_time), &doc, &params, &key)
            .await
            .unwrap();

        let actual_doc = state.log_entries.last().unwrap().get_state().clone();

        // Create deactivation entry
        let deact_params = Parameters {
            update_keys: Some(Arc::new(vec![])),
            deactivated: Some(true),
            ..Default::default()
        };
        state
            .create_log_entry(
                Some(base_time + Duration::seconds(1)),
                &actual_doc,
                &deact_params,
                &key,
            )
            .await
            .unwrap();

        // Reset validation status
        for entry in &mut state.log_entries {
            entry.validation_status = LogEntryValidationStatus::NotValidated;
        }

        let report = state.validate().unwrap();
        assert!(report.truncated.is_none());
        assert!(state.deactivated);
        // Should still have 2 entries (both valid, but deactivated stops further processing)
        assert_eq!(state.log_entries.len(), 2);
    }

    /// Tests that an invalid first log entry produces an immediate error.
    ///
    /// If the very first entry in the log is malformed (e.g., missing a proof),
    /// there is no previous valid entry to fall back to. The validator must return
    /// a "No valid LogEntry found" error rather than silently succeeding with an
    /// empty state. This guards the invariant that every WebVH DID must begin with
    /// a cryptographically valid genesis entry.
    #[test]
    fn test_validate_invalid_first_entry_error() {
        let mut state = DIDWebVHState::default();
        // Push an invalid entry with no proof
        state.log_entries.push(LogEntryState {
            log_entry: crate::log_entry::LogEntry::Spec1_0(
                crate::log_entry::spec_1_0::LogEntry1_0 {
                    version_id: "1-abc".to_string(),
                    version_time: Utc::now().fixed_offset(),
                    parameters: crate::parameters::spec_1_0::Parameters1_0::default(),
                    state: json!({}),
                    proof: vec![],
                },
            ),
            version_number: 1,
            validated_parameters: Parameters::default(),
            validation_status: LogEntryValidationStatus::NotValidated,
        });

        let err = state.validate().unwrap_err();
        assert!(err.to_string().contains("No valid LogEntry found"));
    }

    /// Validates TTL behavior by creating a state with the given TTL, validating it,
    /// and asserting the expiration is within the expected range.
    async fn assert_ttl_produces_expiry(ttl: Option<u32>, expected_seconds: i64) {
        let mut state = create_single_entry_state(ttl).await;
        let _report = state.validate().unwrap();
        let now = Utc::now().fixed_offset();
        let diff = state.expires - now;
        assert!(
            diff.num_seconds() > (expected_seconds - 100) && diff.num_seconds() <= expected_seconds,
            "Expected expiry ~{expected_seconds}s, got {}s",
            diff.num_seconds()
        );
    }

    /// Tests that validation applies the default TTL of 3600 seconds (1 hour) when no
    /// TTL is specified in the parameters.
    ///
    /// A sensible default TTL is important so that resolvers know how long they can
    /// cache a resolved DID document before re-fetching.
    #[tokio::test]
    async fn test_validate_ttl_default() {
        assert_ttl_produces_expiry(None, 3600).await;
    }

    /// Tests that a TTL value of zero is treated as the default TTL of 3600 seconds.
    ///
    /// A zero TTL would cause immediate expiration, which is not useful. The validator
    /// treats TTL=0 as "use default" to prevent accidental misconfiguration from making
    /// a DID effectively unresolvable due to instant cache expiry.
    #[tokio::test]
    async fn test_validate_ttl_zero_defaults_to_3600() {
        assert_ttl_produces_expiry(Some(0), 3600).await;
    }

    /// Tests that a custom TTL value (7200 seconds / 2 hours) is honored by the validator.
    ///
    /// When the parameters specify a non-zero TTL, the validated state's expiration
    /// should reflect that exact duration. This ensures DID publishers can control how
    /// long resolvers cache their DID documents.
    #[tokio::test]
    async fn test_validate_ttl_custom() {
        assert_ttl_produces_expiry(Some(7200), 7200).await;
    }

    /// Tests that validating a state with no log entries at all returns an error.
    ///
    /// An empty log is not a valid WebVH DID -- there must be at least a genesis entry.
    /// The validator must return a "No validated LogEntries" error to prevent resolvers
    /// from accepting a DID that has no verifiable history.
    #[test]
    fn test_validate_no_log_entries_error() {
        let mut state = DIDWebVHState::default();
        let err = state.validate().unwrap_err();
        assert!(err.to_string().contains("No validated LogEntries"));
    }
}
