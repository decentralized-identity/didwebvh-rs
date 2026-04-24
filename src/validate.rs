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
use std::sync::Arc;
use tracing::{debug, error};

use crate::{
    DIDWebVHError, DIDWebVHState,
    log_entry_state::{LogEntryState, LogEntryValidationStatus},
    witness::WitnessVerifyOptions,
};

/// Why log-entry validation stopped before consuming every loaded entry.
///
/// Returned inside [`ValidationReport::truncated`] when entries loaded into
/// [`DIDWebVHState`] were dropped during validation. Two cases:
///
/// - [`Self::VerificationFailed`]: a later entry failed signature or
///   parameter verification. The chain up to the failing entry's predecessor
///   is still usable; the failing entry *and everything after it* has been
///   dropped from [`DIDWebVHState::log_entries`]. The underlying
///   [`DIDWebVHError`] is carried structurally in an [`Arc`] so callers can
///   pattern-match on the specific error variant without this enum having
///   to be `Clone`-incompatible.
/// - [`Self::PostDeactivation`]: a valid deactivation entry was followed by
///   additional entries in the loaded log. Per spec a deactivated DID
///   cannot be updated, so those trailing entries are dropped. Surfacing
///   this loudly matters: silently accepting a `[genesis, deactivate,
///   attacker-appended]` log would let an attacker hide tampered entries
///   behind a real deactivation.
///
/// `#[non_exhaustive]` lets future variants land without breaking
/// downstream matches.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TruncationReason {
    /// A log entry failed verification (bad proof, parameter transition,
    /// hash chain, etc.). Contains the failing entry's `versionId` and the
    /// structural error.
    VerificationFailed {
        /// `versionId` of the entry at which verification stopped.
        at_version_id: String,
        /// The underlying error. Wrapped in [`Arc`] because
        /// [`DIDWebVHError`] is not `Clone` (some variants wrap non-cloneable
        /// `reqwest` / `serde_json` sources). Callers that want the
        /// variant should pattern-match on `&*error`; callers that just
        /// want a string can `error.to_string()`.
        error: Arc<DIDWebVHError>,
    },
    /// Entries past a valid deactivation entry were dropped. The controller
    /// cannot legitimately extend a deactivated log; a resolver that sees
    /// such entries should treat them as tampering attempts rather than
    /// silently truncating.
    PostDeactivation {
        /// `versionId` of the deactivation entry.
        deactivated_at: String,
        /// Number of entries in the loaded log past the deactivation entry
        /// that were dropped.
        dropped_entries: u32,
    },
}

impl TruncationReason {
    /// The `versionId` at which the truncation happened — the failing entry
    /// for `VerificationFailed`, the deactivation entry for
    /// `PostDeactivation`.
    pub fn at_version_id(&self) -> &str {
        match self {
            Self::VerificationFailed { at_version_id, .. }
            | Self::PostDeactivation {
                deactivated_at: at_version_id,
                ..
            } => at_version_id,
        }
    }
}

/// Summary of a call to [`DIDWebVHState::validate`].
///
/// Always carries the `versionId` of the last-known-good entry in `ok_until`.
/// If `truncated` is `Some`, entries past that point were dropped — see
/// [`TruncationReason`] for the two cases.
///
/// # Handling the report
///
/// ```ignore
/// // Strict: fail on any truncation (recommended for resolvers).
/// state.validate()?.assert_complete()?;
///
/// // Best-effort: accept partial logs, inspect truncation manually.
/// let report = state.validate()?;
/// if let Some(reason) = &report.truncated {
///     tracing::warn!(?reason, "partial validation");
/// }
/// ```
///
/// # On `#[must_use]`
///
/// The `#[must_use]` attribute catches the most obvious misuse —
/// `state.validate();` as a bare statement — and forces a call-site
/// binding. **It does not catch propagation-and-drop**: `state.validate()?;`
/// still compiles cleanly, because `?` consumes the `Result` and drops
/// the `Ok(ValidationReport)` without triggering the lint. Reach for
/// [`Self::assert_complete`] whenever you need the stricter "succeed only
/// if every loaded entry validated" contract — that is the one call that
/// turns truncation into an `Err`.
#[must_use = "a ValidationReport may contain a truncation that the caller must handle — \
              call .assert_complete() to turn it into an error, or inspect .truncated"]
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// `versionId` of the last log entry that validated successfully.
    pub ok_until: String,
    /// `Some` if some entries in the loaded log did not survive validation.
    /// See [`TruncationReason`] for the variants (verification failure vs
    /// post-deactivation tampering).
    pub truncated: Option<TruncationReason>,
}

impl ValidationReport {
    /// Returns `Err` if the report indicates any truncation.
    ///
    /// Convenience for the common "strict resolver" case — a caller that
    /// wants `Ok(())` only when every loaded entry validated can write
    /// `state.validate()?.assert_complete()?`.
    pub fn assert_complete(self) -> Result<(), DIDWebVHError> {
        let Some(reason) = &self.truncated else {
            return Ok(());
        };
        let version = crate::log_entry::parse_version_id_fields(reason.at_version_id())
            .map(|(n, _)| n)
            .unwrap_or(0);
        let msg = match reason {
            TruncationReason::VerificationFailed {
                at_version_id,
                error,
            } => format!(
                "Log truncated at {at_version_id}: {error}. Last valid entry: {}.",
                self.ok_until,
            ),
            TruncationReason::PostDeactivation {
                deactivated_at,
                dropped_entries,
            } => format!(
                "Log contains {dropped_entries} entries past the deactivation entry \
                 at {deactivated_at}; a deactivated DID cannot be updated."
            ),
        };
        Err(DIDWebVHError::validation(msg, version))
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
        self.validate_with(&WitnessVerifyOptions::new())
    }

    /// Variant of [`Self::validate`] that accepts runtime [`WitnessVerifyOptions`]
    /// — useful for consumers that need to widen the accepted witness cryptosuites
    /// (e.g. post-quantum interop testing) without recompiling.
    pub fn validate_with(
        &mut self,
        options: &WitnessVerifyOptions,
    ) -> Result<ValidationReport, DIDWebVHError> {
        // Validate each LogEntry
        let original_len = self.log_entries.len();
        let mut previous_entry: Option<&LogEntryState> = None;
        let mut truncated: Option<TruncationReason> = None;
        // Records where deactivation happened so post-deactivation drops
        // can be surfaced in the report.
        let mut deactivation_info: Option<(usize, String)> = None;

        for (idx, entry) in self.log_entries.iter_mut().enumerate() {
            match entry.verify_log_entry(previous_entry) {
                Ok(()) => (),
                Err(e) => {
                    error!(
                        "There was an issue with LogEntry: {}! Reason: {e}",
                        entry.get_version_id()
                    );
                    if previous_entry.is_some() {
                        // Record truncation and fall back to last known good.
                        truncated = Some(TruncationReason::VerificationFailed {
                            at_version_id: entry.get_version_id().to_string(),
                            error: Arc::new(e),
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
                deactivation_info = Some((idx, entry.get_version_id().to_string()));
            }

            // Set the next previous records
            previous_entry = Some(entry);

            if self.deactivated {
                // If we have a deactivated entry, we stop processing further entries
                break;
            }
        }

        // Post-deactivation entries: entries loaded past the deactivation
        // entry cannot legitimately exist (a deactivated DID is terminal).
        // Only report this when we didn't already record a verification
        // failure — the two are mutually exclusive, but guard anyway.
        if truncated.is_none()
            && let Some((idx, deactivated_at)) = deactivation_info
        {
            let dropped = original_len.saturating_sub(idx + 1);
            if dropped > 0 {
                error!(
                    "Log contains {dropped} entries past deactivation at {deactivated_at}; \
                     treating as tampering."
                );
                truncated = Some(TruncationReason::PostDeactivation {
                    deactivated_at,
                    dropped_entries: u32::try_from(dropped).unwrap_or(u32::MAX),
                });
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

        // Bind witness proofs to *this* log: a witness signs `{"versionId": X}`,
        // and that signature is only meaningful here if X is the versionId of an
        // entry in this log. The witness-proofs file is fetched from the
        // (potentially compromised) DID host, so without this check an attacker
        // can replay a genuine proof that W issued for a *different* DID's entry
        // "N-otherhash" — the later-proof branch in validate_log_entry would
        // verify the signature against the claimed versionId and count it.
        let valid_version_ids: std::collections::HashSet<&str> = self
            .log_entries
            .iter()
            .map(|e| e.get_version_id())
            .collect();
        self.witness_proofs
            .witness_version
            .retain(|_, (version_id, _, _)| valid_version_ids.contains(version_id.as_str()));

        // Step 4: Validate the witness proofs
        for log_entry in self.log_entries.iter_mut() {
            debug!("Witness Proof Validating: {}", log_entry.get_version_id());
            self.witness_proofs
                .validate_log_entry(log_entry, highest_version_number, options)?;
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

        self.expires = Utc::now().fixed_offset() + Duration::seconds(i64::from(ttl));

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

    /// Tests that entries loaded past a valid deactivation are surfaced as
    /// [`TruncationReason::PostDeactivation`] and then dropped.
    ///
    /// Models a tampering scenario: `[genesis, deactivate, attacker-appended]`.
    /// Before this was surfaced, `validate()` returned `Ok` with no truncation
    /// reported — the attacker-appended entry was silently dropped by `retain`.
    /// A resolver had no way to tell apart a clean deactivated log from one
    /// with extra junk after the deactivation. Now the report tells the caller
    /// exactly how many entries past the deactivation were dropped, and
    /// `assert_complete()` turns it into a hard error.
    #[tokio::test]
    async fn test_validate_entries_past_deactivation_reported() {
        use super::TruncationReason;

        let base_time = (Utc::now() - Duration::seconds(1000)).fixed_offset();
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

        // Legit deactivation entry.
        state
            .create_log_entry(
                Some(base_time + Duration::seconds(1)),
                &actual_doc,
                &Parameters {
                    update_keys: Some(Arc::new(vec![])),
                    deactivated: Some(true),
                    ..Default::default()
                },
                &key,
            )
            .await
            .unwrap();

        // Attacker-appended entry: push a stub directly into the vec. We
        // don't need to sign it — validate() breaks on the deactivation
        // entry before ever reaching this one, so the trailing entry is
        // dropped as PostDeactivation, not as VerificationFailed. Models
        // what a resolver sees when loading a tampered did.jsonl from disk
        // or HTTP: all entries load, then validation walks them in order.
        state.log_entries.push(LogEntryState {
            log_entry: crate::log_entry::LogEntry::Spec1_0(
                crate::log_entry::spec_1_0::LogEntry1_0 {
                    version_id: "3-ZZZZattackerappended".to_string(),
                    version_time: (base_time + Duration::seconds(2)).fixed_offset(),
                    parameters: crate::parameters::spec_1_0::Parameters1_0::default(),
                    state: actual_doc.clone(),
                    proof: vec![],
                },
            ),
            version_number: 3,
            validated_parameters: Parameters::default(),
            validation_status: LogEntryValidationStatus::NotValidated,
        });
        // `create_log_entry` flipped state.deactivated to true during the
        // deactivation entry — clear it so validate() gets the unvalidated
        // state a freshly-loaded log would present.
        state.deactivated = false;

        // Reset validation status so validate() walks fresh.
        for entry in &mut state.log_entries {
            entry.validation_status = LogEntryValidationStatus::NotValidated;
        }
        assert_eq!(state.log_entries.len(), 3);

        let report = state.validate().unwrap();
        // The deactivation entry and everything before it survives.
        assert_eq!(state.log_entries.len(), 2);
        assert!(state.deactivated);
        // The trailing entry is flagged, not silently dropped.
        let Some(TruncationReason::PostDeactivation {
            ref deactivated_at,
            dropped_entries,
        }) = report.truncated
        else {
            panic!("expected PostDeactivation, got {:?}", report.truncated);
        };
        assert_eq!(dropped_entries, 1);
        assert!(deactivated_at.starts_with("2-"));

        // assert_complete() must refuse the report.
        let err = report.assert_complete().unwrap_err();
        assert!(err.to_string().contains("past the deactivation entry"));
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

    /// Regression test for cross-DID witness-proof replay.
    ///
    /// A witness signs `{"versionId": X}`. That signature is *globally* valid
    /// — it does not name the DID. So if witness W also witnesses some other
    /// DID, an attacker who controls this DID's host can lift W's genuine
    /// proof for `"3-<other-hash>"` from the other DID's witness file and drop
    /// it into this one. Before the fix, the later-version branch in
    /// `validate_log_entry` would verify the signature against the *claimed*
    /// versionId (which checks out — W really signed it) and count it toward
    /// the threshold for entries 1 and 2, even though `"3-<other-hash>"` is
    /// not an entry in this log at all.
    ///
    /// Scenario built here:
    ///   - entry 1: sets `witness: {threshold:1, [W]}` → entry 1 needs W
    ///   - entry 2: sets `witness: {}` (off) → entry 2 still needs W (active
    ///     witness is the *previous* entry's config)
    ///   - entry 3: no witness param → active_witness is None, no proof needed
    ///   - witness file: one genuine W signature over `"3-crossdidhash"`,
    ///     replayed from a different DID
    ///
    /// Without the fix: entries 1 and 2 are satisfied via the later-version
    /// branch, entry 3 needs nothing → full validation passes with W never
    /// having signed anything in this log. With the fix: the replayed proof's
    /// versionId is not in this log, so it is dropped before witness
    /// validation and entry 1 fails its threshold.
    #[tokio::test]
    async fn test_validate_rejects_cross_did_witness_replay() {
        use crate::witness::{Witness, Witnesses};
        use affinidi_data_integrity::{DataIntegrityProof, SignOptions};

        let base_time = (Utc::now() - Duration::seconds(1000)).fixed_offset();
        let controller = generate_signing_key();
        let controller_mb = Multibase::new(controller.get_public_keymultibase().unwrap());

        // Witness key — secret.id must be the did:key VM so the proof's
        // verificationMethod matches what validate_log_entry looks up.
        let witness_secret =
            affinidi_secrets_resolver::secrets::Secret::generate_ed25519(None, None);
        let w_pk = witness_secret.get_public_keymultibase().unwrap();
        let mut witness_secret = witness_secret.clone();
        witness_secret.id = format!("did:key:{w_pk}#{w_pk}");

        let doc = did_doc_with_key("did:webvh:{SCID}:localhost%3A8000", &controller);
        let mut state = DIDWebVHState::default();

        // Entry 1: turn on witnessing.
        state
            .create_log_entry(
                Some(base_time),
                &doc,
                &Parameters {
                    update_keys: Some(Arc::new(vec![controller_mb.clone()])),
                    portable: Some(false),
                    witness: Some(Arc::new(Witnesses::Value {
                        threshold: 1,
                        witnesses: vec![Witness {
                            id: Multibase::new(format!("did:key:{w_pk}")),
                        }],
                    })),
                    ..Default::default()
                },
                &controller,
            )
            .await
            .unwrap();
        let actual_doc = state.log_entries.last().unwrap().get_state().clone();

        // Entry 2: turn witnessing off (takes effect at entry 3).
        state
            .create_log_entry(
                Some(base_time + Duration::seconds(1)),
                &actual_doc,
                &Parameters {
                    witness: Some(Arc::new(Witnesses::Empty {})),
                    ..Default::default()
                },
                &controller,
            )
            .await
            .unwrap();

        // Entry 3: no witness needed.
        state
            .create_log_entry(
                Some(base_time + Duration::seconds(2)),
                &actual_doc,
                &Parameters::default(),
                &controller,
            )
            .await
            .unwrap();

        // The replayed proof: W's genuine signature over a versionId from a
        // *different* DID's log. Version number 3 ≤ highest (3) so it survives
        // generate_proof_state, and 3 > {1,2} so entries 1 and 2 hit the
        // later-version branch — which only checks the signature against the
        // claimed versionId, not against this log.
        let replayed = DataIntegrityProof::sign(
            &json!({"versionId": "3-crossdidhash"}),
            &witness_secret,
            SignOptions::new(),
        )
        .await
        .unwrap();
        state
            .witness_proofs
            .add_proof("3-crossdidhash", &replayed, false)
            .unwrap();

        for entry in &mut state.log_entries {
            entry.validation_status = LogEntryValidationStatus::NotValidated;
        }

        let err = state.validate().expect_err(
            "cross-DID witness proof must not satisfy this log's threshold",
        );
        assert!(
            err.to_string().contains("threshold"),
            "expected threshold failure, got: {err}"
        );
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
