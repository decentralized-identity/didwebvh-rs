/*!
*  Reads a JSON Log file, all functions related to reading and verifying Log Entries are here
*/

use super::LogEntry;
use crate::{
    DIDWebVHError, Multibase, SCID_HOLDER,
    log_entry::{LogEntryMethods, PublicKey, spec_1_0::LogEntry1_0, spec_1_0_pre::LogEntry1_0Pre},
    parameters::Parameters,
};
use affinidi_data_integrity::VerifyOptions;
use chrono::Utc;
use std::{
    fs::File,
    io::{self, BufRead},
    sync::Arc,
};

use tracing::{debug, warn};

impl LogEntry {
    /// Load all LogEntries from a file and return them as a vector
    /// Returns an error if the file cannot be read or if the entries are invalid.
    pub(crate) fn load_from_file(file_path: &str) -> Result<Vec<LogEntry>, DIDWebVHError> {
        let file = File::open(file_path)
            .map_err(|e| DIDWebVHError::LogEntryError(format!("Failed to open log file: {e}")))?;
        let buf_reader = io::BufReader::new(file);

        let mut entries = Vec::new();
        let mut version = None;
        for line in buf_reader.lines() {
            match line {
                Ok(line) => {
                    let log_entry = LogEntry::deserialize_string(&line, version)?;
                    version = Some(log_entry.get_webvh_version());
                    entries.push(log_entry);
                }
                Err(e) => {
                    return Err(DIDWebVHError::LogEntryError(format!(
                        "Failed to read line from log file: {e}",
                    )));
                }
            }
        }

        Ok(entries)
    }

    /// Verify a LogEntry against a previous entry if it exists
    /// NOTE: THIS DOES NOT VERIFY WITNESS PROOFS!
    /// NOTE: You must validate witness proofs separately
    /// Returns validated current-state Parameters and MetaData
    pub fn verify_log_entry(
        &self,
        previous_log_entry: Option<&LogEntry>,
        previous_parameters: Option<&Parameters>,
    ) -> Result<Parameters, DIDWebVHError> {
        debug!("Verifiying LogEntry: {}", self.get_version_id());

        // Ensure we are dealing with a signed LogEntry
        let Some(proof) = &self.get_proofs().first() else {
            return Err(DIDWebVHError::ValidationError(
                "Missing proof in the signed LogEntry!".to_string(),
            ));
        };

        // Ensure proofPurpose is assertionMethod as required by the spec
        if proof.proof_purpose != "assertionMethod" {
            return Err(DIDWebVHError::ValidationError(format!(
                "Invalid proofPurpose '{}': must be 'assertionMethod'",
                proof.proof_purpose
            )));
        }

        // Ensure the Parameters are correctly setup
        let parameters = match self.get_parameters().validate(previous_parameters) {
            Ok(params) => params,
            Err(e) => {
                return Err(DIDWebVHError::LogEntryError(format!(
                    "Failed to validate parameters: {e}",
                )));
            }
        };
        debug!("Validated parameters: {parameters:#?}");

        // Ensure that the signed proof key is part of the authorized keys.
        //
        // didwebvh 1.0 §"Authorized Keys for the New DID Log Entry":
        // - Pre-rotation mode (previous entry declared `nextKeyHashes`): the current
        //   entry's own `updateKeys` are pre-committed and self-authorize its proof.
        // - Plain rotation: the current entry's proof must come from the PREVIOUS
        //   entry's `updateKeys` — newly-declared keys do not activate until N+1.
        // - Genesis entry: self-authorizing against its own `updateKeys`.
        //
        // `active_update_keys` is "keys active for the next entry" (forward-looking),
        // which is exactly what we need for the plain-rotation read rule when applied
        // to the previous entry. See also the mirror logic in `DIDWebVHState::verify_log_entry_state`.
        let authorized = match (previous_log_entry, previous_parameters) {
            (Some(_), Some(previous_params)) if !previous_params.pre_rotation_active => {
                &previous_params.active_update_keys
            }
            (Some(_), Some(previous_params)) => {
                // Pre-rotation self-authorisation: trust this arm only if
                // the previous entry actually committed `nextKeyHashes` —
                // otherwise `Parameters::validate` has diverged from
                // `pre_rotation_active`, which would silently admit
                // unauthorised keys. Cheap local invariant on a hot path.
                debug_assert!(
                    previous_params.next_key_hashes.is_some(),
                    "pre_rotation_active=true implies next_key_hashes.is_some(); \
                     Parameters::validate invariant broken",
                );
                if previous_params.next_key_hashes.is_none() {
                    return Err(DIDWebVHError::ValidationError(
                        "previous entry claims pre-rotation but has no nextKeyHashes: \
                         refusing to self-authorise"
                            .to_string(),
                    ));
                }
                &parameters.active_update_keys
            }
            _ => &parameters.active_update_keys,
        };
        if !LogEntry::check_signing_key_authorized(authorized, &proof.verification_method) {
            warn!(
                "Signing key {} is not authorized",
                &proof.verification_method
            );
            return Err(DIDWebVHError::ValidationError(format!(
                "Signing key ({}) is not authorized",
                &proof.verification_method
            )));
        }

        // Verify Signature
        let verify_doc = match self {
            LogEntry::Spec1_0(log_entry) => LogEntry::Spec1_0(LogEntry1_0 {
                proof: Vec::new(),
                ..log_entry.clone()
            }),
            LogEntry::Spec1_0Pre(log_entry) => LogEntry::Spec1_0Pre(LogEntry1_0Pre {
                proof: Vec::new(),
                ..log_entry.clone()
            }),
        };

        proof
            .verify_with_public_key(
                &verify_doc,
                proof.get_public_key_bytes()?.as_slice(),
                VerifyOptions::new(),
            )
            .map_err(|e| {
                DIDWebVHError::LogEntryError(format!("Signature verification failed: {e}"))
            })?;

        // As a version of this LogEntry gets modified to recalculate hashes,
        // we create a clone once and reuse it for verification
        let mut working_entry = self.clone();
        working_entry.clear_proofs();

        // Verify the version ID
        working_entry.verify_version_id(previous_log_entry)?;

        // Validate the version timestamp
        self.verify_version_time(previous_log_entry)?;

        // Check DID portability: if the DID document `id` changed, `portable` must be true
        // and the previous DID must appear in `alsoKnownAs` (per spec)
        if let Some(previous) = previous_log_entry {
            self.verify_portability(previous, &parameters)?;
        }

        // Do we need to calculate the SCID for the first logEntry?
        if previous_log_entry.is_none() {
            // First LogEntry and we must validate the SCID
            working_entry.verify_scid()?;
        }

        debug!("LogEntry {} successfully verified", self.get_version_id());

        Ok(parameters)
    }

    /// Ensures that the signing key exists in the currently aothorized keys
    /// Format of authorized keys will be a multikey E.g. z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15
    /// Format of proof_key will be a DID (only supports DID:key)
    /// Returns true if key is authorized or false if not
    fn check_signing_key_authorized(
        authorized_keys: &Arc<Vec<Multibase>>,
        proof_key: &str,
    ) -> bool {
        if authorized_keys.is_empty() {
            warn!("No authorized keys found, skipping signing key check");
            return false;
        }

        if let Some((_, key)) = proof_key.split_once('#') {
            authorized_keys.iter().any(|f| f.as_str() == key)
        } else {
            false
        }
    }

    /// Checks the version ID of a LogEntry against the previous LogEntry
    fn verify_version_id(&mut self, previous: Option<&LogEntry>) -> Result<(), DIDWebVHError> {
        let (current_id, current_hash) = self.get_version_id_fields()?;

        // Check if the version number is incremented correctly
        if let Some(previous) = previous {
            let (id, _) = previous.get_version_id_fields()?;

            if current_id != id + 1 {
                return Err(DIDWebVHError::ValidationError(format!(
                    "Current LogEntry version ID ({current_id}) must be one greater than previous version ID ({id})",
                )));
            }
            // Set the versionId to the previous versionId to calculate the hash
            self.set_version_id(previous.get_version_id());
        } else if current_id != 1 {
            return Err(DIDWebVHError::ValidationError(format!(
                "First LogEntry must have version ID 1, got {current_id}",
            )));
        } else {
            let scid = self
                .get_scid()
                .ok_or_else(|| {
                    DIDWebVHError::ValidationError(
                        "First LogEntry must have a valid SCID".to_string(),
                    )
                })?
                .to_string();
            self.set_version_id(&scid);
        };

        // Validate the entryHash
        let entry_hash = self.generate_log_entry_hash()?;
        if entry_hash != current_hash {
            return Err(DIDWebVHError::ValidationError(format!(
                "Current LogEntry version ID ({current_id}) hash ({current_hash}) does not match calculated hash ({entry_hash})",
            )));
        }

        Ok(())
    }

    /// Verifies that DID portability rules are respected.
    /// If the DID document `id` has changed from the previous entry, the `portable` parameter
    /// must be `true`, and the previous DID must appear in the `alsoKnownAs` array.
    fn verify_portability(
        &self,
        previous: &LogEntry,
        parameters: &Parameters,
    ) -> Result<(), DIDWebVHError> {
        let current_id = self.get_state().get("id").and_then(|v| v.as_str());
        let previous_id = previous.get_state().get("id").and_then(|v| v.as_str());

        if let (Some(current), Some(previous_did)) = (current_id, previous_id)
            && current != previous_did
        {
            // DID identifier changed — this is a move/rename
            if parameters.portable != Some(true) {
                return Err(DIDWebVHError::ValidationError(
                    "DID document id has changed but portable is not enabled".to_string(),
                ));
            }

            // Per spec: the previous DID string MUST appear in alsoKnownAs
            let has_previous_in_also_known_as = self
                .get_state()
                .get("alsoKnownAs")
                .and_then(|v| v.as_array())
                .is_some_and(|arr| {
                    arr.iter()
                        .any(|v| v.as_str().is_some_and(|s| s == previous_did))
                });

            if !has_previous_in_also_known_as {
                return Err(DIDWebVHError::ValidationError(format!(
                    "DID has been moved but previous DID ({previous_did}) is not in alsoKnownAs",
                )));
            }
        }

        Ok(())
    }

    /// Verifies everything is ok with the versionTime LogEntry field
    fn verify_version_time(&self, previous: Option<&LogEntry>) -> Result<(), DIDWebVHError> {
        if self.get_version_time() > Utc::now() {
            return Err(DIDWebVHError::ValidationError(format!(
                "versionTime ({}) cannot be in the future",
                self.get_version_time_string()
            )));
        }

        if let Some(previous) = previous {
            // Current time must be strictly greater than the previous time (per spec)
            if self.get_version_time() <= previous.get_version_time() {
                return Err(DIDWebVHError::ValidationError(format!(
                    "Current versionTime ({}) must be greater than previous versionTime ({})",
                    self.get_version_time_string(),
                    previous.get_version_time_string()
                )));
            }
        }

        Ok(())
    }

    /// Verifies that the SCID is correct for the first log entry
    fn verify_scid(&mut self) -> Result<(), DIDWebVHError> {
        self.set_version_id(SCID_HOLDER);

        let scid = self
            .get_scid()
            .ok_or_else(|| {
                DIDWebVHError::ValidationError("First LogEntry must have a valid SCID".to_string())
            })?
            .to_string();

        // Convert the SCID value to holder
        let temp = serde_json::to_string(&self).map_err(|e| {
            DIDWebVHError::LogEntryError(format!("Failed to serialize log entry: {e}"))
        })?;

        let scid_entry: LogEntry = match self {
            LogEntry::Spec1_0(_) => LogEntry::Spec1_0(
                serde_json::from_str(&temp.replace(&scid, SCID_HOLDER)).map_err(|e| {
                    DIDWebVHError::LogEntryError(format!("Failed to deserialize log entry: {e}"))
                })?,
            ),
            LogEntry::Spec1_0Pre(_) => LogEntry::Spec1_0Pre(
                serde_json::from_str(&temp.replace(&scid, SCID_HOLDER)).map_err(|e| {
                    DIDWebVHError::LogEntryError(format!("Failed to deserialize log entry: {e}"))
                })?,
            ),
        };

        let verify_scid = scid_entry.generate_first_scid()?;
        if scid != verify_scid {
            return Err(DIDWebVHError::ValidationError(format!(
                "SCID ({scid}) does not match calculated SCID ({verify_scid})",
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::DIDWebVHError;
    use crate::Multibase;
    use crate::log_entry::LogEntry;
    use crate::log_entry::spec_1_0::LogEntry1_0;
    use crate::parameters::Parameters;
    use crate::parameters::spec_1_0::Parameters1_0;
    use affinidi_data_integrity::{DataIntegrityProof, crypto_suites::CryptoSuite};
    use chrono::{Duration, Utc};
    use serde_json::json;

    /// Helper to create a minimal Spec1_0 LogEntry with a given DID document state.
    /// Uses a fixed versionId of "1-abc123", the current timestamp, default parameters,
    /// and an empty proof list. Useful for tests that focus on state-level behavior
    /// (e.g. portability checks) without needing valid cryptographic proofs.
    fn make_log_entry(state: serde_json::Value) -> LogEntry {
        LogEntry::Spec1_0(LogEntry1_0 {
            version_id: "1-abc123".to_string(),
            version_time: Utc::now().fixed_offset(),
            parameters: Parameters1_0::default(),
            state,
            proof: vec![],
        })
    }

    /// Helper to create a minimal Spec1_0 LogEntry with a specific timestamp.
    /// Uses a fixed versionId of "1-abc123", a default DID document state with a
    /// valid id field, default parameters, and an empty proof list. Useful for tests
    /// that focus on versionTime ordering without needing valid cryptographic proofs.
    fn make_log_entry_with_time(time: chrono::DateTime<chrono::FixedOffset>) -> LogEntry {
        LogEntry::Spec1_0(LogEntry1_0 {
            version_id: "1-abc123".to_string(),
            version_time: time,
            parameters: Parameters1_0::default(),
            state: json!({"id": "did:webvh:abc123:example.com"}),
            proof: vec![],
        })
    }

    /// Tests that verify_log_entry rejects proofs with any proofPurpose other
    /// than "assertionMethod", including "authentication", "keyAgreement",
    /// "capabilityInvocation", and an empty string.
    /// Expected: Each invalid purpose returns a ValidationError mentioning "assertionMethod".
    /// This matters because the WebVH spec mandates that log entry proofs use
    /// "assertionMethod"; accepting other purposes would weaken the trust model.
    #[test]
    fn test_invalid_proof_purpose_rejected() {
        for bad_purpose in ["authentication", "keyAgreement", "capabilityInvocation", ""] {
            let entry = LogEntry::Spec1_0(LogEntry1_0 {
                version_id: "1-abcdef".to_string(),
                version_time: Utc::now().fixed_offset(),
                parameters: Parameters1_0::default(),
                state: json!({}),
                proof: vec![DataIntegrityProof {
                    type_: "DataIntegrityProof".to_string(),
                    cryptosuite: CryptoSuite::EddsaJcs2022,
                    created: None,
                    verification_method: "did:key:z6Mk#z6Mk".to_string(),
                    proof_purpose: bad_purpose.to_string(),
                    proof_value: Some("zDummy".to_string()),
                    context: None,
                }],
            });

            let result = entry.verify_log_entry(None, None);
            assert!(
                matches!(result, Err(DIDWebVHError::ValidationError(ref msg)) if msg.contains("assertionMethod")),
                "Expected assertionMethod error for proofPurpose '{bad_purpose}', got: {result:?}",
            );
        }
    }

    /// Tests that verify_portability passes when the DID document id has not
    /// changed between entries and portable is false.
    /// Expected: Returns Ok because no move occurred.
    /// This matters because most DID updates do not change the identifier;
    /// portability checks should not interfere with normal non-move updates.
    #[test]
    fn test_portability_same_id_not_portable() {
        // Same DID id between entries, portable=false → should pass
        let previous = make_log_entry(json!({"id": "did:webvh:abc123:example.com"}));
        let current = make_log_entry(json!({"id": "did:webvh:abc123:example.com"}));
        let params = Parameters {
            portable: Some(false),
            ..Default::default()
        };

        assert!(current.verify_portability(&previous, &params).is_ok());
    }

    /// Tests that verify_portability fails when the DID document id has changed
    /// but the portable parameter is false.
    /// Expected: Returns an error indicating "portable is not enabled".
    /// This matters because the spec requires portable=true for DID moves;
    /// allowing identifier changes without the flag would break DID resolution.
    #[test]
    fn test_portability_different_id_not_portable() {
        // DID id changed, portable=false → must fail
        let previous = make_log_entry(json!({"id": "did:webvh:abc123:example.com"}));
        let current = make_log_entry(json!({"id": "did:webvh:abc123:newdomain.com"}));
        let params = Parameters {
            portable: Some(false),
            ..Default::default()
        };

        let result = current.verify_portability(&previous, &params);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("portable is not enabled")
        );
    }

    /// Tests that verify_portability fails when the DID document id has changed
    /// and the portable parameter is None (defaults to false).
    /// Expected: Returns an error indicating "portable is not enabled".
    /// This matters because an unset portable flag must default to non-portable
    /// behavior, preventing accidental DID moves.
    #[test]
    fn test_portability_different_id_portable_none() {
        // DID id changed, portable=None (defaults to false) → must fail
        let previous = make_log_entry(json!({"id": "did:webvh:abc123:example.com"}));
        let current = make_log_entry(json!({"id": "did:webvh:abc123:newdomain.com"}));
        let params = Parameters {
            portable: None,
            ..Default::default()
        };

        let result = current.verify_portability(&previous, &params);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("portable is not enabled")
        );
    }

    /// Tests that verify_portability fails when the DID id has changed,
    /// portable is true, but the alsoKnownAs array is missing from the state.
    /// Expected: Returns an error indicating the previous DID is "not in alsoKnownAs".
    /// This matters because the spec requires the previous DID to appear in
    /// alsoKnownAs after a move, establishing a verifiable chain of identity.
    #[test]
    fn test_portability_different_id_portable_missing_also_known_as() {
        // DID id changed, portable=true, but no alsoKnownAs → must fail
        let previous = make_log_entry(json!({"id": "did:webvh:abc123:example.com"}));
        let current = make_log_entry(json!({"id": "did:webvh:abc123:newdomain.com"}));
        let params = Parameters {
            portable: Some(true),
            ..Default::default()
        };

        let result = current.verify_portability(&previous, &params);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not in alsoKnownAs")
        );
    }

    /// Tests that verify_portability fails when the DID id has changed,
    /// portable is true, and alsoKnownAs exists but does not contain the
    /// previous DID identifier.
    /// Expected: Returns an error indicating the previous DID is "not in alsoKnownAs".
    /// This matters because an alsoKnownAs array that references a different DID
    /// does not satisfy the spec's requirement to link back to the original identity.
    #[test]
    fn test_portability_different_id_portable_wrong_also_known_as() {
        // DID id changed, portable=true, alsoKnownAs exists but doesn't contain previous DID
        let previous = make_log_entry(json!({"id": "did:webvh:abc123:example.com"}));
        let current = make_log_entry(json!({
            "id": "did:webvh:abc123:newdomain.com",
            "alsoKnownAs": ["did:webvh:abc123:other.com"]
        }));
        let params = Parameters {
            portable: Some(true),
            ..Default::default()
        };

        let result = current.verify_portability(&previous, &params);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not in alsoKnownAs")
        );
    }

    /// Tests that verify_portability succeeds when the DID id has changed,
    /// portable is true, and alsoKnownAs correctly contains the previous DID.
    /// Expected: Returns Ok, allowing the DID move.
    /// This matters because this is the happy path for portable DIDs; the spec
    /// allows identifier changes only when all three conditions are met.
    #[test]
    fn test_portability_different_id_portable_with_also_known_as() {
        // DID id changed, portable=true, alsoKnownAs contains previous DID → should pass
        let previous = make_log_entry(json!({"id": "did:webvh:abc123:example.com"}));
        let current = make_log_entry(json!({
            "id": "did:webvh:abc123:newdomain.com",
            "alsoKnownAs": ["did:webvh:abc123:example.com"]
        }));
        let params = Parameters {
            portable: Some(true),
            ..Default::default()
        };

        assert!(current.verify_portability(&previous, &params).is_ok());
    }

    /// Tests that verify_portability succeeds when the DID id has not changed,
    /// even if portable is set to true.
    /// Expected: Returns Ok because no move actually occurred.
    /// This matters because enabling portability should not break normal updates
    /// where the identifier stays the same; only actual moves trigger the checks.
    #[test]
    fn test_portability_same_id_portable_enabled() {
        // Same DID id, portable=true → should pass (no move happened)
        let previous = make_log_entry(json!({"id": "did:webvh:abc123:example.com"}));
        let current = make_log_entry(json!({"id": "did:webvh:abc123:example.com"}));
        let params = Parameters {
            portable: Some(true),
            ..Default::default()
        };

        assert!(current.verify_portability(&previous, &params).is_ok());
    }

    /// Tests that verify_portability passes when neither the previous nor the
    /// current log entry states contain an "id" field.
    /// Expected: Returns Ok because no comparison is possible.
    /// This matters because edge cases with missing id fields should not cause
    /// false-positive portability failures during validation.
    #[test]
    fn test_portability_missing_id_fields() {
        // Missing id fields in state → should pass (no comparison possible)
        let previous = make_log_entry(json!({}));
        let current = make_log_entry(json!({}));
        let params = Parameters {
            portable: Some(false),
            ..Default::default()
        };

        assert!(current.verify_portability(&previous, &params).is_ok());
    }

    /// Tests that verify_version_time passes when the current entry's timestamp
    /// is strictly after the previous entry's timestamp.
    /// Expected: Returns Ok.
    /// This matters because the spec requires monotonically increasing timestamps
    /// across log entries to maintain a consistent and tamper-evident version history.
    #[test]
    fn test_version_time_strictly_after_previous() {
        // Current versionTime is after previous → should pass
        let now = Utc::now().fixed_offset();
        let previous = make_log_entry_with_time(now - Duration::seconds(10));
        let current = make_log_entry_with_time(now);

        assert!(current.verify_version_time(Some(&previous)).is_ok());
    }

    /// Tests that verify_version_time fails when the current and previous entries
    /// have identical timestamps.
    /// Expected: Returns an error about versionTime needing to be greater.
    /// This matters because the spec requires strictly increasing timestamps;
    /// equal times would make version ordering ambiguous.
    #[test]
    fn test_version_time_equal_to_previous() {
        // Current versionTime equals previous → must fail (spec requires strictly greater)
        let now = Utc::now().fixed_offset();
        let previous = make_log_entry_with_time(now);
        let current = make_log_entry_with_time(now);

        let result = current.verify_version_time(Some(&previous));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must be greater than previous versionTime")
        );
    }

    /// Tests that verify_version_time fails when the current entry's timestamp
    /// is earlier than the previous entry's timestamp.
    /// Expected: Returns an error about versionTime needing to be greater.
    /// This matters because a backwards timestamp would indicate log tampering
    /// or an out-of-order entry, violating the append-only log invariant.
    #[test]
    fn test_version_time_before_previous() {
        // Current versionTime is before previous → must fail
        let now = Utc::now().fixed_offset();
        let previous = make_log_entry_with_time(now);
        let current = make_log_entry_with_time(now - Duration::seconds(10));

        let result = current.verify_version_time(Some(&previous));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must be greater than previous versionTime")
        );
    }

    /// Tests that verify_version_time passes for the first log entry (no previous
    /// entry to compare against).
    /// Expected: Returns Ok.
    /// This matters because the first entry in a DID log has no predecessor, so
    /// the time-ordering check must be skipped for the genesis entry.
    #[test]
    fn test_version_time_no_previous() {
        // First entry (no previous) → should pass
        let now = Utc::now().fixed_offset();
        let current = make_log_entry_with_time(now);

        assert!(current.verify_version_time(None).is_ok());
    }

    /// Tests that check_signing_key_authorized returns false when the authorized
    /// keys list is empty, even if the proof key format is valid.
    /// Expected: Returns false.
    /// This matters because an empty authorized key set means no key is trusted;
    /// allowing any key through would be a critical security vulnerability.
    #[test]
    fn test_authorized_keys_fail() {
        let authorized_keys: Vec<Multibase> = Vec::new();
        assert!(!LogEntry::check_signing_key_authorized(
            &Arc::new(authorized_keys),
            "did:key:z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15#z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15"
        ));
    }

    /// Tests that check_signing_key_authorized returns false when the proof key
    /// is missing the fragment separator (#), making key extraction impossible.
    /// Expected: Returns false.
    /// This matters because the multikey identifier is extracted from the fragment
    /// after '#'; without it, the key cannot be matched against authorized keys.
    #[test]
    fn test_authorized_keys_missing_key_id_fail() {
        let authorized_keys: Vec<Multibase> = Vec::new();
        assert!(!LogEntry::check_signing_key_authorized(
            &Arc::new(authorized_keys),
            "did:key:z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15"
        ));
    }

    /// Tests that check_signing_key_authorized returns true when the proof key's
    /// fragment matches one of the authorized multikey identifiers.
    /// Expected: Returns true.
    /// This matters because only keys listed in updateKeys are allowed to sign
    /// log entries; this is the core authorization check for DID updates.
    #[test]
    fn test_authorized_keys_ok() {
        let authorized_keys: Vec<Multibase> = vec![Multibase::new(
            "z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15",
        )];

        assert!(LogEntry::check_signing_key_authorized(
            &Arc::new(authorized_keys),
            "did:key:z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15#z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15"
        ));
    }

    /// Tests that verify_log_entry fails when the log entry has no proof at all.
    /// Expected: Returns an error mentioning "Missing proof".
    /// This matters because every log entry must be signed with a data integrity
    /// proof; unsigned entries cannot be trusted and must be rejected.
    #[test]
    fn test_verify_log_entry_missing_proof() {
        let entry = make_log_entry(json!({"id": "did:webvh:scid:example.com"}));
        let result = entry.verify_log_entry(None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Missing proof"));
    }

    /// Tests that verify_version_id fails when the first log entry (no previous)
    /// has a version number other than 1.
    /// Expected: Returns an error about the first entry needing version ID 1.
    /// This matters because the DID log must start at version 1; any other
    /// starting version indicates a missing or truncated log history.
    #[test]
    fn test_verify_version_id_first_entry_not_one() {
        let mut entry = LogEntry::Spec1_0(LogEntry1_0 {
            version_id: "5-abc123".to_string(),
            version_time: Utc::now().fixed_offset(),
            parameters: Parameters1_0::default(),
            state: json!({"id": "did:webvh:scid:example.com"}),
            proof: vec![DataIntegrityProof {
                type_: "DataIntegrityProof".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: None,
                verification_method: "did:key:z6Mk#z6Mk".to_string(),
                proof_purpose: "assertionMethod".to_string(),
                proof_value: Some("zDummy".to_string()),
                context: None,
            }],
        });
        // verify_version_id checks first entry must have version ID 1
        let result = entry.verify_version_id(None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must have version ID 1")
        );
    }

    /// Tests that verify_version_id fails when the current entry's version number
    /// is not exactly one greater than the previous entry's version number (e.g.
    /// jumping from 1 to 5 instead of 1 to 2).
    /// Expected: Returns an error about the version needing to be "one greater".
    /// This matters because the spec requires sequential version numbering to
    /// ensure no log entries have been skipped or inserted out of order.
    #[test]
    fn test_verify_version_id_not_incremented() {
        let previous = LogEntry::Spec1_0(LogEntry1_0 {
            version_id: "1-abc123".to_string(),
            version_time: (Utc::now() - Duration::seconds(10)).fixed_offset(),
            parameters: Parameters1_0 {
                scid: Some(Arc::new("scidtest".to_string())),
                ..Parameters1_0::default()
            },
            state: json!({"id": "did:webvh:scidtest:example.com"}),
            proof: vec![],
        });
        let mut current = LogEntry::Spec1_0(LogEntry1_0 {
            version_id: "5-xyz789".to_string(), // should be 2, not 5
            version_time: Utc::now().fixed_offset(),
            parameters: Parameters1_0::default(),
            state: json!({"id": "did:webvh:scidtest:example.com"}),
            proof: vec![],
        });
        let result = current.verify_version_id(Some(&previous));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must be one greater")
        );
    }

    // ===== File I/O error tests =====

    /// Tests that load_from_file returns an error when the file does not exist.
    /// Expected: Returns a LogEntryError mentioning "Failed to open".
    #[test]
    fn test_load_from_file_missing_file() {
        let result = LogEntry::load_from_file("/nonexistent/path/did.jsonl");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to open log file")
        );
    }

    /// Tests that load_from_file returns an error when the file contains invalid JSON.
    /// Expected: Returns an error during deserialization.
    #[test]
    fn test_load_from_file_corrupted_content() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir
            .join(format!(
                "test_corrupted_{}.jsonl",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
            .to_string_lossy()
            .to_string();

        std::fs::write(&file_path, "this is not valid json\n").unwrap();
        let result = LogEntry::load_from_file(&file_path);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&file_path);
    }

    /// Tests that load_from_file returns an empty vec for an empty file.
    /// Expected: Returns Ok with an empty Vec since there are no lines to parse.
    #[test]
    fn test_load_from_file_empty_file() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir
            .join(format!(
                "test_empty_{}.jsonl",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
            .to_string_lossy()
            .to_string();

        std::fs::write(&file_path, "").unwrap();
        let result = LogEntry::load_from_file(&file_path);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
        let _ = std::fs::remove_file(&file_path);
    }

    /// Tests that verify_version_time rejects a log entry whose timestamp is
    /// in the future (1 hour ahead of the current time).
    /// Expected: Returns an error indicating the time is "in the future".
    /// This matters because future-dated entries could be used to pre-commit
    /// changes or manipulate version ordering; the spec prohibits them.
    #[test]
    fn test_verify_version_time_future_error() {
        let future_time = (Utc::now() + Duration::hours(1)).fixed_offset();
        let entry = make_log_entry_with_time(future_time);
        let result = entry.verify_version_time(None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("in the future"));
    }
}
