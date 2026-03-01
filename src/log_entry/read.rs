/*!
*  Reads a JSON Log file, all functions related to reading and verifying Log Entries are here
*/

use super::LogEntry;
use crate::{
    DIDWebVHError, SCID_HOLDER,
    log_entry::{LogEntryMethods, PublicKey, spec_1_0::LogEntry1_0, spec_1_0_pre::LogEntry1_0Pre},
    parameters::Parameters,
};
use affinidi_data_integrity::verification_proof::verify_data_with_public_key;
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

        // Ensure that the signed proof key is part of the authorized keys
        if !LogEntry::check_signing_key_authorized(
            &parameters.active_update_keys,
            &proof.verification_method,
        ) {
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

        let verified = verify_data_with_public_key(
            &verify_doc,
            None,
            proof,
            proof.get_public_key_bytes()?.as_slice(),
        )
        .map_err(|e| DIDWebVHError::LogEntryError(format!("Signature verification failed: {e}")))?;
        if !verified.verified {
            return Err(DIDWebVHError::LogEntryError(
                "Signature verification failed".to_string(),
            ));
        }

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
    fn check_signing_key_authorized(authorized_keys: &Arc<Vec<String>>, proof_key: &str) -> bool {
        if authorized_keys.is_empty() {
            warn!("No authorized keys found, skipping signing key check");
            return false;
        }

        if let Some((_, key)) = proof_key.split_once('#') {
            authorized_keys.iter().any(|f| f == key)
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
            self.set_version_id(&previous.get_version_id());
        } else if current_id != 1 {
            return Err(DIDWebVHError::ValidationError(format!(
                "First LogEntry must have version ID 1, got {current_id}",
            )));
        } else {
            let Some(scid) = self.get_scid() else {
                return Err(DIDWebVHError::ValidationError(
                    "First LogEntry must have a valid SCID".to_string(),
                ));
            };
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

        if let (Some(current), Some(previous_did)) = (current_id, previous_id) {
            if current != previous_did {
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
            // Current time must be greater than the previous time
            if self.get_version_time() < previous.get_version_time() {
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

        let Some(scid) = self.get_scid() else {
            return Err(DIDWebVHError::ValidationError(
                "First LogEntry must have a valid SCID".to_string(),
            ));
        };

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

    use crate::log_entry::LogEntry;
    use crate::log_entry::spec_1_0::LogEntry1_0;
    use crate::parameters::Parameters;
    use crate::parameters::spec_1_0::Parameters1_0;
    use chrono::Utc;
    use serde_json::json;

    /// Helper to create a minimal LogEntry with a given DID document state
    fn make_log_entry(state: serde_json::Value) -> LogEntry {
        LogEntry::Spec1_0(LogEntry1_0 {
            version_id: "1-abc123".to_string(),
            version_time: Utc::now().fixed_offset(),
            parameters: Parameters1_0::default(),
            state,
            proof: vec![],
        })
    }

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

    #[test]
    fn test_authorized_keys_fail() {
        let authorized_keys: Vec<String> = Vec::new();
        assert!(!LogEntry::check_signing_key_authorized(
            &Arc::new(authorized_keys),
            "did:key:z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15#z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15"
        ));
    }

    #[test]
    fn test_authorized_keys_missing_key_id_fail() {
        let authorized_keys: Vec<String> = Vec::new();
        assert!(!LogEntry::check_signing_key_authorized(
            &Arc::new(authorized_keys),
            "did:key:z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15"
        ));
    }

    #[test]
    fn test_authorized_keys_ok() {
        let authorized_keys: Vec<String> =
            vec!["z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15".to_string()];

        assert!(LogEntry::check_signing_key_authorized(
            &Arc::new(authorized_keys),
            "did:key:z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15#z6Mkr46vzpmne5FJTE1TgRHrWkoc5j9Kb1suMYtxkdvgMu15"
        ));
    }
}
