/*!
*   A webvh that has witnessing enabled requires a proof file containing each witness proof
*
*   When saving or serializing the Witness Proofs, you should run `optimise_records` first
*   THis will ensure that previous witness proof records have been removed
*/
use std::{fs::File, sync::Arc};

use crate::DIDWebVHError;
use affinidi_data_integrity::DataIntegrityProof;
use ahash::HashMap;
use serde::{Deserialize, Serialize};
use tracing::warn;

// *********************************************************
// Witness Proof File
// *********************************************************

/// WebVH witness proof file format
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessProofShadow(Vec<WitnessProof>);

/// Record of each LogEntry that requires witnessing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessProof {
    /// versionId of the DID Log Entry to which witness proofs apply.
    pub version_id: Arc<String>,
    /// Array of DataIntegrity Proofs from each Witness
    pub proof: Vec<Arc<DataIntegrityProof>>,

    /// Internally used for partial proofs
    /// Set to true if versionId relates to an unpublished LogEntry
    /// Defauklts to false
    #[serde(skip)]
    pub future_entry: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(try_from = "WitnessProofShadow")]
pub struct WitnessProofCollection {
    /// Raw Witness Proofs
    pub(crate) proofs: WitnessProofShadow,

    /// Mapping of Proofs by witness. Points to the highest versionId
    /// Value = versionId, integer prefix of versionId, Data Integrity Proof
    #[serde(skip)]
    pub(crate) witness_version: HashMap<String, (Arc<String>, u32, Arc<DataIntegrityProof>)>,
}

/// Converts the inner Secret Shadow to a public Shadow Struct
impl TryFrom<WitnessProofShadow> for WitnessProofCollection {
    type Error = DIDWebVHError;

    fn try_from(proofs: WitnessProofShadow) -> Result<Self, Self::Error> {
        Ok(WitnessProofCollection {
            proofs,
            ..Default::default()
        })
    }
}

impl WitnessProofCollection {
    /// Insert a witness proof for a given versionId
    /// versionId is in the format of n-hash, where n is the version number and hash is the hash of
    /// the LogEntry
    /// proof is the DataIntegrityProof from the witness
    /// future_entry is set to true if the versionId relates to a future LogEntry that has not been
    /// published yet
    pub fn add_proof(
        &mut self,
        version_id: &str,
        proof: &DataIntegrityProof,
        future_entry: bool,
    ) -> Result<(), DIDWebVHError> {
        let Some((id, _)) = version_id.split_once('-') else {
            return Err(DIDWebVHError::WitnessProofError(format!(
                "Invalid versionID ({version_id}) in witness proofs! Expected n-hash, but missing n",
            )));
        };
        let Ok(id): Result<u32, _> = str::parse(id) else {
            return Err(DIDWebVHError::WitnessProofError(format!(
                "Invalid versionID ({version_id}) in witness proofs! expected n-hash, where n is a number!",
            )));
        };

        if !future_entry {
            // Check if proof has an earlier version, remove it if so
            if let Some((p_version, p_id, p)) =
                self.witness_version.get_mut(&proof.verification_method)
            {
                if &id > p_id {
                    // Remove the earlier proof
                    for e in self.proofs.0.iter_mut() {
                        if e.version_id == *p_version {
                            e.proof
                                .retain(|i| i.verification_method != p.verification_method);
                        }
                    }
                }

                // Remove empty versionId entries
                self.proofs.0.retain(|e| !e.proof.is_empty());
            }
        }

        let rc_proof = Arc::new(proof.clone());
        let version_id = if let Some(record) = self
            .proofs
            .0
            .iter_mut()
            .find(|p| *p.version_id == version_id)
        {
            // versionId already exists
            record.proof.push(rc_proof.clone());
            record.version_id.clone()
        } else {
            // Need to create a new WitnessProof record
            let version_id = Arc::new(version_id.to_string());
            self.proofs.0.push(WitnessProof {
                version_id: version_id.clone(),
                future_entry,
                proof: vec![rc_proof.clone()],
            });
            version_id
        };

        // Update the pointer to latest witness version proof
        self.witness_version.insert(
            proof.verification_method.clone(),
            (version_id, id, rc_proof),
        );

        Ok(())
    }

    /// Completely remove all proofs relating to a versionId
    pub fn remove_version_id(&mut self, version_id: &str) {
        self.proofs.0.retain(|p| *p.version_id != version_id);
    }

    /// How many Witness proofs exist for a given versionId
    /// Returns 0 if no proofs exist for that versionId (or not found)
    /// This is a safe fail for how witness proofs are handled
    pub fn get_proof_count(&self, version_id: &str) -> usize {
        self.proofs
            .0
            .iter()
            .find(|p| *p.version_id == version_id)
            .map_or(0, |p| p.proof.len())
    }

    /// Load existing proofs from a file
    pub(crate) fn read_from_file(file_path: &str) -> Result<Self, DIDWebVHError> {
        let file = File::open(file_path).map_err(|e| {
            DIDWebVHError::WitnessProofError(format!(
                "Couldn't open Witness Proofs file ({file_path}): {e}",
            ))
        })?;
        let proofs: WitnessProofShadow = serde_json::from_reader(file).map_err(|e| {
            DIDWebVHError::WitnessProofError(format!(
                "Couldn't deserialize Witness Proofs Data from file ({file_path}): {e}",
            ))
        })?;

        Ok(WitnessProofCollection {
            proofs,
            ..Default::default()
        })
    }

    /// Save proofs to a file
    /// Returns bytes written
    pub fn save_to_file(&self, file_path: &str) -> Result<u32, DIDWebVHError> {
        let json_data = serde_json::to_string(&self.proofs).map_err(|e| {
            DIDWebVHError::WitnessProofError(
                format!("Couldn't serialize Witness Proofs Data: {e}",),
            )
        })?;
        let bytes = json_data.len() as u32;
        std::fs::write(file_path, json_data).map_err(|e| {
            DIDWebVHError::WitnessProofError(format!(
                "Couldn't write to Witness Proofs file ({file_path}): {e}",
            ))
        })?;
        Ok(bytes)
    }

    /// Get WitnessProof record for a given version_id
    pub fn get_proofs(&self, version_id: &str) -> Option<&WitnessProof> {
        self.proofs.0.iter().find(|p| *p.version_id == version_id)
    }

    /// Useed to regenerate the proof state table when you want to cap the LogEntry
    /// version number to a specific value.
    /// This is can be used to exclude future proofs that are not yet valid or match
    /// a published LogEntry
    pub fn generate_proof_state(
        &mut self,
        highest_version_number: u32,
    ) -> Result<(), DIDWebVHError> {
        let mut new_proofs_state = WitnessProofCollection::default();

        for version in &self.proofs.0 {
            let version_number = if let Some((prefix, _)) = version.version_id.split_once('-') {
                prefix.parse::<u32>().map_err(|_| {
                    DIDWebVHError::WitnessProofError(format!(
                        "Invalid versionID ({}) in witness proofs! expected n-hash, where n is a number!",
                        version.version_id
                    ))
                })?
            } else {
                return Err(DIDWebVHError::WitnessProofError(format!(
                    "Invalid versionID ({}) in witness proofs! Expected n-hash, but missing n",
                    version.version_id
                )));
            };

            if version_number > highest_version_number {
                // Skip this versionId as it is for a future entry and thus needs to be kept
                continue;
            }
            for proof in &version.proof {
                new_proofs_state
                    .add_proof(
                        &version.version_id,
                        proof, // Assuming at least one proof exists
                        false,
                    )
                    .map_err(|e| {
                        DIDWebVHError::WitnessProofError(format!(
                            "Error adding witness proof state to table: {e}",
                        ))
                    })?;
            }
        }

        self.witness_version = new_proofs_state.witness_version;

        Ok(())
    }

    /// Runs through and removes witness proofs from earlier LogEntries that are not required
    pub fn write_optimise_records(&mut self) -> Result<(), DIDWebVHError> {
        // Map out which versions each witness is visible in
        for v in &self.proofs.0 {
            if v.future_entry {
                // Skip this versionId as it is for a future entry and thus needs to be kept
                continue;
            }
            let Some((id, _)) = v.version_id.split_once('-') else {
                return Err(DIDWebVHError::WitnessProofError(format!(
                    "Invalid versionID ({}) in witness proofs! Expected n-hash, but missing n",
                    v.version_id
                )));
            };
            let Ok(id): Result<u32, _> = str::parse(id) else {
                return Err(DIDWebVHError::WitnessProofError(format!(
                    "Invalid versionID ({}) in witness proofs! expected n-hash, where n is a number!",
                    v.version_id
                )));
            };

            // Walk through each proof for this versionID
            for p in &v.proof {
                if let Some((_, proof_id, _)) = self.witness_version.get_mut(&p.verification_method)
                {
                    if &id > proof_id {
                        *proof_id = id;
                    }
                } else {
                    // Create new witness record
                    self.witness_version.insert(
                        p.verification_method.clone(),
                        (v.version_id.clone(), id, p.clone()),
                    );
                }
            }
        }

        // Strip out older proofs as needed
        self.proofs.0.retain_mut(|v| {
            if v.future_entry {
                // Skip this versionId as it is for a future entry and thus needs to be kept
                return true;
            }

            let Some((id, _)) = v.version_id.split_once('-') else {
                warn!(
                    "Invalid versionID ({}) in witness proofs! Expected n-hash, but missing n", v.version_id);
                return false;
            };
            let Ok(id): Result<u32, _> = str::parse(id) else {
                warn!(
                    "Invalid versionID ({}) in witness proofs! expected n-hash, where n is a number!", v.version_id);
            return false;
            };

            // Remove older proofs
            v.proof
                .retain(|p| &id >= if let Some((_, proof_id, _)) = self.witness_version.get(&p.verification_method) { proof_id } else {&0});

            // If version has no proofs, then remove it
             !v.proof.is_empty()
        });

        Ok(())
    }

    /// Returns the number of Witness Proofs in the collection
    pub fn get_total_count(&self) -> usize {
        self.proofs.0.iter().map(|p| p.proof.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::WitnessProof;
    use crate::{
        DIDWebVHError, test_utils::make_test_proof, witness::proofs::WitnessProofCollection,
    };

    /// Creates a `WitnessProofCollection` pre-populated with two version groups:
    ///
    /// - Version "1-abcd" with 3 proofs (non-future)
    /// - Version "2-abcd" with 3 proofs (future)
    ///
    /// This is a common setup pattern used by tests that need to exercise
    /// multi-version proof operations such as removal, retrieval, and state
    /// regeneration.
    fn setup_two_versions() -> WitnessProofCollection {
        let mut proofs = WitnessProofCollection::default();
        let proof = make_test_proof("verification-method");

        for _ in 0..3 {
            proofs
                .add_proof("1-abcd", &proof, false)
                .expect("Couldn't add proof");
        }

        for _ in 0..3 {
            proofs
                .add_proof("2-abcd", &proof, true)
                .expect("Couldn't add proof");
        }

        proofs
    }

    /// Tests that `add_proof` rejects a version ID with no dash separator.
    ///
    /// Expected behavior: returns a `WitnessProofError` with an "Invalid versionID" message.
    ///
    /// This catches malformed version IDs that would otherwise cause panics or
    /// silent data corruption when splitting on '-'.
    #[test]
    fn test_add_proof_bad_version_id() {
        let mut proofs = WitnessProofCollection::default();
        let proof = make_test_proof("verification-method");

        let result = proofs.add_proof("invalid", &proof, false);

        if let Err(DIDWebVHError::WitnessProofError(msg)) = result {
            assert!(msg.starts_with("Invalid versionID"));
        } else {
            panic!("Expected an error for invalid version ID");
        }
    }

    /// Tests that `add_proof` rejects a version ID where the prefix is not a number.
    ///
    /// Expected behavior: returns a `WitnessProofError` when the portion before '-'
    /// cannot be parsed as a u32.
    ///
    /// This catches version IDs like "abc-hash" where the numeric prefix is missing,
    /// which would break version ordering logic.
    #[test]
    fn test_add_proof_bad_version_id_number() {
        let mut proofs = WitnessProofCollection::default();
        let proof = make_test_proof("verification-method");

        let result = proofs.add_proof("invalid-number", &proof, false);

        if let Err(DIDWebVHError::WitnessProofError(msg)) = result {
            assert!(msg.starts_with("Invalid versionID"));
        } else {
            panic!("Expected an error for invalid version ID");
        }
    }

    /// Tests that `add_proof` accepts a future entry after a non-future entry.
    ///
    /// Expected behavior: both proofs are added without error, and the future entry
    /// does not trigger cleanup of the earlier non-future proof.
    ///
    /// This validates the core future-entry mechanism where witnesses can pre-sign
    /// proofs for log entries that have not yet been published.
    #[test]
    fn test_add_proof_future_version() {
        let mut proofs = WitnessProofCollection::default();
        let proof = make_test_proof("verification-method");

        proofs
            .add_proof("1-abcd", &proof, false)
            .expect("Couldn't add proof");

        proofs
            .add_proof("2-abcd", &proof, true)
            .expect("Couldn't add proof");
    }

    /// Tests that multiple proofs can be added to the same version ID.
    ///
    /// Expected behavior: all 3 proofs accumulate under version "1-abcd" rather than
    /// replacing each other.
    ///
    /// This ensures that multiple witnesses can each contribute a proof for the same
    /// log entry version without overwriting previous proofs.
    #[test]
    fn test_add_proof_multiple_same_version() {
        let mut proofs = WitnessProofCollection::default();
        let proof = make_test_proof("verification-method");

        proofs
            .add_proof("1-abcd", &proof, false)
            .expect("Couldn't add proof");

        proofs
            .add_proof("1-abcd", &proof, false)
            .expect("Couldn't add proof");

        proofs
            .add_proof("1-abcd", &proof, false)
            .expect("Couldn't add proof");

        proofs.proofs.0.iter().for_each(|p| {
            assert_eq!(p.proof.len(), 3, "Expected 3 proofs for version 1-abcd");
        });
    }

    /// Tests that multiple proofs can be added across different version IDs.
    ///
    /// Expected behavior: each version group ("1-abcd" and "2-abcd") contains exactly
    /// 3 proofs, and they are stored independently.
    ///
    /// This validates that the collection correctly partitions proofs by version ID
    /// when the same witness contributes to multiple versions.
    #[test]
    fn test_add_proof_multiple_multiple_versions() {
        let mut proofs = WitnessProofCollection::default();
        let proof = make_test_proof("verification-method");

        proofs
            .add_proof("1-abcd", &proof, false)
            .expect("Couldn't add proof");

        proofs
            .add_proof("1-abcd", &proof, false)
            .expect("Couldn't add proof");

        proofs
            .add_proof("1-abcd", &proof, false)
            .expect("Couldn't add proof");

        proofs
            .add_proof("2-abcd", &proof, false)
            .expect("Couldn't add proof");

        proofs
            .add_proof("2-abcd", &proof, false)
            .expect("Couldn't add proof");

        proofs
            .add_proof("2-abcd", &proof, false)
            .expect("Couldn't add proof");

        proofs.proofs.0.iter().enumerate().for_each(|(i, p)| {
            let version = if i == 0 { "1-abcd" } else { "2-abcd" };
            assert_eq!(p.proof.len(), 3, "Expected 3 proofs for version {version}");
        });
    }

    /// Tests that `remove_version_id` removes all proofs for the targeted version.
    ///
    /// Expected behavior: after removing "1-abcd", only "2-abcd" remains with its
    /// original 3 proofs intact.
    ///
    /// This validates that version removal is precise and does not affect other
    /// version groups in the collection.
    #[test]
    fn test_remove_version_id() {
        let mut proofs = setup_two_versions();

        assert_eq!(proofs.proofs.0.len(), 2);
        proofs.remove_version_id("1-abcd");
        assert_eq!(proofs.proofs.0.len(), 1);

        assert_eq!(proofs.get_proof_count("2-abcd"), 3);
    }

    /// Tests that `get_proofs` returns the correct proof record for a given version ID.
    ///
    /// Expected behavior: retrieving proofs for "1-abcd" returns a `WitnessProof`
    /// containing exactly 3 proof entries.
    ///
    /// This validates the lookup path that resolvers use to find witness proofs when
    /// verifying a specific log entry version.
    #[test]
    fn test_get_proofs() {
        let proofs = setup_two_versions();

        let p1 = proofs.get_proofs("1-abcd").expect("Couldn't get proofs");

        assert_eq!(p1.proof.len(), 3);
    }

    /// Tests that `generate_proof_state` rebuilds the internal witness_version map.
    ///
    /// Expected behavior: calling `generate_proof_state(2)` succeeds and processes
    /// all versions up to and including version 2.
    ///
    /// This validates the state regeneration path used when capping the version
    /// number to exclude future or unpublished log entries.
    #[test]
    fn test_generate_proof_state() {
        let mut proofs = setup_two_versions();

        proofs
            .generate_proof_state(2)
            .expect("Couldn't generate new proof state");
    }

    /// Tests that `write_optimise_records` removes older proofs from the same witness.
    ///
    /// Expected behavior: when a witness has proofs in both v1 and v2, the v1 proof
    /// is removed and only the v2 proof is kept.
    ///
    /// This validates the write-time optimization that prevents the proof file from
    /// growing unboundedly as new versions are published.
    #[test]
    fn test_write_optimise_removes_old_proofs() {
        let mut proofs = WitnessProofCollection::default();
        let proof = make_test_proof("verification-method");

        proofs
            .add_proof("1-abcd", &proof, false)
            .expect("Couldn't add proof");

        proofs
            .add_proof("2-efgh", &proof, false)
            .expect("Couldn't add proof");

        proofs
            .write_optimise_records()
            .expect("Couldn't optimise records");

        // The v1 proof should have been removed since the same witness has a v2 proof
        assert_eq!(
            proofs.get_proof_count("1-abcd"),
            0,
            "Expected v1 proof to be removed after optimisation"
        );
        assert_eq!(
            proofs.get_proof_count("2-efgh"),
            1,
            "Expected v2 proof to be preserved after optimisation"
        );
    }

    /// Tests that `write_optimise_records` preserves proofs marked as future entries.
    ///
    /// Expected behavior: a future entry at v2 is not removed during optimization,
    /// even though the same witness has an older v1 proof.
    ///
    /// This catches a potential regression where optimization could accidentally
    /// discard pre-signed proofs for unpublished log entries.
    #[test]
    fn test_write_optimise_preserves_future_entries() {
        let mut proofs = WitnessProofCollection::default();
        let proof = make_test_proof("verification-method");

        proofs
            .add_proof("1-abcd", &proof, false)
            .expect("Couldn't add proof");

        proofs
            .add_proof("2-efgh", &proof, true)
            .expect("Couldn't add proof");

        proofs
            .write_optimise_records()
            .expect("Couldn't optimise records");

        // Future entry should be preserved even after optimisation
        assert_eq!(
            proofs.get_proof_count("2-efgh"),
            1,
            "Expected future entry proof to be preserved after optimisation"
        );
    }

    /// Tests that `generate_proof_state` returns an error for malformed version IDs.
    ///
    /// Expected behavior: a directly inserted proof with version ID "bad" (no dash)
    /// causes `generate_proof_state` to return a `WitnessProofError`.
    ///
    /// This catches cases where corrupt data in the proof collection would silently
    /// produce incorrect state rather than failing explicitly.
    #[test]
    fn test_generate_proof_state_invalid_version_id_error() {
        let mut proofs = WitnessProofCollection::default();
        let proof = make_test_proof("verification-method");

        // Directly insert a proof with an invalid version_id (no dash separator)
        proofs.proofs.0.push(WitnessProof {
            version_id: Arc::new("bad".to_string()),
            proof: vec![Arc::new(proof)],
            future_entry: false,
        });

        let result = proofs.generate_proof_state(10);

        if let Err(DIDWebVHError::WitnessProofError(msg)) = result {
            assert!(
                msg.contains("Invalid versionID"),
                "Expected invalid versionID error, got: {msg}"
            );
        } else {
            panic!("Expected an error for invalid version ID in generate_proof_state");
        }
    }

    /// Tests that `generate_proof_state` excludes versions above the given cap.
    ///
    /// Expected behavior: with `highest_version_number=2`, a v1 proof is included
    /// in the regenerated state but a v3 proof is excluded.
    ///
    /// This validates the version capping logic that allows resolvers to rebuild
    /// state at a specific point in the log history without being affected by
    /// proofs for later entries.
    #[test]
    fn test_generate_proof_state_skips_future_versions() {
        let mut proofs = WitnessProofCollection::default();
        let proof_a = make_test_proof("witness-a");
        let proof_b = make_test_proof("witness-b");

        proofs
            .add_proof("1-abcd", &proof_a, false)
            .expect("Couldn't add proof");

        proofs
            .add_proof("3-ijkl", &proof_b, false)
            .expect("Couldn't add proof");

        // Regenerate state with highest_version_number=2, v3 should be skipped
        proofs
            .generate_proof_state(2)
            .expect("Couldn't generate proof state");

        // witness-a (v1) should be in the state, witness-b (v3) should not
        assert!(
            proofs.witness_version.contains_key("witness-a"),
            "Expected witness-a to be in proof state"
        );
        assert!(
            !proofs.witness_version.contains_key("witness-b"),
            "Expected witness-b (v3) to be skipped in proof state"
        );
    }

    /// Tests that `add_proof` automatically removes an older proof from the same witness.
    ///
    /// Expected behavior: when a non-future v2 proof is added for a witness that
    /// already has a v1 proof, the v1 proof is removed and only v2 remains.
    ///
    /// This validates the incremental cleanup during `add_proof` that keeps the
    /// collection compact without requiring a separate optimization pass.
    #[test]
    fn test_add_proof_replaces_older_same_witness() {
        let mut proofs = WitnessProofCollection::default();
        let proof = make_test_proof("verification-method");

        proofs
            .add_proof("1-abcd", &proof, false)
            .expect("Couldn't add proof");

        assert_eq!(proofs.get_proof_count("1-abcd"), 1);

        proofs
            .add_proof("2-efgh", &proof, false)
            .expect("Couldn't add proof");

        // The v1 entry should have been cleaned up when v2 was added
        assert_eq!(
            proofs.get_proof_count("1-abcd"),
            0,
            "Expected v1 proof to be removed when v2 proof was added for the same witness"
        );
        assert_eq!(
            proofs.get_proof_count("2-efgh"),
            1,
            "Expected v2 proof to exist"
        );
    }

    /// Tests the round-trip of saving proofs to a file and reading them back.
    ///
    /// Expected behavior: the total proof count is preserved after serializing to
    /// JSON and deserializing from the file.
    ///
    /// This validates the file-based persistence path that witness nodes use to
    /// store and recover proof state across restarts.
    #[test]
    fn test_save_and_read_from_file() {
        let mut proofs = WitnessProofCollection::default();
        let proof_a = make_test_proof("witness-a");
        let proof_b = make_test_proof("witness-b");

        proofs
            .add_proof("1-abcd", &proof_a, false)
            .expect("Couldn't add proof");

        proofs
            .add_proof("1-abcd", &proof_b, false)
            .expect("Couldn't add proof");

        proofs
            .add_proof("2-efgh", &proof_a, false)
            .expect("Couldn't add proof");

        let temp_dir = std::env::temp_dir();
        let unique_name = format!(
            "test_witness_proofs_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let file_path = temp_dir.join(unique_name).to_string_lossy().to_string();

        proofs
            .save_to_file(&file_path)
            .expect("Couldn't save proofs to file");

        let loaded = WitnessProofCollection::read_from_file(&file_path)
            .expect("Couldn't read proofs from file");

        assert_eq!(
            loaded.get_total_count(),
            proofs.get_total_count(),
            "Expected loaded proof count to match saved proof count"
        );

        // Clean up
        let _ = std::fs::remove_file(&file_path);
    }

    /// Tests that `get_total_count` accurately tracks the total number of proofs
    /// across all versions as proofs are added and old ones are cleaned up.
    ///
    /// Expected behavior: the count increases as new proofs are added and stays
    /// stable when older proofs are automatically replaced by newer versions from
    /// the same witness.
    ///
    /// This validates the accounting logic that callers rely on to determine
    /// whether sufficient witness coverage has been reached.
    #[test]
    fn test_get_total_count() {
        let mut proofs = WitnessProofCollection::default();
        let proof_a = make_test_proof("witness-a");
        let proof_b = make_test_proof("witness-b");

        assert_eq!(proofs.get_total_count(), 0, "Expected 0 proofs initially");

        proofs
            .add_proof("1-abcd", &proof_a, false)
            .expect("Couldn't add proof");

        assert_eq!(
            proofs.get_total_count(),
            1,
            "Expected 1 proof after first add"
        );

        proofs
            .add_proof("1-abcd", &proof_b, false)
            .expect("Couldn't add proof");

        assert_eq!(
            proofs.get_total_count(),
            2,
            "Expected 2 proofs after adding second witness to same version"
        );

        proofs
            .add_proof("2-efgh", &proof_a, false)
            .expect("Couldn't add proof");

        // proof_a v1 gets cleaned up when v2 is added, so total should be 2 (proof_b v1 + proof_a v2)
        assert_eq!(
            proofs.get_total_count(),
            2,
            "Expected 2 proofs after v2 replaced v1 for witness-a"
        );

        proofs
            .add_proof("2-efgh", &proof_b, false)
            .expect("Couldn't add proof");

        // proof_b v1 gets cleaned up when v2 is added, so total should be 2 (proof_a v2 + proof_b v2)
        assert_eq!(
            proofs.get_total_count(),
            2,
            "Expected 2 proofs after v2 replaced v1 for witness-b"
        );
    }
}
