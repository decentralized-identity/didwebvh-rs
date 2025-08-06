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
