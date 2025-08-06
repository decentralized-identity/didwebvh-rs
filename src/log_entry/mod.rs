/*!
*   Webvh utilizes Log Entries for each version change of the DID Document.
*/
use crate::{
    DIDWebVHError, Version,
    log_entry::{spec_1_0::LogEntry1_0, spec_1_0_pre::LogEntry1_0Pre},
    parameters::Parameters,
    witness::Witnesses,
};
use affinidi_data_integrity::{DataIntegrityProof, verification_proof::verify_data};
use base58::ToBase58;
use chrono::{DateTime, FixedOffset};
use multihash::Multihash;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use serde_json_canonicalizer::to_string;
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, io::Write};

use tracing::debug;

pub mod read;
pub mod spec_1_0;
pub mod spec_1_0_pre;

/// Resolved Document MetaData
/// Returned as reolved Document MetaData on a successful resolve
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetaData {
    pub version_id: String,
    pub version_time: String,
    pub created: String,
    pub updated: String,
    pub scid: String,
    pub portable: bool,
    pub deactivated: bool,
    pub witness: Option<Witnesses>,
    pub watchers: Option<Vec<String>>,
}

/// Each version of the DID gets a new log entry
/// [Log Entries](https://identity.foundation/didwebvh/v1.0/#the-did-log-file)
#[non_exhaustive]
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum LogEntry {
    /// Official v1.0 specification
    Spec1_0(LogEntry1_0),

    /// Interim 1.0 spec where nulls were used instyead of empty arrays and objects
    Spec1_0Pre(LogEntry1_0Pre),
}

pub trait LogEntryMethods {
    /// LogEntry Parameters versionTime
    fn get_version_time_string(&self) -> String;

    /// LogEntry Parameters versionTime
    fn get_version_time(&self) -> DateTime<FixedOffset>;

    /// Set the versionId to an updated value
    fn get_version_id(&self) -> String;

    /// Set the versionId to an updated value
    fn set_version_id(&mut self, version_id: &str);

    /// Get Parameters
    fn get_parameters(&self) -> Parameters;

    /// Add a proof for this LogeEntry
    fn add_proof(&mut self, proof: DataIntegrityProof);

    /// Get proofs
    fn get_proofs(&self) -> &Vec<DataIntegrityProof>;

    /// Resets all proofs for this LogEntry
    fn clear_proofs(&mut self);

    fn get_scid(&self) -> Option<String>;

    fn get_state(&self) -> &Value;
}

/// Where-ever we need to create a LogEntry across versions
pub(crate) trait LogEntryCreate {
    fn create(
        version_id: String,
        version_time: DateTime<FixedOffset>,
        parameters: Parameters,
        state: Value,
    ) -> Result<LogEntry, DIDWebVHError>;
}

impl LogEntry {
    /// Reading in a LogEntry and converting it requires custom logic.
    /// [deserialize_string] handles detecting the version and deserializing the LogEntry correctly
    /// Attributes:
    /// - input: The input string to deserialize
    /// - version: If you want to override the default latest version, specify the previous
    ///   LogEntry version here
    pub fn deserialize_string(
        input: &str,
        version: Option<Version>,
    ) -> Result<LogEntry, DIDWebVHError> {
        // Step 1: Parse the String to generic JSON Values
        let values: Value = serde_json::from_str(input).map_err(|e| {
            DIDWebVHError::LogEntryError(format!("Couldn't deserialize LogEntry. Reason: {e}"))
        })?;

        println!("{values:#?}");

        // Step 2: Detect method version
        let version = if let Some(parameters) = values.get("parameters") {
            if let Some(method) = parameters.get("method") {
                if let Some(method) = method.as_str() {
                    Version::try_from(method).unwrap_or(version.unwrap_or_default())
                } else {
                    version.unwrap_or_default()
                }
            } else {
                version.unwrap_or_default()
            }
        } else {
            version.unwrap_or_default()
        };

        // Step 3: Deserialize using the LogEntry method version

        match version {
            Version::V1_0 => {
                // There is a pre-ratified difference in the v1.0 spec where nulls were used
                // instead of empty arrays and objects
                let Some(parameters) = values.get("parameters") else {
                    return Err(DIDWebVHError::LogEntryError(
                        "No parameters exist in the LogEntry!".to_string(),
                    ));
                };

                // Check if there are JSON nulls in the parameters
                let mut pre_version = false;
                if let Some(v) = parameters.get("updateKeys") {
                    if v.is_null() {
                        pre_version = true;
                    }
                }
                if let Some(v) = parameters.get("nextKeyHashes") {
                    if v.is_null() {
                        pre_version = true;
                    }
                }
                if let Some(v) = parameters.get("witness") {
                    if v.is_null() {
                        pre_version = true;
                    }
                }
                if let Some(v) = parameters.get("watchers") {
                    if v.is_null() {
                        pre_version = true;
                    }
                }
                if let Some(v) = parameters.get("ttl") {
                    if v.is_null() {
                        pre_version = true;
                    }
                }

                if pre_version {
                    Ok(LogEntry::Spec1_0Pre(
                        serde_json::from_value::<LogEntry1_0Pre>(values).map_err(|e| {
                            DIDWebVHError::LogEntryError(format!("Failed to parse LogEntry: {e}"))
                        })?,
                    ))
                } else {
                    Ok(LogEntry::Spec1_0(
                        serde_json::from_value::<LogEntry1_0>(values).map_err(|e| {
                            DIDWebVHError::LogEntryError(format!("Failed to parse LogEntry: {e}"))
                        })?,
                    ))
                }
            }
            _ => Err(DIDWebVHError::LogEntryError(format!(
                "Version ({version}) is not supported!"
            ))),
        }
    }

    /// Get the WebVH Specification version for this LogEntry
    pub fn get_webvh_version(&self) -> Version {
        match self {
            LogEntry::Spec1_0(_) => Version::V1_0,
            LogEntry::Spec1_0Pre(_) => Version::V1_0Pre,
        }
    }

    /// Converts a string into the correct version when version is known
    pub fn from_string_to_known_version(
        input: &str,
        version: Version,
    ) -> Result<LogEntry, DIDWebVHError> {
        match version {
            Version::V1_0 => serde_json::from_str::<LogEntry1_0>(input)
                .map(LogEntry::Spec1_0)
                .map_err(|e| {
                    DIDWebVHError::LogEntryError(format!("Failed to parse LogEntry: {e}"))
                }),
            Version::V1_0Pre => serde_json::from_str::<LogEntry1_0Pre>(input)
                .map(LogEntry::Spec1_0Pre)
                .map_err(|e| {
                    DIDWebVHError::LogEntryError(format!("Failed to parse LogEntry: {e}"))
                }),
        }
    }

    /// Append a valid LogEntry to a file
    pub fn save_to_file(&self, file_path: &str) -> Result<(), DIDWebVHError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)
            .map_err(|e| {
                DIDWebVHError::LogEntryError(format!("Couldn't open file {file_path}: {e}"))
            })?;

        file.write_all(
            serde_json::to_string(self)
                .map_err(|e| {
                    DIDWebVHError::LogEntryError(format!(
                        "Couldn't serialize LogEntry to JSON. Reason: {e}",
                    ))
                })?
                .as_bytes(),
        )
        .map_err(|e| {
            DIDWebVHError::LogEntryError(format!(
                "Couldn't append LogEntry to file({file_path}). Reason: {e}",
            ))
        })?;
        file.write_all("\n".as_bytes()).map_err(|e| {
            DIDWebVHError::LogEntryError(format!(
                "Couldn't append LogEntry to file({file_path}). Reason: {e}",
            ))
        })?;

        Ok(())
    }

    /// Generates a SCID from a preliminary LogEntry
    /// This only needs to be called once when the DID is first created.
    pub(crate) fn generate_first_scid(&self) -> Result<String, DIDWebVHError> {
        self.generate_log_entry_hash().map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate SCID from preliminary LogEntry. Reason: {e}",
            ))
        })
    }

    /// Calculates a Log Entry hash
    pub fn generate_log_entry_hash(&self) -> Result<String, DIDWebVHError> {
        let jcs = to_string(self).map_err(|e| {
            DIDWebVHError::SCIDError(format!("Couldn't generate JCS from LogEntry. Reason: {e}",))
        })?;
        debug!("JCS for LogEntry hash: {}", jcs);

        // SHA_256 code = 0x12, length of SHA256 is 32 bytes
        let hash_encoded = Multihash::<32>::wrap(0x12, Sha256::digest(jcs.as_bytes()).as_slice())
            .map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't create multihash encoding for LogEntry. Reason: {e}",
            ))
        })?;
        Ok(hash_encoded.to_bytes().to_base58())
    }

    pub fn validate_witness_proof(
        &self,
        witness_proof: &DataIntegrityProof,
    ) -> Result<bool, DIDWebVHError> {
        // Verify the Data Integrity Proof against the Signing Document
        verify_data(
            &json!({"versionId": &self.get_version_id()}),
            None,
            witness_proof,
        )
        .map_err(|e| {
            DIDWebVHError::LogEntryError(format!("Data Integrity Proof verification failed: {e}"))
        })?;

        Ok(true)
    }

    /// Splits the version number and the version hash for a DID versionId
    pub fn get_version_id_fields(&self) -> Result<(u32, String), DIDWebVHError> {
        match self {
            LogEntry::Spec1_0(log_entry) => {
                LogEntry::parse_version_id_fields(&log_entry.version_id)
            }
            LogEntry::Spec1_0Pre(log_entry) => {
                LogEntry::parse_version_id_fields(&log_entry.version_id)
            }
        }
    }

    /// Splits the version number and the version hash for a DID versionId
    pub fn parse_version_id_fields(version_id: &str) -> Result<(u32, String), DIDWebVHError> {
        let Some((id, hash)) = version_id.split_once('-') else {
            return Err(DIDWebVHError::ValidationError(format!(
                "versionID ({version_id}) doesn't match format <int>-<hash>",
            )));
        };
        let id = id.parse::<u32>().map_err(|e| {
            DIDWebVHError::ValidationError(
                format!("Failed to parse version ID ({id}) as u32: {e}",),
            )
        })?;
        Ok((id, hash.to_string()))
    }

    /// Create a new LogEntry depending on the WebVH Version
    pub(crate) fn create(
        version_id: String,
        version_time: DateTime<FixedOffset>,
        parameters: Parameters,
        state: Value,
        webvh_version: Version,
    ) -> Result<LogEntry, DIDWebVHError> {
        match webvh_version {
            Version::V1_0 => LogEntry1_0::create(version_id, version_time, parameters, state),
            Version::V1_0Pre => Err(DIDWebVHError::LogEntryError(
                "WebVH Version must be 1.0 or higher".to_string(),
            )),
        }
    }
}

impl LogEntryMethods for LogEntry {
    fn get_version_time_string(&self) -> String {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_version_time_string(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_version_time_string(),
        }
    }

    fn get_version_id(&self) -> String {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_version_id(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_version_id(),
        }
    }

    fn set_version_id(&mut self, version_id: &str) {
        match self {
            LogEntry::Spec1_0(log_entry) => {
                log_entry.set_version_id(version_id);
            }
            LogEntry::Spec1_0Pre(log_entry) => {
                log_entry.set_version_id(version_id);
            }
        }
    }

    fn get_parameters(&self) -> Parameters {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_parameters(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_parameters(),
        }
    }

    fn add_proof(&mut self, proof: DataIntegrityProof) {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.add_proof(proof),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.add_proof(proof),
        }
    }

    fn get_proofs(&self) -> &Vec<DataIntegrityProof> {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_proofs(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_proofs(),
        }
    }

    fn clear_proofs(&mut self) {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.clear_proofs(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.clear_proofs(),
        }
    }

    fn get_scid(&self) -> Option<String> {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_scid(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_scid(),
        }
    }
    fn get_version_time(&self) -> DateTime<FixedOffset> {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_version_time(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_version_time(),
        }
    }
    fn get_state(&self) -> &Value {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_state(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_state(),
        }
    }
}
