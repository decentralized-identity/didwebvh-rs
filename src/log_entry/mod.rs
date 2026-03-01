/*!
*   Webvh utilizes Log Entries for each version change of the DID Document.
*/
use crate::{
    DIDWebVHError, Version,
    log_entry::{spec_1_0::LogEntry1_0, spec_1_0_pre::LogEntry1_0Pre},
    parameters::Parameters,
    witness::Witnesses,
};
use affinidi_data_integrity::{
    DataIntegrityProof, verification_proof::verify_data_with_public_key,
};
use affinidi_secrets_resolver::secrets::Secret;
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

pub trait PublicKey {
    fn get_public_key_bytes(&self) -> Result<Vec<u8>, DIDWebVHError>;
}

impl PublicKey for DataIntegrityProof {
    fn get_public_key_bytes(&self) -> Result<Vec<u8>, DIDWebVHError> {
        // Create public key bytes from Verification Material
        if !self.verification_method.starts_with("did:key:") {
            return Err(DIDWebVHError::InvalidMethodIdentifier(
                "Verification method must start with 'did:key:'".to_string(),
            ));
        }
        let Some((_, public_key)) = self.verification_method.split_once('#') else {
            return Err(DIDWebVHError::InvalidMethodIdentifier(
                "Invalid verification method format".to_string(),
            ));
        };
        Secret::decode_multikey(public_key)
            .map_err(|e| DIDWebVHError::InvalidMethodIdentifier(format!("Invalid public key: {e}")))
    }
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

    /// Get the raw DID Document state
    /// Does NOT include implied services
    fn get_state(&self) -> &Value;

    /// Returns a full DID Document including implied services
    fn get_did_document(&self) -> Result<Value, DIDWebVHError>;
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

/// Shared helper: serialize versionTime with seconds-only precision
pub(crate) fn format_version_time<S>(
    date: &DateTime<FixedOffset>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Shared helper: split a versionId into (number, hash)
pub fn parse_version_id_fields(version_id: &str) -> Result<(u32, String), DIDWebVHError> {
    let Some((id, hash)) = version_id.split_once('-') else {
        return Err(DIDWebVHError::ValidationError(format!(
            "versionID ({version_id}) doesn't match format <int>-<hash>",
        )));
    };
    let id = id.parse::<u32>().map_err(|e| {
        DIDWebVHError::ValidationError(format!(
            "Failed to parse version ID ({id}) as u32: {e}",
        ))
    })?;
    Ok((id, hash.to_string()))
}

/// Implements the common inherent methods and `LogEntryMethods` trait for a log entry struct.
///
/// The struct must have fields: `version_id`, `version_time`, `parameters`, `state`, `proof`.
/// The parameters type must implement `Into<Parameters>` and `Clone`.
macro_rules! impl_log_entry_common {
    ($type:ty) => {
        impl $type {
            /// Calculates a Log Entry hash
            pub fn generate_log_entry_hash(&self) -> Result<String, DIDWebVHError> {
                let jcs = serde_json_canonicalizer::to_string(self).map_err(|e| {
                    DIDWebVHError::SCIDError(format!(
                        "Couldn't generate JCS from LogEntry. Reason: {e}",
                    ))
                })?;
                tracing::debug!("JCS for LogEntry hash: {}", jcs);

                let hash_encoded =
                    multihash::Multihash::<32>::wrap(0x12, <sha2::Sha256 as sha2::Digest>::digest(jcs.as_bytes()).as_slice())
                        .map_err(|e| {
                            DIDWebVHError::SCIDError(format!(
                                "Couldn't create multihash encoding for LogEntry. Reason: {e}",
                            ))
                        })?;
                Ok(base58::ToBase58::to_base58(hash_encoded.to_bytes().as_slice()))
            }

            pub fn validate_witness_proof(
                &self,
                witness_proof: &affinidi_data_integrity::DataIntegrityProof,
            ) -> Result<bool, DIDWebVHError> {
                use crate::log_entry::PublicKey;
                affinidi_data_integrity::verification_proof::verify_data_with_public_key(
                    &serde_json::json!({"versionId": &self.version_id}),
                    None,
                    witness_proof,
                    witness_proof.get_public_key_bytes()?.as_slice(),
                )
                .map_err(|e| {
                    DIDWebVHError::LogEntryError(format!(
                        "Data Integrity Proof verification failed: {e}"
                    ))
                })?;
                Ok(true)
            }

            /// Splits the version number and the version hash for a DID versionId
            pub fn get_version_id_fields(&self) -> Result<(u32, String), DIDWebVHError> {
                crate::log_entry::parse_version_id_fields(&self.version_id)
            }

            /// Splits the version number and the version hash for a DID versionId
            pub fn parse_version_id_fields(
                version_id: &str,
            ) -> Result<(u32, String), DIDWebVHError> {
                crate::log_entry::parse_version_id_fields(version_id)
            }
        }

        impl crate::log_entry::LogEntryMethods for $type {
            fn get_version_time_string(&self) -> String {
                self.version_time
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            }

            fn get_version_time(&self) -> chrono::DateTime<chrono::FixedOffset> {
                self.version_time
            }

            fn get_version_id(&self) -> String {
                self.version_id.clone()
            }

            fn set_version_id(&mut self, version_id: &str) {
                self.version_id = version_id.to_string();
            }

            fn get_parameters(&self) -> crate::parameters::Parameters {
                self.parameters.clone().into()
            }

            fn add_proof(&mut self, proof: affinidi_data_integrity::DataIntegrityProof) {
                self.proof.push(proof);
            }

            fn get_proofs(&self) -> &Vec<affinidi_data_integrity::DataIntegrityProof> {
                &self.proof
            }

            fn clear_proofs(&mut self) {
                self.proof.clear();
            }

            fn get_scid(&self) -> Option<String> {
                self.parameters.scid.clone().map(|scid| scid.to_string())
            }

            fn get_state(&self) -> &serde_json::Value {
                &self.state
            }

            fn get_did_document(&self) -> Result<serde_json::Value, DIDWebVHError> {
                let services = self.state.get("service");
                let mut new_state = self.state.clone();
                if let Some(id) = self.state.get("id")
                    && let Some(id) = id.as_str()
                {
                    crate::resolve::implicit::update_implicit_services(
                        services, &mut new_state, id,
                    )?;
                    Ok(new_state)
                } else {
                    Err(DIDWebVHError::ValidationError(
                        "DID Document is missing 'id' field or it's not a string".to_string(),
                    ))
                }
            }
        }
    };
}

pub(crate) use impl_log_entry_common;

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
                if let Some(v) = parameters.get("updateKeys")
                    && v.is_null()
                {
                    pre_version = true;
                }
                if let Some(v) = parameters.get("nextKeyHashes")
                    && v.is_null()
                {
                    pre_version = true;
                }
                if let Some(v) = parameters.get("witness")
                    && v.is_null()
                {
                    pre_version = true;
                }
                if let Some(v) = parameters.get("watchers")
                    && v.is_null()
                {
                    pre_version = true;
                }
                if let Some(v) = parameters.get("ttl")
                    && v.is_null()
                {
                    pre_version = true;
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
        let append = if self.get_version_id_fields()?.0 == 1 {
            false // Don't append to the file if this is the first version
        } else {
            true // Append to the file for all subsequent versions
        };

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(!append)
            .append(append)
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

    /// Validates a witness proof against the log entry
    pub fn validate_witness_proof(
        &self,
        witness_proof: &DataIntegrityProof,
    ) -> Result<bool, DIDWebVHError> {
        // Verify the Data Integrity Proof against the Signing Document
        verify_data_with_public_key(
            &json!({"versionId": &self.get_version_id()}),
            None,
            witness_proof,
            witness_proof.get_public_key_bytes()?.as_slice(),
        )
        .map_err(|e| {
            DIDWebVHError::LogEntryError(format!("Data Integrity Proof verification failed: {e}"))
        })?;

        Ok(true)
    }

    /// Splits the version number and the version hash for a DID versionId
    pub fn get_version_id_fields(&self) -> Result<(u32, String), DIDWebVHError> {
        match self {
            LogEntry::Spec1_0(log_entry) => parse_version_id_fields(&log_entry.version_id),
            LogEntry::Spec1_0Pre(log_entry) => parse_version_id_fields(&log_entry.version_id),
        }
    }

    /// Splits the version number and the version hash for a DID versionId
    pub fn parse_version_id_fields(version_id: &str) -> Result<(u32, String), DIDWebVHError> {
        parse_version_id_fields(version_id)
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

    fn get_did_document(&self) -> Result<Value, DIDWebVHError> {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_did_document(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_did_document(),
        }
    }
}
