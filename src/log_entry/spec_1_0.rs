//! WebVH Specification 1.0 implementation

use affinidi_data_integrity::{DataIntegrityProof, verification_proof::verify_data};
use base58::ToBase58;
use chrono::{DateTime, FixedOffset};
use multihash::Multihash;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use serde_json_canonicalizer::to_string;
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::{
    DIDWebVHError,
    log_entry::{LogEntry, LogEntryCreate, LogEntryMethods},
    parameters::{Parameters, spec_1_0::Parameters1_0},
};

/// Each version of the DID gets a new log entry
/// [Log Entries](https://identity.foundation/didwebvh/v1.0/#the-did-log-file)
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry1_0 {
    /// format integer-prev_hash
    pub version_id: String,

    /// ISO 8601 date format
    #[serde(serialize_with = "format_version_time")]
    pub version_time: DateTime<FixedOffset>,

    /// Parameters for this LogEntry
    pub parameters: Parameters1_0,

    /// DID document
    pub state: Value,

    /// Data Integrity Proof
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub proof: Vec<DataIntegrityProof>,
}

// Helper function to serialize versionTime with seconds only precision
fn format_version_time<S>(date: &DateTime<FixedOffset>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

impl LogEntry1_0 {
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
        verify_data(&json!({"versionId": &self.version_id}), None, witness_proof).map_err(|e| {
            DIDWebVHError::LogEntryError(format!("Data Integrity Proof verification failed: {e}"))
        })?;

        Ok(true)
    }

    /// Splits the version number and the version hash for a DID versionId
    pub fn get_version_id_fields(&self) -> Result<(u32, String), DIDWebVHError> {
        LogEntry::parse_version_id_fields(&self.version_id)
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
}

impl LogEntryCreate for LogEntry1_0 {
    fn create(
        version_id: String,
        version_time: DateTime<FixedOffset>,
        parameters: Parameters,
        state: Value,
    ) -> Result<LogEntry, DIDWebVHError> {
        Ok(LogEntry::Spec1_0(LogEntry1_0 {
            version_id,
            version_time,
            parameters: parameters.into(),
            state,
            proof: vec![],
        }))
    }
}

impl LogEntryMethods for LogEntry1_0 {
    fn get_version_time_string(&self) -> String {
        self.version_time
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    fn get_version_time(&self) -> DateTime<FixedOffset> {
        self.version_time
    }

    fn get_version_id(&self) -> String {
        self.version_id.clone()
    }

    fn set_version_id(&mut self, version_id: &str) {
        self.version_id = version_id.to_string();
    }

    fn get_parameters(&self) -> Parameters {
        self.parameters.clone().into()
    }

    fn add_proof(&mut self, proof: DataIntegrityProof) {
        self.proof.push(proof);
    }

    fn get_proofs(&self) -> &Vec<DataIntegrityProof> {
        &self.proof
    }

    fn clear_proofs(&mut self) {
        self.proof.clear();
    }

    fn get_scid(&self) -> Option<String> {
        self.parameters.scid.clone().map(|scid| scid.to_string())
    }

    fn get_state(&self) -> &Value {
        &self.state
    }
}
