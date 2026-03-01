//! WebVH Specification pre 1.0 implementation
//! This exists as there was a period of time where some LogEntries
//! for version 1.0 may contain nulls instead of empty arrays

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    DIDWebVHError,
    log_entry::{LogEntry, LogEntryCreate, format_version_time, impl_log_entry_common},
    parameters::{Parameters, spec_1_0_pre::Parameters1_0Pre},
};

/// Each version of the DID gets a new log entry
/// [Log Entries](https://identity.foundation/didwebvh/v1.0/#the-did-log-file)
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry1_0Pre {
    /// format integer-prev_hash
    pub version_id: String,

    /// ISO 8601 date format
    #[serde(serialize_with = "format_version_time")]
    pub version_time: DateTime<FixedOffset>,

    /// Parameters for this LogEntry
    pub parameters: Parameters1_0Pre,

    /// DID document
    pub state: Value,

    /// Data Integrity Proof
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub proof: Vec<affinidi_data_integrity::DataIntegrityProof>,
}

impl_log_entry_common!(LogEntry1_0Pre);

impl LogEntryCreate for LogEntry1_0Pre {
    fn create(
        _: String,
        _: DateTime<FixedOffset>,
        _: Parameters,
        _: Value,
    ) -> Result<LogEntry, DIDWebVHError> {
        Err(DIDWebVHError::LogEntryError(
            "LogEntry1_0Pre cannot be created directly. Use LogEntry1_0Pre::new() instead."
                .to_string(),
        ))
    }
}
