//! WebVH Specification 1.0 implementation

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    DIDWebVHError,
    log_entry::{LogEntry, LogEntryCreate, format_version_time, impl_log_entry_common},
    parameters::{Parameters, spec_1_0::Parameters1_0},
};

/// Each version of the DID gets a new log entry
/// [Log Entries](https://identity.foundation/didwebvh/v1.0/#the-did-log-file)
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct LogEntry1_0 {
    /// format integer-prev_hash
    pub version_id: String,

    /// ISO 8601 date format
    #[serde(serialize_with = "format_version_time")]
    #[cfg_attr(
        feature = "arbitrary",
        arbitrary(with = crate::arbitrary_support::arb_version_time)
    )]
    pub version_time: DateTime<FixedOffset>,

    /// Parameters for this LogEntry
    pub parameters: Parameters1_0,

    /// DID document
    #[cfg_attr(
        feature = "arbitrary",
        arbitrary(with = crate::arbitrary_support::arb_json_value)
    )]
    pub state: Value,

    /// Data Integrity Proof
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    #[cfg_attr(
        feature = "arbitrary",
        arbitrary(with = crate::arbitrary_support::arb_no_proofs)
    )]
    pub proof: Vec<affinidi_data_integrity::DataIntegrityProof>,
}

impl_log_entry_common!(LogEntry1_0);

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
