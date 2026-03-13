use std::sync::Arc;

use crate::{
    DIDWebVHError, Multibase, Version,
    log_entry::{LogEntry, LogEntryMethods},
    parameters::Parameters,
    witness::Witnesses,
};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Tracks validation status of a LogEntry
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum LogEntryValidationStatus {
    /// LogEntry failed validation
    Invalid(String),
    /// Validation process has NOT started yet
    #[default]
    NotValidated,
    /// LogEntry has been validated (step 1 of 2)
    LogEntryOnly,
    /// Witness Proof for this LogEntry has been validated (step 2 of 2)
    WitnessProof,
    /// LogEntry has been fully Validated
    Ok,
}

/// Manages state relating to a LogEntry during validation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntryState {
    /// webvh LogEntry record
    pub log_entry: LogEntry,

    /// Integer representing versionId for this LogEntry
    pub version_number: u32,

    /// After validation, parameters that were active at that time are stored here
    pub validated_parameters: Parameters,

    /// Validation status of this record
    pub validation_status: LogEntryValidationStatus,
}

impl LogEntryState {
    /// Validates a LogEntry
    /// NOTE: Does NOT validate witness proofs!
    pub fn verify_log_entry(
        &mut self,
        previous_log_entry: Option<&LogEntryState>,
    ) -> Result<(), DIDWebVHError> {
        if self.validation_status == LogEntryValidationStatus::Ok {
            // already validated
            return Ok(());
        }

        let parameters = self.log_entry.verify_log_entry(
            previous_log_entry.map(|e| &e.log_entry),
            previous_log_entry.map(|e| &e.validated_parameters),
        )?;

        self.validated_parameters = parameters;
        self.validation_status = LogEntryValidationStatus::LogEntryOnly;

        Ok(())
    }

    /// Returns the active witnesses for this LogEntry
    pub fn get_active_witnesses(&self) -> Option<Arc<Witnesses>> {
        self.validated_parameters.active_witness.as_ref().cloned()
    }

    /// Get LogEntry State (DID Document)
    /// WARN: This returns the raw DID Document only! It does not augment with implied services
    /// For use in a resolver please use [get_did_document](Self::get_did_document)
    pub fn get_state(&self) -> &Value {
        self.log_entry.get_state()
    }

    /// Returns a fully formed DID Document for this LogEntry
    /// This will add implied services as defined by the WebVH Specification
    /// To get the raw DID Document only, use [get_state](Self::get_state)
    pub fn get_did_document(&self) -> Result<Value, DIDWebVHError> {
        self.log_entry.get_did_document()
    }

    /// Get the version Number of this LogEntry
    /// WHich is the prefix in versionId
    pub(crate) fn get_version_number(&self) -> u32 {
        self.version_number
    }

    pub(crate) fn get_version_time_string(&self) -> String {
        self.log_entry.get_version_time_string()
    }

    pub(crate) fn get_version_time(&self) -> DateTime<FixedOffset> {
        self.log_entry.get_version_time()
    }

    /// WebVH Specification Version
    /// If not specified, will default to the Default Version
    pub(crate) fn get_webvh_version(&self) -> Version {
        self.validated_parameters.method.unwrap_or_default()
    }

    /// Returns the full versionId string for this log entry.
    pub fn get_version_id(&self) -> String {
        self.log_entry.get_version_id()
    }

    pub(crate) fn get_scid(&self) -> Option<String> {
        self.validated_parameters
            .scid
            .clone()
            .map(|scid| scid.to_string())
    }

    pub(crate) fn get_active_update_keys(&self) -> Arc<Vec<Multibase>> {
        self.validated_parameters.active_update_keys.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_entry::spec_1_0::LogEntry1_0;
    use crate::parameters::spec_1_0::Parameters1_0;
    use chrono::Utc;
    use serde_json::json;

    fn make_entry(version_id: &str, version_number: u32) -> LogEntryState {
        LogEntryState {
            version_number,
            log_entry: LogEntry::Spec1_0(LogEntry1_0 {
                proof: vec![],
                parameters: Parameters1_0::default(),
                version_id: version_id.to_string(),
                version_time: Utc::now().fixed_offset(),
                state: json!({"id": "did:webvh:scid123:example.com"}),
            }),
            validated_parameters: Parameters::default(),
            validation_status: LogEntryValidationStatus::NotValidated,
        }
    }

    #[test]
    fn get_version_id_returns_log_entry_version() {
        let entry = make_entry("3-abc123", 3);
        assert_eq!(entry.get_version_id(), "3-abc123");
    }

    #[test]
    fn get_version_number_returns_stored_number() {
        let entry = make_entry("5-xyz", 5);
        assert_eq!(entry.get_version_number(), 5);
    }

    #[test]
    fn get_state_returns_did_document() {
        let entry = make_entry("1-test", 1);
        let state = entry.get_state();
        assert_eq!(
            state["id"].as_str().unwrap(),
            "did:webvh:scid123:example.com"
        );
    }

    #[test]
    fn get_active_witnesses_returns_none_by_default() {
        let entry = make_entry("1-test", 1);
        assert!(entry.get_active_witnesses().is_none());
    }

    #[test]
    fn get_active_witnesses_returns_configured_witnesses() {
        let mut entry = make_entry("1-test", 1);
        let witnesses = Witnesses::Value {
            threshold: 1,
            witnesses: vec![],
        };
        entry.validated_parameters.active_witness = Some(Arc::new(witnesses));
        assert!(entry.get_active_witnesses().is_some());
    }

    #[test]
    fn get_scid_returns_none_by_default() {
        let entry = make_entry("1-test", 1);
        assert!(entry.get_scid().is_none());
    }

    #[test]
    fn get_scid_returns_configured_scid() {
        let mut entry = make_entry("1-test", 1);
        entry.validated_parameters.scid = Some(Arc::new("scid123".to_string()));
        assert_eq!(entry.get_scid().unwrap(), "scid123");
    }

    #[test]
    fn get_webvh_version_defaults_to_v1_0() {
        let entry = make_entry("1-test", 1);
        assert_eq!(entry.get_webvh_version(), Version::V1_0);
    }

    #[test]
    fn validation_status_defaults_to_not_validated() {
        let entry = make_entry("1-test", 1);
        assert_eq!(
            entry.validation_status,
            LogEntryValidationStatus::NotValidated
        );
    }
}
