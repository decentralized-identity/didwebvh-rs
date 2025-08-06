use std::sync::Arc;

use crate::{
    DIDWebVHError, Version,
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
#[derive(Debug)]
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
    pub fn get_state(&self) -> &Value {
        self.log_entry.get_state()
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

    pub fn get_version_id(&self) -> String {
        self.log_entry.get_version_id()
    }

    pub(crate) fn get_scid(&self) -> Option<String> {
        self.validated_parameters
            .scid
            .clone()
            .map(|scid| scid.to_string())
    }
}
