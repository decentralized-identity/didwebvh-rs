/*!
*   DID method for Web with Verifiable History
*   See [WebVH Spec](https://identity.foundation/didwebvh/v1.0)
*/
#![warn(missing_docs)]

use crate::{
    log_entry::{LogEntry, LogEntryMethods, MetaData},
    log_entry_state::{LogEntryState, LogEntryValidationStatus},
    parameters::Parameters,
    witness::proofs::WitnessProofCollection,
};
use affinidi_data_integrity::DataIntegrityProof;
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, FixedOffset, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fmt, sync::Arc};
use thiserror::Error;
use tracing::debug;

pub mod create;
pub mod did_web;
pub mod log_entry;
/// Manages per-entry validation state during DID log processing.
pub mod log_entry_state;
pub mod multibase_type;
pub mod parameters;
pub mod prelude;
pub mod resolve;
/// Parsing and conversion of `did:webvh` URLs and HTTP URLs.
pub mod url;
pub mod validate;
pub mod witness;

pub use multibase_type::Multibase;

#[cfg(test)]
pub(crate) mod test_utils;

// Re-export Affinidi Secrets Resolver so others can create Secrets
pub use affinidi_secrets_resolver;

// Re-export Signer trait and KeyType so consumers can implement custom signing backends.
//
// # Security note for Signer implementors
//
// If your `Signer` implementation holds key material in memory (rather than
// delegating to an HSM/KMS), consider zeroizing sensitive buffers on drop
// (e.g. via the `zeroize` crate) to limit exposure of secrets in memory.
pub use affinidi_data_integrity::signer::Signer;
pub use affinidi_secrets_resolver::secrets::KeyType;

// Re-export async_trait so consumers implementing `Signer` don't need a separate dependency.
pub use async_trait::async_trait;

/// WebVH Specification supports multiple LogEntry versions in the same DID
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum Version {
    /// Official v1.0 specification
    #[default]
    V1_0,

    /// Pre 1.0 ratification, there was a change in how Parameters were reset
    /// Null values vs. empty arrays
    V1_0Pre,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Version::V1_0 => write!(f, "did:webvh:1.0"),
            Version::V1_0Pre => write!(f, "did:webvh:1.0"),
        }
    }
}

impl TryFrom<&str> for Version {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "did:webvh:1.0" => Ok(Version::V1_0),
            _ => Err(format!("Invalid WebVH Version: {value}")),
        }
    }
}

impl Version {
    /// Turns the Version to a number so we can compare for version control
    pub(crate) fn as_f32(&self) -> f32 {
        match self {
            Version::V1_0Pre => 1.0, // Considered to be 1.0
            Version::V1_0 => 1.0,
        }
    }
}

/// Magic string used for first LogEntry
pub const SCID_HOLDER: &str = "{SCID}";

/// Helper to safely get a mutable reference to a JSON object map.
pub(crate) fn ensure_object_mut(
    value: &mut Value,
) -> Result<&mut serde_json::Map<String, Value>, DIDWebVHError> {
    value
        .as_object_mut()
        .ok_or_else(|| DIDWebVHError::DIDError("Expected a JSON object".to_string()))
}

/// Error types for WebVH method
#[derive(Error, Debug)]
pub enum DIDWebVHError {
    /// The DID has been deactivated and can no longer be resolved.
    #[error("DeactivatedError: {0}")]
    DeactivatedError(String),
    /// A general DID-related error (e.g. invalid query parameters).
    #[error("DIDError: {0}")]
    DIDError(String),
    /// The DID method-specific identifier is malformed or invalid.
    #[error("Invalid method identifier: {0}")]
    InvalidMethodIdentifier(String),
    /// An error occurred while parsing or processing a log entry.
    #[error("LogEntryError: {0}")]
    LogEntryError(String),
    /// A network request failed.
    ///
    /// Consumers can inspect `status_code` to distinguish HTTP-level errors (e.g. 404, 500)
    /// from transport-level failures (where `status_code` is `None`).
    #[error("NetworkError: {message} (url: {url})")]
    NetworkError {

        /// The URL that was being fetched.
        url: String,
        /// HTTP status code, if the server responded.
        status_code: Option<u16>,
        /// Human-readable error description.
        message: String,
    },
    /// The requested DID or log entry version was not found.
    #[error("DID Query NotFound: {0}")]
    NotFound(String),
    /// The HTTP response body exceeds the maximum allowed size.
    #[error("ResponseTooLarge: response from {url} exceeds maximum allowed size of {max_bytes} bytes")]
    ResponseTooLarge {
        /// The URL that was being fetched.
        url: String,
        /// The maximum number of bytes allowed.
        max_bytes: u64,
    },
    /// The requested operation is not yet implemented.
    #[error("NotImplemented: {0}")]
    NotImplemented(String),
    /// A log entry parameters block is invalid or inconsistent.
    #[error("ParametersError: {0}")]
    ParametersError(String),
    /// An error related to the Self-Certifying Identifier (SCID).
    #[error("SCIDError: {0}")]
    SCIDError(String),
    /// A server-side error occurred while processing the DID.
    #[error("ServerError: {0}")]
    ServerError(String),
    /// The DID method is not `did:webvh`.
    #[error("UnsupportedMethod: {0}")]
    UnsupportedMethod(String),
    /// There was an error in validating the DID
    #[error("ValidationError: {0}")]
    ValidationError(String),
    /// An error occurred while working with Witness Proofs
    #[error("WitnessProofError: {0}")]
    WitnessProofError(String),
}

impl DIDWebVHError {
    /// Create a [`DIDWebVHError::ValidationError`] with version context.
    pub fn validation(msg: impl fmt::Display, version: u32) -> Self {
        Self::ValidationError(format!("[version {version}] {msg}"))
    }

    /// Create a [`DIDWebVHError::ParametersError`] with field context.
    pub fn parameter(field: &str, msg: impl fmt::Display) -> Self {
        Self::ParametersError(format!("[{field}] {msg}"))
    }

    /// Create a [`DIDWebVHError::LogEntryError`] with version context.
    pub fn log_entry(msg: impl fmt::Display, version: u32) -> Self {
        Self::LogEntryError(format!("[version {version}] {msg}"))
    }
}

/// Information relating to a webvh DID
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DIDWebVHState {
    pub(crate) log_entries: Vec<LogEntryState>,
    pub(crate) witness_proofs: WitnessProofCollection,

    /// What SCID is this state representing?
    pub(crate) scid: String,

    /// Timestamp of the first LogEntry
    pub(crate) meta_first_ts: String,

    /// Timestamp of the last LogEntry
    pub(crate) meta_last_ts: String,

    /// Timestamp for when this DID will expire and need to be reloaded
    pub(crate) expires: DateTime<FixedOffset>,

    /// Validated?
    pub(crate) validated: bool,

    /// Deactivated?
    pub(crate) deactivated: bool,
}

impl DIDWebVHState {
    /// Returns a reference to all log entries.
    pub fn log_entries(&self) -> &[LogEntryState] {
        &self.log_entries
    }

    /// Returns a mutable reference to the log entries.
    pub fn log_entries_mut(&mut self) -> &mut Vec<LogEntryState> {
        &mut self.log_entries
    }

    /// Removes and returns the last log entry, if any.
    pub fn remove_last_log_entry(&mut self) -> Option<LogEntryState> {
        self.log_entries.pop()
    }

    /// Returns a reference to the witness proof collection.
    pub fn witness_proofs(&self) -> &WitnessProofCollection {
        &self.witness_proofs
    }

    /// Returns a mutable reference to the witness proof collection.
    pub fn witness_proofs_mut(&mut self) -> &mut WitnessProofCollection {
        &mut self.witness_proofs
    }

    /// Returns references to both the log entries and the mutable witness proof collection.
    /// This allows simultaneous read access to log entries and write access to witness proofs,
    /// which would otherwise conflict when using separate accessor methods.
    pub fn log_entries_and_witness_proofs_mut(
        &mut self,
    ) -> (&[LogEntryState], &mut WitnessProofCollection) {
        (&self.log_entries, &mut self.witness_proofs)
    }

    /// Sets the witness proof collection.
    pub fn set_witness_proofs(&mut self, proofs: WitnessProofCollection) {
        self.witness_proofs = proofs;
    }

    /// Returns the SCID for this DID.
    pub fn scid(&self) -> &str {
        &self.scid
    }

    /// Returns the timestamp of the first log entry.
    pub fn meta_first_ts(&self) -> &str {
        &self.meta_first_ts
    }

    /// Returns the timestamp of the last log entry.
    pub fn meta_last_ts(&self) -> &str {
        &self.meta_last_ts
    }

    /// Returns the expiration timestamp for cached resolution.
    pub fn expires(&self) -> DateTime<FixedOffset> {
        self.expires
    }

    /// Returns whether this DID state has been validated.
    pub fn validated(&self) -> bool {
        self.validated
    }

    /// Returns whether this DID has been deactivated.
    pub fn deactivated(&self) -> bool {
        self.deactivated
    }
}

impl DIDWebVHState {
    /// Convenience method to load LogEntries from a file, will ensure default state is set
    /// NOTE: NO WEBVH VALIDATION IS DONE HERE
    pub fn load_log_entries_from_file(&mut self, file_path: &str) -> Result<(), DIDWebVHError> {
        for log_entry in LogEntry::load_from_file(file_path)? {
            self.log_entries.push(LogEntryState {
                log_entry: log_entry.clone(),
                version_number: log_entry.get_version_id_fields()?.0,
                validation_status: LogEntryValidationStatus::NotValidated,
                validated_parameters: Parameters::default(),
            });
        }
        Ok(())
    }

    /// Convenience method to load WitnessProofs from a file, will ensure default state is set
    /// NOTE: NO WEBVH VALIDATION IS DONE HERE
    /// NOTE: Not all DIDs will have witness proofs, so this is optional
    pub fn load_witness_proofs_from_file(&mut self, file_path: &str) {
        match WitnessProofCollection::read_from_file(file_path) {
            Ok(proofs) => self.witness_proofs = proofs,
            Err(e) => tracing::warn!("Failed to load witness proofs from {}: {}", file_path, e),
        }
    }

    /// Creates a new LogEntry appended to this DID's history.
    ///
    /// Validates that `signing_key` is authorized (via update keys or pre-rotation
    /// hashes), computes the parameter diff against the previous entry, signs the
    /// entry using the provided [`Signer`], and returns the resulting [`LogEntryState`].
    ///
    /// # Arguments
    /// * `version_time` — Timestamp for the entry; defaults to now if `None`.
    /// * `document` — The DID Document as a JSON Value.
    /// * `parameters` — Full parameter set; a diff against the previous entry is computed automatically.
    /// * `signing_key` — Any [`Signer`] implementation (e.g. `Secret`, HSM, KMS).
    pub async fn create_log_entry(
        &mut self,
        version_time: Option<DateTime<FixedOffset>>,
        document: &Value,
        parameters: &Parameters,
        signing_key: &dyn Signer,
    ) -> Result<&LogEntryState, DIDWebVHError> {
        let now = Utc::now();
        let last_log_entry = self.log_entries.last();

        // Ensure that the signing key is valid
        Self::check_signing_key(last_log_entry, parameters, signing_key)?;

        // If this LogEntry causes the DID to be deactivated, then updateKeys should be set to
        // invalid
        if parameters.deactivated.unwrap_or_default() {
            let version = last_log_entry.map_or(1, |e| e.version_number + 1);
            // DID will be deactivated
            if let Some(keys) = &parameters.update_keys
                && keys.is_empty()
            {
                // Valid empty UpdateKeys for a deactivated DID
            } else {
                return Err(DIDWebVHError::log_entry(
                    "Cannot deactivate DID unless update_keys is set to []",
                    version,
                ));
            }
        }

        let mut new_entry = if let Some(last_log_entry) = last_log_entry {
            // Utilizes the previous LogEntry for some info

            debug!(
                "previous.validated parameters: {:#?}",
                last_log_entry.validated_parameters
            );

            // Ensure correct webvh version is being used
            let webvh_version = if let Some(this_version) = parameters.method {
                if this_version.as_f32() < 1.0 {
                    return Err(DIDWebVHError::LogEntryError(
                        "WebVH Version must be 1.0 or higher".to_string(),
                    ));
                } else if this_version.as_f32() < last_log_entry.get_webvh_version().as_f32() {
                    return Err(DIDWebVHError::LogEntryError(format!(
                        "This LogEntry WebVH Version ({}) must be equal or higher than the previous LogEntry version ({})",
                        this_version.as_f32(),
                        last_log_entry.get_webvh_version().as_f32()
                    )));
                } else {
                    this_version
                }
            } else {
                Version::default()
            };

            LogEntry::create(
                last_log_entry.get_version_id().to_string(),
                version_time.unwrap_or_else(|| now.fixed_offset()),
                // Only use the difference of the parameters
                parameters.diff(&last_log_entry.validated_parameters)?,
                document.clone(),
                webvh_version,
            )?
        } else {
            // First LogEntry so we need to set up a few things first
            // Ensure SCID field is set correctly

            // Ensure correct webvh version is being used
            let webvh_version = if let Some(this_version) = parameters.method {
                if this_version.as_f32() < 1.0 {
                    return Err(DIDWebVHError::LogEntryError(
                        "WebVH Version must be 1.0 or higher".to_string(),
                    ));
                } else {
                    this_version
                }
            } else {
                Version::default()
            };
            let mut parameters = parameters.clone();
            parameters.scid = Some(Arc::new(SCID_HOLDER.to_string()));
            parameters.method = Some(Version::default());

            let log_entry = LogEntry::create(
                SCID_HOLDER.to_string(),
                version_time.unwrap_or_else(|| now.fixed_offset()),
                // Only use the difference of the parameters
                parameters,
                document.clone(),
                webvh_version,
            )?;

            // Create the SCID from the first log entry
            let scid = log_entry.generate_first_scid()?;
            //
            // Replace all instances of {SCID} with the actual SCID
            let le_str = serde_json::to_string(&log_entry).map_err(|e| {
                DIDWebVHError::SCIDError(format!(
                    "Couldn't serialize LogEntry to JSON. Reason: {e}",
                ))
            })?;

            LogEntry::from_string_to_known_version(
                &le_str.replace(SCID_HOLDER, &scid),
                webvh_version,
            )?
        };

        // Create the entry hash for this Log Entry
        let entry_hash = new_entry.generate_log_entry_hash().map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate entryHash for first LogEntry. Reason: {e}",
            ))
        })?;

        let new_params = new_entry.get_parameters();

        let validated_parameters = if let Some(last_entry) = last_log_entry {
            // NOT first LogEntry
            // Increment the version-id
            let current_id = last_entry.get_version_number();
            new_entry.set_version_id(&[&(current_id + 1).to_string(), "-", &entry_hash].concat());
            self.meta_last_ts = new_entry.get_version_time().to_string();
            new_params.validate(Some(&last_entry.validated_parameters))?
        } else {
            // First LogEntry
            new_entry.set_version_id(&["1-", &entry_hash].concat());
            let scid = new_entry
                .get_scid()
                .ok_or_else(|| {
                    DIDWebVHError::LogEntryError("First LogEntry does not have a SCID!".to_string())
                })?
                .to_string();

            let validated_parameters = new_params.validate(None)?;
            //let mut validated_params = new_entry.get_parameters();
            //validated_params.active_witness = validated_params.witness.clone();
            self.meta_first_ts = new_entry.get_version_time_string().to_string();
            self.meta_last_ts = self.meta_first_ts.clone();
            self.scid = scid.to_string();
            validated_parameters
        };

        // Generate the proof for the log entry
        let proof = DataIntegrityProof::sign_jcs_data(&new_entry, None, signing_key, None)
            .await
            .map_err(|e| {
                DIDWebVHError::SCIDError(format!(
                    "Couldn't generate Data Integrity Proof for LogEntry. Reason: {e}"
                ))
            })?;

        new_entry.add_proof(proof);

        let id_number = new_entry.get_version_id_fields()?.0;

        self.log_entries.push(LogEntryState {
            log_entry: new_entry,
            version_number: id_number,
            validation_status: LogEntryValidationStatus::Ok,
            validated_parameters,
        });

        self.log_entries.last().ok_or_else(|| {
            DIDWebVHError::LogEntryError(
                "INTERNAL Error. Successfully created LogEntry, but can not find it!".to_string(),
            )
        })
    }

    /// Gets a specific LogEntry based on versionId, versionTime, or versionNumber
    /// Only one parameter should be set (mutual exclusivity enforced at parse time)
    pub fn get_specific_log_entry(
        &self,
        version_id: Option<&str>,
        version_time: Option<DateTime<FixedOffset>>,
        version_number: Option<u32>,
    ) -> Result<&LogEntryState, DIDWebVHError> {
        if let Some(version_id) = version_id {
            for log_entry in self.log_entries.iter() {
                if log_entry.get_version_id() == version_id {
                    return Ok(log_entry);
                }
            }
            return Err(DIDWebVHError::NotFound(format!(
                "No matching log entry for versionId={version_id}",
            )));
        }

        if let Some(version_number) = version_number {
            for log_entry in self.log_entries.iter() {
                if log_entry.get_version_number() == version_number {
                    return Ok(log_entry);
                }
            }
            return Err(DIDWebVHError::NotFound(format!(
                "No matching log entry for versionNumber={version_number}",
            )));
        }

        if let Some(version_time) = version_time {
            let mut found = None;
            for log_entry in self.log_entries.iter() {
                if log_entry.get_version_time() <= version_time {
                    found = Some(log_entry);
                } else {
                    break;
                }
            }
            if let Some(found) = found {
                return Ok(found);
            }
            return Err(DIDWebVHError::NotFound(format!(
                "No matching log entry for versionTime={version_time}",
            )));
        }

        Err(DIDWebVHError::NotFound(
            "No query parameter specified (versionId, versionTime, or versionNumber)".to_string(),
        ))
    }

    /// Creates a MetaData struct from a validated LogEntryState
    pub fn generate_meta_data(&self, log_entry: &LogEntryState) -> MetaData {
        MetaData {
            version_id: log_entry.get_version_id().to_string(),
            version_time: log_entry.get_version_time_string().to_string(),
            created: self.meta_first_ts.clone(),
            updated: self.meta_last_ts.clone(),
            scid: self.scid.clone(),
            portable: log_entry.validated_parameters.portable.unwrap_or(false),
            deactivated: self.deactivated,
            witness: log_entry
                .validated_parameters
                .active_witness
                .as_deref()
                .cloned(),
            watchers: log_entry.validated_parameters.watchers.as_deref().cloned(),
        }
    }

    // -----------------------------------------------------------------------
    // Convenience API
    // -----------------------------------------------------------------------

    /// Returns a clone of the current parameters from the last log entry.
    fn current_parameters(&self) -> Result<Parameters, DIDWebVHError> {
        self.log_entries
            .last()
            .map(|e| e.validated_parameters.clone())
            .ok_or_else(|| DIDWebVHError::LogEntryError("No log entries exist".to_string()))
    }

    /// Returns a clone of the current DID Document from the last log entry.
    fn current_document(&self) -> Result<Value, DIDWebVHError> {
        self.log_entries
            .last()
            .map(|e| e.get_state().clone())
            .ok_or_else(|| DIDWebVHError::LogEntryError("No log entries exist".to_string()))
    }

    /// Update the DID document, creating a new log entry.
    ///
    /// This is a convenience wrapper around [`create_log_entry()`](Self::create_log_entry)
    /// that reuses the current parameters and only changes the document.
    pub async fn update_document(
        &mut self,
        document: Value,
        signing_key: &dyn Signer,
    ) -> Result<&LogEntryState, DIDWebVHError> {
        let params = self.current_parameters()?;
        self.create_log_entry(None, &document, &params, signing_key)
            .await
    }

    /// Rotate the DID's update keys, creating a new log entry.
    ///
    /// The current document is preserved; only the `update_keys` parameter changes.
    pub async fn rotate_keys(
        &mut self,
        new_keys: Vec<Multibase>,
        signing_key: &dyn Signer,
    ) -> Result<&LogEntryState, DIDWebVHError> {
        let mut params = self.current_parameters()?;
        let doc = self.current_document()?;
        params.update_keys = Some(Arc::new(new_keys));
        self.create_log_entry(None, &doc, &params, signing_key)
            .await
    }

    /// Deactivate the DID, creating a final log entry.
    ///
    /// Sets `deactivated: true` and clears `update_keys` as required by the spec.
    pub async fn deactivate(
        &mut self,
        signing_key: &dyn Signer,
    ) -> Result<&LogEntryState, DIDWebVHError> {
        let mut params = self.current_parameters()?;
        let doc = self.current_document()?;
        params.deactivated = Some(true);
        params.update_keys = Some(Arc::new(vec![]));
        self.create_log_entry(None, &doc, &params, signing_key)
            .await
    }

    // -----------------------------------------------------------------------
    // Cache serialization
    // -----------------------------------------------------------------------

    /// Serialize this state to a JSON file for offline caching.
    ///
    /// **Note:** Loaded state should be re-validated via [`resolve()`](Self::resolve) or
    /// [`resolve_file()`](Self::resolve_file) before use, because computed fields like
    /// `active_update_keys` use `#[serde(skip)]` and will be at their defaults after
    /// deserialization.
    pub fn save_state(&self, path: &str) -> Result<(), DIDWebVHError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| DIDWebVHError::DIDError(format!("Failed to serialize state: {e}")))?;
        std::fs::write(path, json)
            .map_err(|e| DIDWebVHError::DIDError(format!("Failed to write state to {path}: {e}")))
    }

    /// Load state from a JSON file previously saved with [`save_state()`](Self::save_state).
    ///
    /// **Important:** The loaded state has `validated = false` by default and computed
    /// fields (`active_update_keys`, `active_witness`) will be at their defaults.
    /// You should re-resolve or re-validate before relying on the loaded state.
    pub fn load_state(path: &str) -> Result<Self, DIDWebVHError> {
        let json = std::fs::read_to_string(path).map_err(|e| {
            DIDWebVHError::DIDError(format!("Failed to read state from {path}: {e}"))
        })?;
        serde_json::from_str(&json)
            .map_err(|e| DIDWebVHError::DIDError(format!("Failed to deserialize state: {e}")))
    }

    /// Extract the multibase key fragment from a verification method URI.
    /// E.g. `"did:key:z6Mk...#z6Mk..."` → `"z6Mk..."` (the part after `#`).
    fn extract_multibase_from_vm(vm: &str) -> Result<&str, DIDWebVHError> {
        vm.split_once('#')
            .map(|(_, fragment)| fragment)
            .ok_or_else(|| {
                DIDWebVHError::LogEntryError(format!(
                    "verification_method '{vm}' must contain '#' with multibase key"
                ))
            })
    }

    /// Validates that `signing_key` is authorized to sign a log entry.
    ///
    /// The authorization check depends on the DID state:
    ///
    /// - **First entry** (no previous): the key's multibase must appear in `parameters.update_keys`.
    /// - **Subsequent entry without pre-rotation**: the key must match `update_keys` from the
    ///   previous validated entry.
    /// - **Subsequent entry with pre-rotation**: the key's multibase *hash* must match one of
    ///   the `next_key_hashes` committed in the previous entry. This supports quantum-resistant
    ///   key rotation by requiring keys to be committed (as hashes) before they are revealed.
    fn check_signing_key(
        previous_log_entry: Option<&LogEntryState>,
        parameters: &Parameters,
        signing_key: &dyn Signer,
    ) -> Result<(), DIDWebVHError> {
        debug!(
            "previous_log_entry exists?: {}",
            previous_log_entry.is_some()
        );

        let vm = signing_key.verification_method();
        let multibase = Self::extract_multibase_from_vm(vm)?;

        if let Some(previous) = previous_log_entry {
            if previous.validated_parameters.pre_rotation_active {
                //Check if signing key exists in the previous verified LogEntry NextKeyHashes
                if let Some(hashes) = &previous.validated_parameters.next_key_hashes {
                    let key_hash = Secret::base58_hash_string(multibase).map_err(|e| {
                        DIDWebVHError::LogEntryError(format!("signing_key isn't valid: {e}"))
                    })?;
                    if !hashes.iter().any(|h| h.as_str() == key_hash) {
                        return Err(DIDWebVHError::ParametersError(format!(
                            "Signing key ID {multibase} does not match any next key hashes {:#?}",
                            previous.get_active_update_keys()
                        )));
                    }
                } else {
                    return Err(DIDWebVHError::LogEntryError(
                        "Previous LogEntry has pre_rotation_active but no next_key_hashes"
                            .to_string(),
                    ));
                }
            } else {
                //Check if signing key exists in the previous verified LogEntry UpdateKeys
                if !previous
                    .get_active_update_keys()
                    .iter()
                    .any(|k| k.as_str() == multibase)
                {
                    return Err(DIDWebVHError::ParametersError(format!(
                        "Signing key ID {multibase} does not match any updateKey {:#?}",
                        previous.get_active_update_keys()
                    )));
                }
            }
        } else {
            // This is the first LogEntry, thus update_keys must exist
            if let Some(keys) = &parameters.update_keys {
                if !keys.iter().any(|k| k.as_str() == multibase) {
                    return Err(DIDWebVHError::ParametersError(format!(
                        "Signing key ID {multibase} does not match any updateKey {keys:#?}",
                    )));
                }
            } else {
                return Err(DIDWebVHError::LogEntryError(
                    "First LogEntry, update_keys are required but none exist".to_string(),
                ));
            }
        }

        Ok(())
    }
}

// Compile-time assertions that core types are Send + Sync,
// ensuring they are safe to use across async runtimes and thread pools.
#[allow(dead_code)]
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assertions() {
        assert_send_sync::<DIDWebVHState>();
        assert_send_sync::<DIDWebVHError>();
    }
};

#[cfg(test)]
mod tests {
    use crate::{
        DIDWebVHError, DIDWebVHState, Multibase, Version,
        log_entry::LogEntry,
        log_entry_state::{LogEntryState, LogEntryValidationStatus},
        parameters::Parameters,
    };
    use chrono::Utc;
    use serde_json::Value;
    use std::sync::Arc;

    /// Creates a minimal but valid DID Document for testing purposes.
    /// The document uses {SCID} placeholders in all identifiers, which get replaced
    /// with the actual SCID during log entry creation. Includes a verification method,
    /// assertion/authentication references, and a DIDComm messaging service.
    fn did_doc() -> Value {
        let raw_did = r#"{
    "@context": [
        "https://www.w3.org/ns/did/v1"
    ],
    "assertionMethod": [
        "did:webvh:{SCID}:test.affinidi.com#key-0"
    ],
    "authentication": [
        "did:webvh:{SCID}:test.affinidi.com#key-0"
    ],
    "id": "did:webvh:{SCID}:test.affinidi.com",
    "service": [
        {
        "id": "did:webvh:{SCID}:test.affinidi.com#service-0",
        "serviceEndpoint": [
            {
            "accept": [
                "didcomm/v2"
            ],
            "routingKeys": [],
            "uri": "http://mediator.affinidi.com:/api"
            }
        ],
        "type": "DIDCommMessaging"
        }
    ],
    "verificationMethod": [
        {
        "controller": "did:webvh:{SCID}:test.affinidi.com",
        "id": "did:webvh:{SCID}:test.affinidi.com#key-0",
        "publicKeyMultibase": "test1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "type": "Multikey"
        }
    ]
    }"#;

        serde_json::from_str(raw_did).expect("Couldn't parse raw DID Doc")
    }

    /// Tests that the string "did:webvh:1.0" correctly parses into Version::V1_0.
    /// Expected: TryFrom succeeds and returns the V1_0 variant.
    /// This matters because version parsing is the first step in determining which
    /// spec rules apply when resolving or validating a WebVH DID log.
    #[test]
    fn version_try_from() {
        assert_eq!(Version::try_from("did:webvh:1.0").unwrap(), Version::V1_0);
    }

    /// Tests that Version::V1_0 converts to the numeric value 1.0.
    /// Expected: as_f32() returns 1.0.
    /// This matters because numeric version comparisons are used to enforce that
    /// log entries never downgrade the spec version across the DID history.
    #[test]
    fn version_as_f32() {
        assert_eq!(Version::V1_0.as_f32(), 1_f32);
    }

    /// Tests that a first log entry can be successfully created with valid parameters
    /// and a matching signing key.
    /// Expected: create_log_entry succeeds (returns Ok).
    /// This matters because creating the initial log entry is the foundational step
    /// in establishing a new WebVH DID, including SCID generation and proof signing.
    #[tokio::test]
    async fn webvh_create_log_entry() {
        let key = crate::test_utils::generate_signing_key();

        let state = did_doc();

        let parameters = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(
                key.get_public_keymultibase().unwrap(),
            )])),
            ..Default::default()
        };

        let mut didwebvh = DIDWebVHState::default();

        assert!(
            didwebvh
                .create_log_entry(None, &state, &parameters, &key)
                .await
                .is_ok()
        );
    }

    /// Tests that creating a first log entry without update_keys fails.
    /// Expected: create_log_entry returns an Err.
    /// This matters because update_keys are mandatory for the initial log entry to
    /// establish who is authorized to manage the DID going forward.
    #[tokio::test]
    async fn webvh_create_log_entry_no_update_keys() {
        let key = crate::test_utils::generate_signing_key();

        let state = did_doc();

        let parameters = Parameters {
            ..Default::default()
        };

        let mut didwebvh = DIDWebVHState::default();

        let log_entry = didwebvh
            .create_log_entry(None, &state, &parameters, &key)
            .await;

        match log_entry {
            Err(DIDWebVHError::LogEntryError(msg)) => {
                assert!(
                    msg.contains("update_keys"),
                    "Expected update_keys error, got: {msg}"
                );
            }
            other => panic!("Expected LogEntryError about update_keys, got: {other:?}"),
        }
    }

    /// Tests that a signing key is accepted for the first log entry when it matches
    /// one of the provided update_keys and pre-rotation is not enabled.
    /// Expected: check_signing_key returns Ok.
    /// This matters because the first log entry must verify the signing key against
    /// update_keys to establish the initial trust anchor for the DID.
    #[test]
    fn webvh_check_signing_key_no_pre_rotate_no_previous() {
        let secret = crate::test_utils::generate_signing_key();

        let result = DIDWebVHState::check_signing_key(
            None,
            &Parameters {
                update_keys: Some(Arc::new(vec![Multibase::new(
                    secret
                        .get_public_keymultibase()
                        .expect("Couldn't get public_key from Secret"),
                )])),
                ..Default::default()
            },
            &secret,
        );

        assert!(result.is_ok())
    }

    /// Tests that a signing key is rejected for the first log entry when it does not
    /// match any of the provided update_keys.
    /// Expected: check_signing_key returns Err.
    /// This matters because accepting an unauthorized signing key would allow an
    /// attacker to create a DID they cannot legitimately control.
    #[test]
    fn webvh_check_signing_key_no_pre_rotate_no_previous_error() {
        let secret = crate::test_utils::generate_signing_key();

        let result = DIDWebVHState::check_signing_key(
            None,
            &Parameters {
                update_keys: Some(Arc::new(vec![Multibase::new("bad_key1234")])),
                ..Default::default()
            },
            &secret,
        );

        match &result {
            Err(DIDWebVHError::ParametersError(msg)) => {
                assert!(
                    msg.contains("does not match"),
                    "Expected key mismatch error, got: {msg}"
                );
            }
            other => panic!("Expected ParametersError about key mismatch, got: {other:?}"),
        }
    }

    /// Tests that a signing key is accepted for a subsequent log entry when it matches
    /// the update_keys from the previous validated log entry (without pre-rotation).
    /// Expected: check_signing_key returns Ok.
    /// This matters because subsequent entries must be authorized by the keys established
    /// in the previous entry to maintain the chain of trust in the DID history.
    #[test]
    fn webvh_check_signing_key_no_pre_rotate_with_previous() {
        let secret = crate::test_utils::generate_signing_key();

        let parameters = Parameters {
            scid: Some(Arc::new("1-abcdef1234567890".to_string())),
            update_keys: Some(Arc::new(vec![Multibase::new(
                secret
                    .get_public_keymultibase()
                    .expect("Couldn't get public_key from Secret"),
            )])),
            ..Default::default()
        };
        let previous = LogEntryState {
            log_entry: LogEntry::create(
                "1-abcdef1234567890".to_string(),
                Utc::now().fixed_offset(),
                parameters.clone(),
                did_doc(),
                Version::V1_0,
            )
            .expect("Failed to create LogEntry"),
            version_number: 1,
            validation_status: LogEntryValidationStatus::Ok,
            validated_parameters: parameters.validate(None).unwrap(),
        };

        let result = DIDWebVHState::check_signing_key(
            Some(&previous),
            &Parameters {
                ..Default::default()
            },
            &secret,
        );

        assert!(result.is_ok())
    }

    /// Tests that a signing key is rejected for a subsequent log entry when it does not
    /// match the update_keys from the previous validated entry (without pre-rotation).
    /// Expected: check_signing_key returns Err.
    /// This matters because allowing an unrecognized key to sign updates would break
    /// the verifiable history chain and enable unauthorized DID modifications.
    #[test]
    fn webvh_check_signing_key_no_pre_rotate_with_previous_error() {
        let secret = crate::test_utils::generate_signing_key();

        let parameters = Parameters {
            scid: Some(Arc::new("1-abcdef1234567890".to_string())),
            update_keys: Some(Arc::new(vec![Multibase::new("bad-key1234")])),
            ..Default::default()
        };
        let previous = LogEntryState {
            log_entry: LogEntry::create(
                "1-abcdef1234567890".to_string(),
                Utc::now().fixed_offset(),
                parameters.clone(),
                did_doc(),
                Version::V1_0,
            )
            .expect("Failed to create LogEntry"),
            version_number: 1,
            validation_status: LogEntryValidationStatus::Ok,
            validated_parameters: parameters.validate(None).unwrap(),
        };

        let result = DIDWebVHState::check_signing_key(
            Some(&previous),
            &Parameters {
                ..Default::default()
            },
            &secret,
        );

        match &result {
            Err(DIDWebVHError::ParametersError(msg)) => {
                assert!(
                    msg.contains("does not match"),
                    "Expected key mismatch error, got: {msg}"
                );
            }
            other => panic!("Expected ParametersError about key mismatch, got: {other:?}"),
        }
    }

    /// Tests that a signing key is accepted for the first log entry when pre-rotation
    /// is configured with matching next_key_hashes.
    /// Expected: check_signing_key returns Ok.
    /// This matters because pre-rotation allows DID controllers to commit to future
    /// keys in advance, providing quantum-resistant key rotation security from the start.
    #[test]
    fn webvh_check_signing_key_pre_rotate_no_previous() {
        let secret = crate::test_utils::generate_signing_key();

        let result = DIDWebVHState::check_signing_key(
            None,
            &Parameters {
                update_keys: Some(Arc::new(vec![Multibase::new(
                    secret
                        .get_public_keymultibase()
                        .expect("Couldn't get public_key from Secret"),
                )])),
                next_key_hashes: Some(Arc::new(vec![Multibase::new(
                    secret
                        .get_public_keymultibase_hash()
                        .expect("Couldn't get public_key_hash from Secret"),
                )])),
                ..Default::default()
            },
            &secret,
        );

        assert!(result.is_ok())
    }

    /// Tests that a rotated signing key is accepted when its hash was pre-committed
    /// in the previous log entry's next_key_hashes (pre-rotation with a previous entry).
    /// Expected: check_signing_key returns Ok using the new (next) key.
    /// This matters because pre-rotation key verification across entries ensures
    /// that only keys committed to in advance can assume control, preventing key compromise attacks.
    #[test]
    fn webvh_check_signing_key_pre_rotate_previous() {
        let secret = crate::test_utils::generate_signing_key();

        let next = crate::test_utils::generate_signing_key();

        let parameters = Parameters {
            scid: Some(Arc::new("1-abcdef1234567890".to_string())),
            update_keys: Some(Arc::new(vec![Multibase::new(
                secret
                    .get_public_keymultibase()
                    .expect("Couldn't get public_key from Secret"),
            )])),
            next_key_hashes: Some(Arc::new(vec![Multibase::new(
                next.get_public_keymultibase_hash()
                    .expect("Couldn't get public_key_hash from Secret"),
            )])),
            ..Default::default()
        };

        let previous = LogEntryState {
            log_entry: LogEntry::create(
                "1-abcdef1234567890".to_string(),
                Utc::now().fixed_offset(),
                parameters.clone(),
                did_doc(),
                Version::V1_0,
            )
            .expect("Failed to create LogEntry"),
            version_number: 1,
            validation_status: LogEntryValidationStatus::Ok,
            validated_parameters: parameters.validate(None).unwrap(),
        };

        let result = DIDWebVHState::check_signing_key(
            Some(&previous),
            &Parameters {
                update_keys: Some(Arc::new(vec![Multibase::new(
                    next.get_public_keymultibase()
                        .expect("Couldn't get public_key from Secret"),
                )])),
                next_key_hashes: Some(Arc::new(vec![Multibase::new(
                    next.get_public_keymultibase_hash()
                        .expect("Couldn't get public_key_hash from Secret"),
                )])),
                ..Default::default()
            },
            &next,
        );

        assert!(result.is_ok())
    }

    // ===== Version tests =====

    /// Tests that an unrecognized version string is rejected by TryFrom.
    /// Expected: TryFrom returns Err with a message containing "Invalid WebVH Version".
    /// This matters because accepting unknown versions could lead to incorrect
    /// parameter parsing or validation logic during DID resolution.
    #[test]
    fn version_try_from_invalid() {
        let result = Version::try_from("did:webvh:99.0");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid WebVH Version"));
    }

    /// Tests that Version::V1_0 displays as "did:webvh:1.0".
    /// Expected: The Display trait produces the canonical version string.
    /// This matters because the version string is embedded in log entries and must
    /// conform to the spec format for interoperability with other WebVH implementations.
    #[test]
    fn version_display() {
        assert_eq!(Version::V1_0.to_string(), "did:webvh:1.0");
    }

    /// Tests that Version::V1_0Pre displays identically to V1_0 as "did:webvh:1.0".
    /// Expected: The Display output matches V1_0 exactly.
    /// This matters because pre-1.0 entries are treated as 1.0-compatible on the wire,
    /// ensuring backward compatibility with documents created before spec ratification.
    #[test]
    fn version_v1_0_pre_display() {
        // V1_0Pre displays same as V1_0
        assert_eq!(Version::V1_0Pre.to_string(), "did:webvh:1.0");
    }

    // ===== create_log_entry() additional tests =====

    /// Tests that creating a deactivated log entry fails when update_keys is non-empty.
    /// Expected: create_log_entry returns Err with a message about update_keys needing to be empty.
    /// This matters because the spec requires that deactivated DIDs have empty update_keys
    /// to ensure no further updates can be made after deactivation.
    #[tokio::test]
    async fn webvh_create_log_entry_deactivated_with_keys_error() {
        let key = crate::test_utils::generate_signing_key();
        let state = did_doc();
        let parameters = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(
                key.get_public_keymultibase().unwrap(),
            )])),
            deactivated: Some(true),
            ..Default::default()
        };
        let mut didwebvh = DIDWebVHState::default();
        let result = didwebvh
            .create_log_entry(None, &state, &parameters, &key)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("update_keys is set to []")
        );
    }

    /// Tests the full deactivation flow: create an initial entry, then deactivate with
    /// empty update_keys. This is a two-step process requiring a valid first entry.
    /// Expected: The deactivation log entry is created successfully.
    /// This matters because DID deactivation must be a valid, signed operation that
    /// permanently removes the ability to update the DID while preserving its history.
    #[tokio::test]
    async fn webvh_create_log_entry_deactivated_ok() {
        let key = crate::test_utils::generate_signing_key();
        let mut key_with_id = key.clone();
        let pk = key.get_public_keymultibase().unwrap();
        key_with_id.id = format!("did:key:{pk}#{pk}");

        let state = did_doc();
        let params1 = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(pk.clone())])),
            ..Default::default()
        };
        let mut didwebvh = DIDWebVHState::default();
        let base_time = (Utc::now() - chrono::Duration::seconds(10)).fixed_offset();
        didwebvh
            .create_log_entry(Some(base_time), &state, &params1, &key_with_id)
            .await
            .unwrap();

        let actual_doc = didwebvh.log_entries.last().unwrap().get_state().clone();

        // Now deactivate
        let params2 = Parameters {
            update_keys: Some(Arc::new(vec![])),
            deactivated: Some(true),
            ..Default::default()
        };
        let result = didwebvh
            .create_log_entry(
                Some(base_time + chrono::Duration::seconds(1)),
                &actual_doc,
                &params2,
                &key_with_id,
            )
            .await;
        assert!(result.is_ok());
    }

    /// Tests that a second log entry can be appended after the initial entry,
    /// verifying the version number increments and the state grows correctly.
    /// Expected: Two log entries exist in the state after both creations succeed.
    /// This matters because the ability to append entries is the core mechanism for
    /// DID Document updates while maintaining a verifiable history chain.
    #[tokio::test]
    async fn webvh_create_log_entry_second_entry() {
        let key = crate::test_utils::generate_signing_key();
        let mut key_with_id = key.clone();
        let pk = key.get_public_keymultibase().unwrap();
        key_with_id.id = format!("did:key:{pk}#{pk}");

        let state = did_doc();
        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(pk.clone())])),
            ..Default::default()
        };
        let mut didwebvh = DIDWebVHState::default();
        let base_time = (Utc::now() - chrono::Duration::seconds(10)).fixed_offset();
        didwebvh
            .create_log_entry(Some(base_time), &state, &params, &key_with_id)
            .await
            .unwrap();

        let actual_doc = didwebvh.log_entries.last().unwrap().get_state().clone();

        // Second entry — just update with same keys
        let params2 = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
            ..Default::default()
        };
        let result = didwebvh
            .create_log_entry(
                Some(base_time + chrono::Duration::seconds(1)),
                &actual_doc,
                &params2,
                &key_with_id,
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(didwebvh.log_entries.len(), 2);
    }

    /// Tests that a custom version_time is correctly recorded in the log entry
    /// rather than defaulting to the current time.
    /// Expected: The stored versionTime matches the custom timestamp provided.
    /// This matters because precise version timestamps are critical for time-based
    /// DID resolution queries and for establishing an accurate audit trail.
    #[tokio::test]
    async fn webvh_create_log_entry_custom_version_time() {
        let key = crate::test_utils::generate_signing_key();
        let pk = key.get_public_keymultibase().unwrap();
        let mut key_with_id = key.clone();
        key_with_id.id = format!("did:key:{pk}#{pk}");

        let state = did_doc();
        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
            ..Default::default()
        };
        let custom_time = (Utc::now() - chrono::Duration::seconds(100)).fixed_offset();
        let mut didwebvh = DIDWebVHState::default();
        let result = didwebvh
            .create_log_entry(Some(custom_time), &state, &params, &key_with_id)
            .await;
        assert!(result.is_ok());
        use crate::log_entry::LogEntryMethods;
        // Compare with seconds precision (versionTime is serialized with seconds only)
        let actual = didwebvh.log_entries[0].log_entry.get_version_time_string();
        let expected = custom_time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        assert_eq!(actual, expected);
    }

    // ===== get_specific_log_entry() tests =====

    /// Creates a DIDWebVHState with two log entries for use in query tests.
    /// The entries are separated by 10 seconds, allowing time-based queries to
    /// distinguish between them. Uses a single signing key for both entries.
    /// Returns the fully populated state with two validated log entries.
    async fn create_multi_entry_state() -> DIDWebVHState {
        let key = crate::test_utils::generate_signing_key();
        let pk = key.get_public_keymultibase().unwrap();
        let mut key_with_id = key.clone();
        key_with_id.id = format!("did:key:{pk}#{pk}");

        let state = did_doc();
        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(pk.clone())])),
            ..Default::default()
        };
        let base_time = (Utc::now() - chrono::Duration::seconds(100)).fixed_offset();
        let mut didwebvh = DIDWebVHState::default();
        didwebvh
            .create_log_entry(Some(base_time), &state, &params, &key_with_id)
            .await
            .unwrap();

        let actual_doc = didwebvh.log_entries.last().unwrap().get_state().clone();

        let params2 = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
            ..Default::default()
        };
        didwebvh
            .create_log_entry(
                Some(base_time + chrono::Duration::seconds(10)),
                &actual_doc,
                &params2,
                &key_with_id,
            )
            .await
            .unwrap();
        didwebvh
    }

    /// Tests that a log entry can be retrieved by its exact versionId string.
    /// Expected: The lookup succeeds and returns the matching entry.
    /// This matters because versionId-based queries allow resolvers to fetch a
    /// specific, cryptographically-identified snapshot of the DID Document.
    #[tokio::test]
    async fn test_get_specific_by_version_id() {
        let state = create_multi_entry_state().await;
        use crate::log_entry::LogEntryMethods;
        let vid = state.log_entries[0].log_entry.get_version_id();
        let result = state.get_specific_log_entry(Some(vid), None, None);
        assert!(result.is_ok());
    }

    /// Tests that querying with a non-existent versionId returns a NotFound error.
    /// Expected: The lookup fails with an error message containing "No matching".
    /// This matters because resolvers must clearly distinguish between valid and
    /// invalid version references to avoid returning stale or incorrect DID Documents.
    #[tokio::test]
    async fn test_get_specific_by_version_id_not_found() {
        let state = create_multi_entry_state().await;
        let result = state.get_specific_log_entry(Some("999-nonexistent"), None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No matching"));
    }

    /// Tests that a log entry can be retrieved by its numeric version number.
    /// Expected: The lookup succeeds and the returned entry has version_number 1.
    /// This matters because version number queries provide a simple, sequential way
    /// to navigate the DID history without needing to know the full versionId hash.
    #[tokio::test]
    async fn test_get_specific_by_version_number() {
        let state = create_multi_entry_state().await;
        let result = state.get_specific_log_entry(None, None, Some(1));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().version_number, 1);
    }

    /// Tests that querying with a non-existent version number returns an error.
    /// Expected: The lookup fails for version number 999.
    /// This matters because out-of-range version queries must fail gracefully rather
    /// than panicking or returning incorrect data during DID resolution.
    #[tokio::test]
    async fn test_get_specific_by_version_number_not_found() {
        let state = create_multi_entry_state().await;
        let result = state.get_specific_log_entry(None, None, Some(999));
        match &result {
            Err(DIDWebVHError::NotFound(msg)) => {
                assert!(
                    msg.contains("No matching"),
                    "Expected 'No matching' message, got: {msg}"
                );
            }
            other => panic!("Expected NotFound error, got: {other:?}"),
        }
    }

    /// Tests that a log entry can be retrieved by versionTime, returning the latest
    /// entry whose timestamp is at or before the queried time.
    /// Expected: The lookup succeeds when using the second entry's exact timestamp.
    /// This matters because time-based resolution allows clients to query the DID
    /// Document state as it existed at a specific point in time.
    #[tokio::test]
    async fn test_get_specific_by_version_time() {
        let state = create_multi_entry_state().await;
        use crate::log_entry::LogEntryMethods;
        let time = state.log_entries[1].log_entry.get_version_time();
        let result = state.get_specific_log_entry(None, Some(time), None);
        assert!(result.is_ok());
    }

    /// Tests that querying with a versionTime before all entries returns a NotFound error.
    /// Expected: The lookup fails when using a timestamp one year in the past.
    /// This matters because resolvers must not return data for timestamps that predate
    /// the DID's creation, as no valid document state existed at that time.
    #[tokio::test]
    async fn test_get_specific_by_version_time_not_found() {
        let state = create_multi_entry_state().await;
        // Use a very old time before any entries
        let old_time = (Utc::now() - chrono::Duration::days(365)).fixed_offset();
        let result = state.get_specific_log_entry(None, Some(old_time), None);
        match &result {
            Err(DIDWebVHError::NotFound(msg)) => {
                assert!(
                    msg.contains("No matching"),
                    "Expected 'No matching' message, got: {msg}"
                );
            }
            other => panic!("Expected NotFound error, got: {other:?}"),
        }
    }

    /// Tests that calling get_specific_log_entry with no query parameters returns an error.
    /// Expected: The lookup fails with a message containing "No query parameter".
    /// This matters because the API must reject ambiguous queries to prevent
    /// accidentally returning the wrong log entry during resolution.
    #[tokio::test]
    async fn test_get_specific_no_params_error() {
        let state = create_multi_entry_state().await;
        let result = state.get_specific_log_entry(None, None, None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No query parameter")
        );
    }

    // ===== File I/O tests =====

    /// Tests that load_log_entries_from_file returns an error for a missing file.
    #[test]
    fn test_load_log_entries_from_file_missing() {
        let mut state = DIDWebVHState::default();
        let result = state.load_log_entries_from_file("/nonexistent/did.jsonl");
        assert!(result.is_err());
    }

    /// Tests that load_witness_proofs_from_file silently ignores a missing file.
    /// The method is designed to be fault-tolerant since witness proofs are optional.
    #[test]
    fn test_load_witness_proofs_from_file_missing() {
        let mut state = DIDWebVHState::default();
        state.load_witness_proofs_from_file("/nonexistent/witness.json");
        // Should not panic, and witness_proofs should remain default
        assert_eq!(state.witness_proofs.get_total_count(), 0);
    }

    // ===== check_signing_key() additional tests =====

    /// Tests that creating a first log entry with no update_keys at all (None) is rejected.
    /// Expected: check_signing_key returns Err with "update_keys are required".
    /// This matters because the first entry must establish authorized update keys;
    /// without them, no future updates could be validated in the DID history.
    #[test]
    fn webvh_check_signing_key_first_entry_no_keys_error() {
        let secret = crate::test_utils::generate_signing_key();
        let result = DIDWebVHState::check_signing_key(
            None,
            &Parameters {
                update_keys: None,
                ..Default::default()
            },
            &secret,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("update_keys are required")
        );
    }

    /// Tests that pre-rotation is rejected when the previous entry has pre_rotation_active
    /// set to true but next_key_hashes is None (an inconsistent state).
    /// Expected: check_signing_key returns Err with "no next_key_hashes".
    /// This matters because pre-rotation without committed key hashes is a broken state
    /// that would make it impossible to verify the legitimacy of rotated keys.
    #[test]
    fn webvh_check_signing_key_pre_rotation_no_hashes_error() {
        let secret = crate::test_utils::generate_signing_key();

        let parameters = Parameters {
            scid: Some(Arc::new("1-abcdef1234567890".to_string())),
            update_keys: Some(Arc::new(vec![Multibase::new(
                secret.get_public_keymultibase().unwrap(),
            )])),
            ..Default::default()
        };
        let mut validated = parameters.validate(None).unwrap();
        // Force pre_rotation_active but remove next_key_hashes
        validated.pre_rotation_active = true;
        validated.next_key_hashes = None;

        let previous = LogEntryState {
            log_entry: LogEntry::create(
                "1-abcdef1234567890".to_string(),
                Utc::now().fixed_offset(),
                parameters.clone(),
                did_doc(),
                Version::V1_0,
            )
            .unwrap(),
            version_number: 1,
            validation_status: crate::log_entry_state::LogEntryValidationStatus::Ok,
            validated_parameters: validated,
        };

        let result =
            DIDWebVHState::check_signing_key(Some(&previous), &Parameters::default(), &secret);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no next_key_hashes")
        );
    }

    // ===== save_state / load_state round-trip tests =====

    #[tokio::test]
    async fn state_save_load_roundtrip() {
        let key = crate::test_utils::generate_signing_key();
        let doc = crate::test_utils::did_doc_with_key("did:webvh:{SCID}:localhost%3A8000", &key);
        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(
                key.get_public_keymultibase().unwrap(),
            )])),
            portable: Some(false),
            ..Default::default()
        };

        let mut state = DIDWebVHState::default();
        state
            .create_log_entry(None, &doc, &params, &key)
            .await
            .unwrap();

        let path = "/tmp/didwebvh_test_state_roundtrip.json";
        state.save_state(path).unwrap();

        let loaded = DIDWebVHState::load_state(path).unwrap();

        // Core fields survive the round-trip
        assert_eq!(loaded.log_entries().len(), state.log_entries().len());
        assert_eq!(loaded.scid(), state.scid());
        assert_eq!(loaded.meta_first_ts(), state.meta_first_ts());
        assert_eq!(loaded.meta_last_ts(), state.meta_last_ts());

        // Computed fields are at defaults after load (documented behavior)
        assert!(!loaded.validated());

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn load_state_nonexistent_file_returns_error() {
        let result = DIDWebVHState::load_state("/tmp/this_file_does_not_exist_12345.json");
        assert!(result.is_err());
    }

    // ===== Convenience API tests =====

    #[tokio::test]
    async fn update_document_creates_new_entry() {
        let key = crate::test_utils::generate_signing_key();
        let doc = crate::test_utils::did_doc_with_key("did:webvh:{SCID}:localhost%3A8000", &key);
        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(
                key.get_public_keymultibase().unwrap(),
            )])),
            portable: Some(false),
            ..Default::default()
        };

        let mut state = DIDWebVHState::default();
        state
            .create_log_entry(None, &doc, &params, &key)
            .await
            .unwrap();
        assert_eq!(state.log_entries().len(), 1);

        // Update with the same document (just creates a new version)
        let current_doc = state.log_entries().last().unwrap().get_state().clone();
        state.update_document(current_doc, &key).await.unwrap();
        assert_eq!(state.log_entries().len(), 2);
    }

    #[tokio::test]
    async fn rotate_keys_changes_update_keys() {
        let key = crate::test_utils::generate_signing_key();
        let doc = crate::test_utils::did_doc_with_key("did:webvh:{SCID}:localhost%3A8000", &key);
        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(
                key.get_public_keymultibase().unwrap(),
            )])),
            portable: Some(false),
            ..Default::default()
        };

        let mut state = DIDWebVHState::default();
        state
            .create_log_entry(None, &doc, &params, &key)
            .await
            .unwrap();

        let new_key = crate::test_utils::generate_signing_key();
        let new_mb = Multibase::new(new_key.get_public_keymultibase().unwrap());

        state.rotate_keys(vec![new_mb.clone()], &key).await.unwrap();
        assert_eq!(state.log_entries().len(), 2);
        // The new update key should be in the validated parameters
        let last = state.log_entries().last().unwrap();
        assert!(
            last.validated_parameters
                .update_keys
                .as_ref()
                .unwrap()
                .contains(&new_mb)
        );
    }

    #[tokio::test]
    async fn deactivate_sets_deactivated_flag() {
        let key = crate::test_utils::generate_signing_key();
        let doc = crate::test_utils::did_doc_with_key("did:webvh:{SCID}:localhost%3A8000", &key);
        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(
                key.get_public_keymultibase().unwrap(),
            )])),
            portable: Some(false),
            ..Default::default()
        };

        let mut state = DIDWebVHState::default();
        state
            .create_log_entry(None, &doc, &params, &key)
            .await
            .unwrap();

        state.deactivate(&key).await.unwrap();
        assert_eq!(state.log_entries().len(), 2);
        let last = state.log_entries().last().unwrap();
        assert_eq!(last.validated_parameters.deactivated, Some(true));
    }

    #[tokio::test]
    async fn convenience_api_on_empty_state_returns_error() {
        let key = crate::test_utils::generate_signing_key();
        let mut state = DIDWebVHState::default();

        match state.update_document(serde_json::json!({}), &key).await {
            Err(DIDWebVHError::LogEntryError(msg)) => {
                assert!(
                    msg.contains("No log entries"),
                    "Expected 'No log entries', got: {msg}"
                );
            }
            other => {
                panic!("Expected LogEntryError for update_document on empty state, got: {other:?}")
            }
        }
        match state.rotate_keys(vec![Multibase::new("z6Mk1")], &key).await {
            Err(DIDWebVHError::LogEntryError(msg)) => {
                assert!(
                    msg.contains("No log entries"),
                    "Expected 'No log entries', got: {msg}"
                );
            }
            other => {
                panic!("Expected LogEntryError for rotate_keys on empty state, got: {other:?}")
            }
        }
        match state.deactivate(&key).await {
            Err(DIDWebVHError::LogEntryError(msg)) => {
                assert!(
                    msg.contains("No log entries"),
                    "Expected 'No log entries', got: {msg}"
                );
            }
            other => panic!("Expected LogEntryError for deactivate on empty state, got: {other:?}"),
        }
    }
}
