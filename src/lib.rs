/*!
*   DID method for Web with Verifiable History
*   See [WebVH Spec](https://identity.foundation/didwebvh/v1.0)
*/

use crate::{
    log_entry::{LogEntry, LogEntryMethods, MetaData},
    log_entry_state::{LogEntryState, LogEntryValidationStatus},
    parameters::Parameters,
    witness::proofs::WitnessProofCollection,
};
use affinidi_data_integrity::DataIntegrityProof;
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, FixedOffset, Utc};
use serde::Serialize;
use serde_json::Value;
use std::{fmt, sync::Arc};
use thiserror::Error;
use tracing::debug;

pub mod log_entry;
pub mod log_entry_state;
pub mod parameters;
pub mod resolve;
pub mod url;
pub mod validate;
pub mod witness;

/// WebVH Specification supports multiple LogEntry versions in the same DID
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize)]
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
            Version::V1_0Pre => 0.9, // Pre 1.0 is considered 0.9
            Version::V1_0 => 1.0,
        }
    }
}

/// Magic string used for first LogEntry
pub const SCID_HOLDER: &str = "{SCID}";

/// Error types for WebVH method
#[derive(Error, Debug)]
pub enum DIDWebVHError {
    #[error("DeactivatedError: {0}")]
    DeactivatedError(String),
    #[error("DIDError: {0}")]
    DIDError(String),
    #[error("Invalid method identifier: {0}")]
    InvalidMethodIdentifier(String),
    #[error("LogEntryError: {0}")]
    LogEntryError(String),
    #[error("NetworkError: {0}")]
    NetworkError(String),
    #[error("DID Query NotFound")]
    NotFound,
    #[error("NotImplemented: {0}")]
    NotImplemented(String),
    #[error("ParametersError: {0}")]
    ParametersError(String),
    #[error("SCIDError: {0}")]
    SCIDError(String),
    #[error("ServerError: {0}")]
    ServerError(String),
    #[error("UnsupportedMethod: Must be did:webvh")]
    UnsupportedMethod,
    /// There was an error in validating the DID
    #[error("ValidationError: {0}")]
    ValidationError(String),
    /// An error occurred while working with Witness Proofs
    #[error("WitnessProofError: {0}")]
    WitnessProofError(String),
}

/// Information relating to a webvh DID
#[derive(Debug, Default)]
pub struct DIDWebVHState {
    pub log_entries: Vec<LogEntryState>,
    pub witness_proofs: WitnessProofCollection,

    /// What SCID is this state representing?
    pub scid: String,

    /// Timestamp of the first LogEntry
    pub meta_first_ts: String,

    /// Timestamp of the last LogEntry
    pub meta_last_ts: String,

    /// Timestamp for when this DID will expire and need to be reloaded
    pub expires: DateTime<FixedOffset>,

    /// Validated?
    pub validated: bool,
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
        if let Ok(proofs) = WitnessProofCollection::read_from_file(file_path) {
            self.witness_proofs = proofs;
        }
    }

    /// Creates a new LogEntry
    /// version_time is optional, if not provided, current time will be used
    /// document is the DID Document as a JSON Value
    /// parameters are the Parameters for the Log Entry (Full set of parameters)
    /// signing_key is the Secret used to sign the Log Entry
    ///   NOTE: A diff comparison to previous parameters is automatically done
    /// signing_key is the Secret used to sign the Log Entry
    pub fn create_log_entry(
        &mut self,
        version_time: Option<DateTime<FixedOffset>>,
        document: &Value,
        parameters: &Parameters,
        signing_key: &Secret,
    ) -> Result<Option<&LogEntryState>, DIDWebVHError> {
        let now = Utc::now();

        // Create a VerificationMethod ID from the signing key matched to an updateKey
        let deactivated = parameters.deactivated.unwrap_or_default();
        if let Some(keys) = &parameters.update_keys
            && !deactivated
        {
            // update_keys exist and DID is NOT deactovated
            if !keys.contains(&signing_key.get_public_keymultibase().map_err(|e| {
                DIDWebVHError::LogEntryError(format!("signing_key isn't valid: {e}"))
            })?) {
                return Err(DIDWebVHError::SCIDError(format!(
                    "Signing key ID {} does not match any updateKey {keys:#?}",
                    signing_key.get_public_keymultibase().unwrap(),
                )));
            }
        } else if deactivated {
            // This is the last LogEntry for a deactivated Entry
            // Do nothing
        } else {
            return Err(DIDWebVHError::SCIDError(
                "No update keys provided in parameters".to_string(),
            ));
        }

        let last_log_entry = self.log_entries.last();

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
                last_log_entry.get_version_id(),
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
            let scid = if let Some(scid) = new_entry.get_scid() {
                scid
            } else {
                return Err(DIDWebVHError::LogEntryError(
                    "First LogEntry does not have a SCID!".to_string(),
                ));
            };

            let mut validated_params = new_entry.get_parameters();
            validated_params.active_witness = validated_params.witness.clone();
            self.meta_first_ts = new_entry.get_version_time_string().to_string();
            self.meta_last_ts = self.meta_first_ts.clone();
            self.scid = scid.clone();
            validated_params
        };

        // Generate the proof for the log entry
        let proof = DataIntegrityProof::sign_jcs_data(&new_entry, None, signing_key, None)
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

        Ok(self.log_entries.last())
    }

    /// Gets a specific LogEntry based on versionId and versionTime
    pub fn get_specific_log_entry(
        &self,
        version_id: Option<&str>,
        version_time: Option<DateTime<FixedOffset>>,
    ) -> Result<&LogEntryState, DIDWebVHError> {
        if let Some(version_id) = version_id {
            for log_entry in self.log_entries.iter() {
                if log_entry.get_version_id() == version_id {
                    if let Some(version_time) = version_time {
                        if version_time < log_entry.get_version_time() {
                            return Err(DIDWebVHError::NotFound);
                        }
                    }
                    return Ok(log_entry);
                }
            }
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
        }

        Err(DIDWebVHError::NotFound)
    }

    /// Creates a MatatData struct from a validaed LogEntryState
    pub fn generate_meta_data(&self, log_entry: &LogEntryState) -> MetaData {
        MetaData {
            version_id: log_entry.get_version_id().to_string(),
            version_time: log_entry.get_version_time_string().to_string(),
            created: self.meta_first_ts.clone(),
            updated: self.meta_last_ts.clone(),
            scid: self.scid.clone(),
            portable: log_entry.validated_parameters.portable.unwrap_or(false),
            deactivated: log_entry
                .validated_parameters
                .deactivated
                .unwrap_or_default(),
            witness: log_entry
                .validated_parameters
                .active_witness
                .as_deref()
                .cloned(),
            watchers: log_entry.validated_parameters.watchers.as_deref().cloned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{DIDWebVHState, Version, parameters::Parameters};
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::Value;
    use ssi::JWK;

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

    #[test]
    fn version_try_from() {
        assert_eq!(Version::try_from("did:webvh:1.0").unwrap(), Version::V1_0);
    }

    #[test]
    fn version_as_f32() {
        assert_eq!(Version::V1_0.as_f32(), 1_f32);
    }

    #[test]
    fn webvh_create_log_entry() {
        let key = Secret::from_jwk(&JWK::generate_ed25519().unwrap())
            .expect("Couldn't create signing key");

        let state = did_doc();

        let parameters = Parameters {
            update_keys: Some(Arc::new(vec![key.get_public_keymultibase().unwrap()])),
            ..Default::default()
        };

        let mut didwebvh = DIDWebVHState::default();

        let log_entry = didwebvh
            .create_log_entry(None, &state, &parameters, &key)
            .expect("Failed to create LogEntry");

        assert!(log_entry.is_some());
    }
}
