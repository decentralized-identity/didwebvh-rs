//! Each WebVH LogEntry requires Parameters that help define behaviour of the DID
//!
//! Different WebVH Specifications can introduce changes to the parameters structure
//!
//! Primary Elements:
//! - Parameters: Used to to input Paramater configuration for a WebVH LogEntry
//! - ParameterSpec: ENUM representing different versions of the WebVH DID Specification
//! - CommonParameterSpec: A generic common representation of the latest Parameter specification

use crate::{DIDWebVHError, Version, parameters::spec_1_0::Parameters1_0, witness::Witnesses};
use affinidi_secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::debug;

pub(crate) mod spec_1_0;
pub(crate) mod spec_1_0_pre;

/// Parameters for WebVH DIDs
#[derive(Clone, Default, Debug, Serialize)]
pub struct Parameters {
    /// SCID (this is often automatically generated))
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scid: Option<Arc<String>>,

    /// DID version specification
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "method_from_version"
    )]
    pub method: Option<Version>,

    /// Keys that are authorized to update future log entries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_keys: Option<Arc<Vec<String>>>,

    /// Can you change the web address for this DID?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portable: Option<bool>,

    /// pre-rotation keys that must be shared prior to updating update keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_key_hashes: Option<Arc<Vec<String>>>,

    /// Parameters for witness nodes
    /// NOTE: This represents the Witness Configuraiton, which may not be the active witnesses
    /// for the LogEntry
    ///
    /// Use [LogEntryState::get_active_witnesses] to get the active witnesses for a logEntry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Arc<Witnesses>>,

    /// DID watchers for this DID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchers: Option<Arc<Vec<String>>>,

    /// Has this DID been revoked?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,

    /// time to live in seconds for a resolved DID document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,

    /// Is key pre-rotation active?
    #[serde(skip)]
    pub pre_rotation_active: bool,

    /// The following are calculated and populated as part of the validation process:

    /// active_update_keys: Vec<String>
    #[serde(skip)]
    pub active_update_keys: Arc<Vec<String>>,

    /// active_witness: Option<Arc<Mutex<Witnesses>>>
    #[serde(skip)]
    pub active_witness: Option<Arc<Witnesses>>,
}

fn method_from_version<S>(data: &Option<Version>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if let Some(data) = data {
        serializer.serialize_str(&data.to_string())
    } else {
        serializer.serialize_none()
    }
}

impl Parameters {
    /// Instantiate a new default ParametersBuilder
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> ParametersBuilder {
        ParametersBuilder {
            pre_rotation_active: false,
            method: Version::default(),
            update_keys: None,
            next_key_hashes: None,
            portable: None,
            witness: None,
            watchers: None,
            deactivated: false,
            ttl: None,
        }
    }

    /// Compares two sets of Parameters and returns a new Parameters object only with the
    /// differences
    /// Will check and verify to spec, will return an error if there is an issue
    pub(crate) fn diff(&self, old_params: &Parameters) -> Result<Parameters, DIDWebVHError> {
        let mut diff = Parameters::default();

        // Calculated fields can be left at defaults as they are ignored in serialization
        // pre_rotation_active, active_update_keys, active_witness
        // scid can not be changed, so leave it at default None

        // Are we changing WebVH Version?
        if let Some(this_version) = self.method
            && let Some(previous_version) = old_params.method
            && this_version != previous_version
        {
            diff.method = self.method
        }

        // Check if portable has been turned off (can never be turned on except on first log entry)
        if self.portable != old_params.portable {
            if self.portable == Some(true) {
                return Err(DIDWebVHError::ParametersError(
                    "Portable cannot be set to true after the first Log Entry".to_string(),
                ));
            }
            diff.portable = self.portable;
        }

        // updateKeys may have changed
        debug!(
            "new_params.update_keys: {:#?} :: previous.update_keys: {:#?}",
            self.update_keys, old_params.update_keys
        );
        diff.update_keys =
            Self::diff_tri_state(&old_params.update_keys, &self.update_keys, "updateKeys")?;

        if self.pre_rotation_active {
            if let Some(update_keys) = &diff.update_keys {
                if update_keys.is_empty() {
                    return Err(DIDWebVHError::ParametersError(
                        "updateKeys cannot be empty when pre-rotation is active".to_string(),
                    ));
                }
            } else {
                return Err(DIDWebVHError::ParametersError(
                    "updateKeys must be defined when pre-rotation is active".to_string(),
                ));
            }
        }

        // nextKeyHashes checks
        diff.next_key_hashes = Self::diff_tri_state(
            &old_params.next_key_hashes,
            &self.next_key_hashes,
            "nextKeyHashes",
        )?;

        // Witness checks
        diff.witness = Self::diff_witness(&old_params.witness, &self.witness)?;

        // Watcher checks
        diff.watchers = Self::diff_tri_state(&old_params.watchers, &self.watchers, "watchers")?;

        // Deactivated
        if let Some(deactivated) = self.deactivated {
            if deactivated && old_params.pre_rotation_active {
                return Err(DIDWebVHError::DeactivatedError(
                    "DID cannot be deactivated while pre-rotation is active".to_string(),
                ));
            } else if self.deactivated != old_params.deactivated {
                diff.deactivated = self.deactivated;
            }
        }

        // TTL Checks
        match self.ttl {
            None => {
                // If None, then keep current parameter ttl
                diff.ttl = None;
            }
            Some(ttl) => {
                // If Some(ttl), then set the new ttl
                if self.ttl == old_params.ttl {
                    // If ttl is the same, no change
                    diff.ttl = None;
                } else {
                    diff.ttl = Some(ttl);
                }
            }
        }

        Ok(diff)
    }

    /// Returns the differences in Parameter attributes
    /// that use tri-state logic
    /// None = Absent, use previous value
    /// Some(Empty) = Clear previous values and set to empty
    /// Some(Value) = Use new value
    fn diff_tri_state(
        previous: &Option<Arc<Vec<String>>>,
        current: &Option<Arc<Vec<String>>>,
        _attribute_name: &str,
    ) -> Result<Option<Arc<Vec<String>>>, DIDWebVHError> {
        let Some(current_value) = current else {
            // If current is None, then keep previous value
            return Ok(None);
        };

        if current_value.is_empty() {
            if let Some(previous) = previous
                && previous.is_empty()
            {
                // Both empty, no change
                return Ok(None);
            }
            Ok(Some(Arc::new(Vec::new())))
        } else {
            // There are values
            if let Some(previous) = previous {
                // if previous.lock().await == current_value.lock().await {
                if previous == current_value {
                    return Ok(None);
                }
            }
            Ok(current.clone())
        }
    }

    /// Returns the differences in witness parameters
    /// the entire witness struct is treated as a singleton
    fn diff_witness(
        previous: &Option<Arc<Witnesses>>,
        current: &Option<Arc<Witnesses>>,
    ) -> Result<Option<Arc<Witnesses>>, DIDWebVHError> {
        let Some(current_witness) = current else {
            // If current is None, then keep previous value
            return Ok(None);
        };

        if current_witness.is_empty() {
            if let Some(previous) = previous
                && previous.is_empty()
            {
                // Both empty, no change
                return Ok(None);
            }
            Ok(Some(Arc::new(Witnesses::Empty {})))
        } else {
            // There are values
            debug!("values: {current_witness:#?}");
            current_witness.validate()?;
            if let Some(previous) = previous
                && previous == current_witness
            {
                return Ok(None);
            }
            Ok(current.clone())
        }
    }

    /// Validates a set of parameters including against the previous LogEntry if it exists
    /// Returns
    /// 1. Validated Parameters (Fully formed set of Parameters that match the state of the WebVH
    ///    DID )
    pub fn validate(&self, previous: Option<&Parameters>) -> Result<Parameters, DIDWebVHError> {
        debug!(">>>> Validating Parameters");
        debug!("current parameters: {:#?}", self);
        debug!("previous parameters: {:#?}", previous);

        let mut new_parameters = Parameters::default();

        // Handle previous values
        let mut pre_rotation_previous_value: bool = false;
        if let Some(previous) = previous {
            new_parameters.pre_rotation_active = previous.pre_rotation_active;
            pre_rotation_previous_value = previous.pre_rotation_active;
            new_parameters.portable = previous.portable;
            new_parameters.next_key_hashes = previous.next_key_hashes.clone();
            new_parameters.scid = previous.scid.clone();

            if let Some(deactivated) = previous.deactivated
                && deactivated
            {
                // If previous is deactivated, then no more log entries can be made
                return Err(DIDWebVHError::DeactivatedError(
                    "DID was deactivated previous Log Entry, no more log entries are allowed."
                        .to_string(),
                ));
            } else {
                new_parameters.deactivated = previous.deactivated
            }

            if self.scid.is_some() {
                return Err(DIDWebVHError::ParametersError(
                    "scid must not be provided on later Log Entries".to_string(),
                ));
            }
        } else {
            // First Log entry
            if let Some(scid) = &self.scid {
                new_parameters.scid = Some(scid.clone());
            } else {
                return Err(DIDWebVHError::ParametersError(
                    "scid must be provided on first Log Entry".to_string(),
                ));
            }
        }

        // Validate and process nextKeyHashes
        match &self.next_key_hashes {
            None => {
                // If absent, but is in pre-rotation state. This is an error
                if new_parameters.pre_rotation_active {
                    return Err(DIDWebVHError::ParametersError(
                        "nextKeyHashes cannot be absent when pre-rotation is active".to_string(),
                    ));
                }
            }
            Some(next_key_hashes) => {
                if next_key_hashes.is_empty() {
                    // If None, turn off key rotation
                    new_parameters.next_key_hashes = None;
                    new_parameters.pre_rotation_active = false; // If None, pre-rotation is not active
                } else {
                    new_parameters.next_key_hashes = Some(next_key_hashes.clone());
                    new_parameters.pre_rotation_active = true; // If Value, pre-rotation is active
                }
            }
        }

        // Validate and update UpdateKeys
        if let Some(previous) = previous {
            match &self.update_keys {
                None => {
                    // If absent, keep current updateKeys
                    new_parameters.active_update_keys = previous.active_update_keys.clone();
                }
                Some(update_keys) => {
                    if update_keys.is_empty() {
                        // If empty, turn off updateKeys
                        new_parameters.update_keys = Some(Arc::new(Vec::new()));
                        new_parameters.active_update_keys = previous.active_update_keys.clone();
                    } else if !new_parameters.pre_rotation_active && pre_rotation_previous_value {
                        // Key pre-rotation has been turned off
                        // Update keys must be part of the previous nextKeyHashes
                        Self::validate_pre_rotation_keys(&previous.next_key_hashes, update_keys)?;
                        new_parameters.update_keys = Some(update_keys.clone());
                        new_parameters.active_update_keys = update_keys.clone();
                    } else if new_parameters.pre_rotation_active {
                        // Key pre-rotation is active
                        // Update keys must be part of the previous nextKeyHashes
                        Self::validate_pre_rotation_keys(&previous.next_key_hashes, update_keys)?;
                        new_parameters.active_update_keys = update_keys.clone();
                    } else {
                        // No Key pre-rotation is active
                        new_parameters.update_keys = Some(update_keys.clone());
                        new_parameters.active_update_keys = update_keys.clone();
                    }
                }
            }
        } else {
            // First Log Entry checks
            if let Some(update_keys) = &self.update_keys {
                if update_keys.is_empty() {
                    return Err(DIDWebVHError::ParametersError(
                        "updateKeys cannot be empty".to_string(),
                    ));
                }
                new_parameters.update_keys = Some(update_keys.clone());
                new_parameters.active_update_keys = update_keys.clone();
            } else {
                return Err(DIDWebVHError::ParametersError(
                    "updateKeys must be provided on first Log Entry".to_string(),
                ));
            }
        }

        // Check Portability
        if let Some(portable) = self.portable {
            if previous.is_none() {
                new_parameters.portable = self.portable;
            } else if portable {
                return Err(DIDWebVHError::ParametersError(
                    "Portable is being set to true after the first Log Entry".to_string(),
                ));
            } else {
                // Can only be set to false after first Log Entry
                new_parameters.portable = Some(false);
            }
        } else if previous.is_none() {
            // First Log entry, if portable not specified then defaults to false
            new_parameters.portable = Some(false)
        }

        // Validate witness
        if let Some(previous) = previous {
            match &self.witness {
                None => {
                    // If absent, keep current witnesses
                    new_parameters.active_witness = previous.witness.clone();
                    new_parameters.witness = previous.witness.clone();
                }
                Some(witnesses) => {
                    if witnesses.is_empty() {
                        // If None, turn off witness
                        new_parameters.witness = None;
                        // Still needs to be witnessed
                        new_parameters.active_witness = previous.witness.clone();
                    } else {
                        // Replace witness with the new value
                        witnesses.validate()?;
                        new_parameters.witness = Some(witnesses.clone());
                        new_parameters.active_witness = previous.witness.clone();
                    }
                }
            }
        } else {
            // First Log Entry
            match &self.witness {
                None => {
                    new_parameters.active_witness = None;
                    new_parameters.witness = None;
                }
                Some(witnesses) => {
                    if witnesses.is_empty() {
                        // Empty witness object means no witnesses configured
                        new_parameters.active_witness = None;
                        new_parameters.witness = None;
                    } else {
                        // Replace witness with the new value
                        witnesses.validate()?;
                        new_parameters.witness = Some(witnesses.clone());
                        new_parameters.active_witness = Some(witnesses.clone());
                    }
                }
            }
        }

        // Validate Watchers
        if let Some(previous) = previous {
            match &self.watchers {
                None => {
                    // If absent, keep current watchers
                    new_parameters.watchers = previous.watchers.clone();
                }
                Some(watchers) => {
                    if watchers.is_empty() {
                        // If None, turn off watchers
                        new_parameters.watchers = None;
                    } else {
                        // Replace watchers with the new value
                        new_parameters.watchers = Some(watchers.clone());
                    }
                }
            }
        } else {
            // First Log Entry
            match &self.watchers {
                None => {
                    new_parameters.watchers = None;
                }
                Some(watchers) => {
                    if watchers.is_empty() {
                        // Empty watchers array means no watchers configured
                        new_parameters.watchers = None;
                    } else {
                        // Replace watchers with the new value
                        new_parameters.watchers = Some(watchers.clone());
                    }
                }
            }
        }

        // Check deactivation status
        if let Some(deactivated) = self.deactivated
            && deactivated
            && previous.is_none()
        {
            // Can't be deactivated on the first log entry
            return Err(DIDWebVHError::DeactivatedError(
                "DID cannot be deactivated on the first Log Entry".to_string(),
            ));
        } else if let Some(deactivated) = self.deactivated
            && deactivated
        {
            if let Some(update_keys) = &self.update_keys
                && !update_keys.is_empty()
            {
                return Err(DIDWebVHError::DeactivatedError(
                    "DID Parameters say deactivated, yet updateKeys are not null!".to_string(),
                ));
            }
            new_parameters.update_keys = Some(Arc::new(Vec::new()));
        }

        new_parameters.deactivated = self.deactivated;

        // Determine TTL: use new value if specified, otherwise inherit from previous
        new_parameters.ttl = match &self.ttl {
            Some(ttl) => Some(*ttl),
            None => previous.and_then(|p| p.ttl),
        };

        debug!("Parameters successfully validated");
        debug!("Validated Parameters: {new_parameters:#?}");
        Ok(new_parameters)
    }

    /// When pre-rotation is enabled, check that each updateKey was defined in the previous
    /// nextKeyHashes
    /// Returns an error if validation fails
    fn validate_pre_rotation_keys(
        next_key_hashes: &Option<Arc<Vec<String>>>,
        update_keys: &Arc<Vec<String>>,
    ) -> Result<(), DIDWebVHError> {
        let Some(next_key_hashes) = next_key_hashes else {
            return Err(DIDWebVHError::ValidationError(
                "nextKeyHashes must be defined when pre-rotation is active".to_string(),
            ));
        };
        for key in update_keys.iter() {
            // Convert the key to the hash value
            let check_hash = Secret::base58_hash_string(key).map_err(|e| {
                DIDWebVHError::ValidationError(format!(
                    "Couldn't hash updateKeys key ({key}). Reason: {e}",
                ))
            })?;
            if !next_key_hashes.contains(&check_hash) {
                return Err(DIDWebVHError::ValidationError(format!(
                    "updateKey ({key}) hash({check_hash}) was not specified in the previous nextKeyHashes!",
                )));
            }
        }
        Ok(())
    }
}

/// Parameters for WebVH DIDs
/// Builder for WebVH Parameters
#[derive(Clone)]
pub struct ParametersBuilder {
    /// Is key pre-rotation active?
    pub(crate) pre_rotation_active: bool,

    /// DID version specification
    /// Default: `did:webvh:1.0`
    pub(crate) method: Version,

    /// Keys that are authorized to update future log entries
    pub(crate) update_keys: Option<Arc<Vec<String>>>,

    /// Can you change the web address for this DID?
    pub(crate) portable: Option<bool>,

    /// pre-rotation keys that must be shared prior to updating update keys
    pub(crate) next_key_hashes: Option<Arc<Vec<String>>>,

    /// Parameters for witness nodes
    pub(crate) witness: Option<Arc<Witnesses>>,

    /// DID watchers for this DID
    pub(crate) watchers: Option<Arc<Vec<String>>>,

    /// Has this DID been revoked?
    pub(crate) deactivated: bool,

    /// time to live in seconds for a resolved DID document
    pub(crate) ttl: Option<u32>,
}

impl ParametersBuilder {
    /// Are updateKeys being pre-rotated for each LogEntry?
    pub fn with_key_pre_rotation(&mut self, active: bool) -> &mut Self {
        self.pre_rotation_active = active;
        self
    }

    /// You can override the default LogEntry Version which will force a specific WebVH Version
    /// Default: did:webvh:1.0
    pub fn with_method(&mut self, method: Version) -> &mut Self {
        self.method = method;
        self
    }

    /// Specify the valid updateKeys
    pub fn with_update_keys(&mut self, update_keys: Vec<String>) -> &mut Self {
        self.update_keys = Some(Arc::new(update_keys));
        self
    }

    /// If pre-rotation is active, what the next set of key hashes for updateKeys
    pub fn with_next_key_hashes(&mut self, next_key_hashes: Vec<String>) -> &mut Self {
        self.next_key_hashes = Some(Arc::new(next_key_hashes));
        self
    }

    /// Can this DID be migrated to a different web address?
    pub fn with_portable(&mut self, portable: bool) -> &mut Self {
        self.portable = Some(portable);
        self
    }

    /// Are there any witnesses for this LogEntry?
    pub fn with_witnesses(&mut self, witness: Witnesses) -> &mut Self {
        self.witness = Some(Arc::new(witness));
        self
    }

    /// Are there any watchers for this LogEntry?
    pub fn with_watchers(&mut self, watchers: Vec<String>) -> &mut Self {
        self.watchers = Some(Arc::new(watchers));
        self
    }

    /// Set this DID to be deactivated
    pub fn with_deactivated(&mut self, deactivated: bool) -> &mut Self {
        self.deactivated = deactivated;
        self
    }

    /// Time To Live in seconds for this LogEntry
    pub fn with_ttl(&mut self, ttl: u32) -> &mut Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn build(&mut self) -> Parameters {
        Parameters {
            scid: None, // SCID is not set in the builder, it is set during validation
            pre_rotation_active: self.pre_rotation_active,
            method: Some(self.method),
            update_keys: self.update_keys.clone(),
            portable: self.portable,
            next_key_hashes: self.next_key_hashes.clone(),
            witness: self.witness.clone(),
            watchers: self.watchers.clone(),
            deactivated: Some(self.deactivated),
            ttl: self.ttl,
            active_update_keys: Arc::new(Vec::new()), // Will be set during validation
            active_witness: None,                     // Will be set during validation
        }
    }
}

/// Contains each defined version of WebVH Parameters
#[non_exhaustive]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ParameterVersions {
    /// Official v1.0 specification
    Spec1_0(Parameters1_0),

    /// Interim 1.0 spec where nulls were used instyead of empty arrays and objects
    Spec1_0Pre {},
}

impl Default for ParameterVersions {
    fn default() -> Self {
        ParameterVersions::Spec1_0(Parameters1_0::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SCID_HOLDER, Version, test_utils::TEST_UPDATE_KEY, witness::Witness};
    use std::sync::Arc;

    // ------------------------------------------------------------------------
    // Helper functions
    // ------------------------------------------------------------------------

    /// Creates a minimal valid Parameters suitable for a first (genesis) log entry.
    ///
    /// Includes a placeholder SCID and a single Ed25519 update key. Use this as the
    /// starting point when testing first-entry validation or as input to
    /// `validated_first_params()` to produce a validated previous-entry baseline.
    fn first_entry_params() -> Parameters {
        Parameters {
            scid: Some(Arc::new(SCID_HOLDER.to_string())),
            update_keys: Some(Arc::new(vec![TEST_UPDATE_KEY.to_string()])),
            ..Default::default()
        }
    }

    /// Returns a fully validated first-entry Parameters, ready to serve as the
    /// "previous" parameter when testing subsequent log entry validation.
    ///
    /// Calls `first_entry_params().validate(None)` so that all computed fields
    /// (active_update_keys, portable default, etc.) are properly populated.
    fn validated_first_params() -> Parameters {
        first_entry_params().validate(None).unwrap()
    }

    /// Creates a minimal valid Parameters for a subsequent (non-genesis) log entry.
    ///
    /// Omits the SCID (which must not appear after the first entry) and provides
    /// the same Ed25519 update key used by `first_entry_params()`. Use this when
    /// you need a simple subsequent entry that should pass validation against a
    /// validated first entry.
    fn subsequent_entry_params() -> Parameters {
        Parameters {
            update_keys: Some(Arc::new(vec![TEST_UPDATE_KEY.to_string()])),
            ..Default::default()
        }
    }

    // ------------------------------------------------------------------------
    // diff() tests -- Parameters::diff computes a delta between two parameter
    // sets, used when building subsequent log entries to include only changed
    // fields in the serialized output.
    // ------------------------------------------------------------------------

    /// Given two identical Parameters,
    /// then diff() should produce an empty object with no fields set.
    ///
    /// This ensures that unchanged parameters are omitted from the serialized
    /// log entry, keeping the DID log compact per the spec.
    #[test]
    fn diff_no_changes() {
        let params = Parameters {
            method: Some(Version::V1_0),
            update_keys: Some(Arc::new(vec!["key1".to_string()])),
            portable: Some(false),
            ttl: Some(3600),
            ..Default::default()
        };
        let diff = params.diff(&params).unwrap();
        assert_eq!(serde_json::to_string(&diff).unwrap(), "{}");
    }

    /// Given old parameters with V1_0 and new parameters with V1_0Pre,
    /// then diff() should include the method field in the result.
    ///
    /// The DID WebVH spec allows version transitions between log entries.
    /// This test confirms that a version change is correctly detected and
    /// included in the diff output.
    #[test]
    fn diff_method_version_change() {
        let old = Parameters {
            method: Some(Version::V1_0),
            ..Default::default()
        };
        // V1_0Pre has a different enum variant but same display — test the branch is entered
        let new = Parameters {
            method: Some(Version::V1_0Pre),
            ..Default::default()
        };
        let diff = new.diff(&old).unwrap();
        // V1_0Pre != V1_0, so method should be in the diff
        assert!(diff.method.is_some());
    }

    /// Given old parameters with portable=false,
    /// then attempting to set portable=true in the diff should return an error.
    ///
    /// Per the DID WebVH spec, the portable flag can only be set to true on the
    /// first log entry. Enabling portability later would undermine DID binding
    /// guarantees, so this must be rejected.
    #[test]
    fn diff_portable_turned_on_error() {
        let old = Parameters {
            portable: Some(false),
            ..Default::default()
        };
        let new = Parameters {
            portable: Some(true),
            ..Default::default()
        };
        assert!(new.diff(&old).is_err());
    }

    /// Given old parameters with portable=true,
    /// then setting portable=false should produce a diff with portable=false.
    ///
    /// The spec allows disabling portability in subsequent entries (opting out
    /// of future domain migration), so this transition must be captured in the diff.
    #[test]
    fn diff_portable_turned_off() {
        let old = Parameters {
            portable: Some(true),
            ..Default::default()
        };
        let new = Parameters {
            portable: Some(false),
            ..Default::default()
        };
        let diff = new.diff(&old).unwrap();
        assert_eq!(diff.portable, Some(false));
    }

    /// Given old parameters with "old_key" and new parameters with "new_key",
    /// then diff() should include the new update key in the result.
    ///
    /// Update key rotation is a core DID WebVH operation. The diff must capture
    /// key changes so that resolvers can verify subsequent log entries with the
    /// correct keys.
    #[test]
    fn diff_update_keys_changed() {
        let old = Parameters {
            update_keys: Some(Arc::new(vec!["old_key".to_string()])),
            ..Default::default()
        };
        let new = Parameters {
            update_keys: Some(Arc::new(vec!["new_key".to_string()])),
            ..Default::default()
        };
        let diff = new.diff(&old).unwrap();
        assert!(diff.update_keys.is_some());
        assert_eq!(diff.update_keys.unwrap()[0], "new_key");
    }

    /// Given pre-rotation is active and the new entry has empty updateKeys,
    /// then diff() should return an error.
    ///
    /// When pre-rotation is enabled, the spec requires that every log entry
    /// include non-empty updateKeys (the pre-committed keys). An empty set
    /// would break the pre-rotation chain.
    #[test]
    fn diff_update_keys_empty_with_pre_rotation_error() {
        let old = Parameters::default();
        let new = Parameters {
            pre_rotation_active: true,
            update_keys: Some(Arc::new(vec![])),
            ..Default::default()
        };
        let err = new.diff(&old).unwrap_err();
        assert!(err.to_string().contains("updateKeys cannot be empty"));
    }

    /// Given pre-rotation is active and the new entry omits updateKeys entirely,
    /// then diff() should return an error.
    ///
    /// Similar to the empty-keys case, omitting updateKeys altogether when
    /// pre-rotation is active violates the spec requirement that rotated keys
    /// must always be present.
    #[test]
    fn diff_update_keys_none_with_pre_rotation_error() {
        let old = Parameters::default();
        let new = Parameters {
            pre_rotation_active: true,
            update_keys: None,
            ..Default::default()
        };
        let err = new.diff(&old).unwrap_err();
        assert!(err.to_string().contains("updateKeys must be defined"));
    }

    /// Given old parameters with pre-rotation active and new parameters requesting deactivation,
    /// then diff() should return an error.
    ///
    /// The spec prohibits deactivating a DID while pre-rotation is active because
    /// the pre-rotation commitment implies future key usage. Deactivation must first
    /// disable pre-rotation.
    #[test]
    fn diff_deactivated_with_pre_rotation_error() {
        let old = Parameters {
            pre_rotation_active: true,
            ..Default::default()
        };
        let new = Parameters {
            deactivated: Some(true),
            update_keys: Some(Arc::new(vec!["key".to_string()])),
            ..Default::default()
        };
        let err = new.diff(&old).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot be deactivated while pre-rotation")
        );
    }

    /// Given old parameters with deactivated=false and new parameters with deactivated=true,
    /// then diff() should include deactivated=true in the result.
    ///
    /// Deactivation is a permanent lifecycle event in the DID WebVH spec. The diff
    /// must record this change so it appears in the serialized log entry.
    #[test]
    fn diff_deactivated_changed() {
        let old = Parameters {
            deactivated: Some(false),
            ..Default::default()
        };
        let new = Parameters {
            deactivated: Some(true),
            ..Default::default()
        };
        let diff = new.diff(&old).unwrap();
        assert_eq!(diff.deactivated, Some(true));
    }

    /// Given old TTL of 3600 and new TTL of 7200,
    /// then diff() should include the updated TTL value.
    ///
    /// TTL controls how long a resolved DID document can be cached. Changes
    /// must propagate through the diff so resolvers respect the new caching policy.
    #[test]
    fn diff_ttl_changed() {
        let old = Parameters {
            ttl: Some(3600),
            ..Default::default()
        };
        let new = Parameters {
            ttl: Some(7200),
            ..Default::default()
        };
        let diff = new.diff(&old).unwrap();
        assert_eq!(diff.ttl, Some(7200));
    }

    /// Given identical TTL values in old and new parameters,
    /// then diff() should not include TTL in the result.
    ///
    /// Redundant fields must be suppressed in the diff to keep log entries minimal.
    #[test]
    fn diff_ttl_same_no_change() {
        let old = Parameters {
            ttl: Some(3600),
            ..Default::default()
        };
        let new = Parameters {
            ttl: Some(3600),
            ..Default::default()
        };
        let diff = new.diff(&old).unwrap();
        assert!(diff.ttl.is_none());
    }

    /// Given old parameters with TTL=3600 and new parameters with TTL=None (absent),
    /// then diff() should not include TTL, preserving the previous value.
    ///
    /// Per the tri-state convention, an absent (None) value means "keep the
    /// previous setting." This test verifies that omitting TTL does not reset it.
    #[test]
    fn diff_ttl_none_keeps_current() {
        let old = Parameters {
            ttl: Some(3600),
            ..Default::default()
        };
        let new = Parameters {
            ttl: None,
            ..Default::default()
        };
        let diff = new.diff(&old).unwrap();
        assert!(diff.ttl.is_none());
    }

    // ------------------------------------------------------------------------
    // validate() tests -- Parameters::validate checks a parameter set against
    // the spec rules and the previous log entry state, producing a fully
    // resolved Parameters with all inherited and computed fields populated.
    // ------------------------------------------------------------------------

    /// Given a previous entry that was deactivated,
    /// then validating any subsequent entry should return an error.
    ///
    /// The DID WebVH spec treats deactivation as terminal -- no further log
    /// entries may be appended after a DID has been deactivated.
    #[test]
    fn validate_previous_deactivated_error() {
        let previous = Parameters {
            deactivated: Some(true),
            ..validated_first_params()
        };
        let current = subsequent_entry_params();
        let err = current.validate(Some(&previous)).unwrap_err();
        assert!(err.to_string().contains("deactivated"));
    }

    /// Given a first log entry that is missing the SCID,
    /// then validate() should return an error.
    ///
    /// The SCID (Self-Certifying Identifier) is mandatory on the genesis entry
    /// because it cryptographically binds the DID to its initial content.
    #[test]
    fn validate_first_entry_missing_scid_error() {
        let params = Parameters {
            scid: None,
            update_keys: Some(Arc::new(vec!["key".to_string()])),
            ..Default::default()
        };
        let err = params.validate(None).unwrap_err();
        assert!(err.to_string().contains("scid must be provided"));
    }

    /// Given a subsequent log entry that includes a SCID,
    /// then validate() should return an error.
    ///
    /// The SCID is established once in the genesis entry and must not be
    /// re-specified in later entries, as it is immutable for the DID's lifetime.
    #[test]
    fn validate_subsequent_scid_present_error() {
        let previous = validated_first_params();
        let current = Parameters {
            scid: Some(Arc::new("extra-scid".to_string())),
            update_keys: Some(Arc::new(vec![TEST_UPDATE_KEY.to_string()])),
            ..Default::default()
        };
        let err = current.validate(Some(&previous)).unwrap_err();
        assert!(err.to_string().contains("scid must not be provided"));
    }

    /// Given a previous entry with pre-rotation active and a current entry that omits nextKeyHashes,
    /// then validate() should return an error.
    ///
    /// When pre-rotation is active, every log entry must include nextKeyHashes to
    /// maintain the pre-commitment chain. Omitting them would break the ability to
    /// verify future key rotations.
    #[test]
    fn validate_next_key_hashes_absent_pre_rotation_active_error() {
        let mut previous = validated_first_params();
        previous.pre_rotation_active = true;
        previous.next_key_hashes = Some(Arc::new(vec!["hash".to_string()]));

        let current = Parameters {
            next_key_hashes: None, // absent
            update_keys: Some(Arc::new(vec![TEST_UPDATE_KEY.to_string()])),
            ..Default::default()
        };
        let err = current.validate(Some(&previous)).unwrap_err();
        assert!(err.to_string().contains("nextKeyHashes cannot be absent"));
    }

    /// Given a previous entry with pre-rotation active and a current entry with empty nextKeyHashes,
    /// then validate() should disable pre-rotation and clear nextKeyHashes.
    ///
    /// An empty nextKeyHashes array is the spec-defined mechanism for opting out of
    /// pre-rotation. This test confirms the transition is handled correctly, setting
    /// pre_rotation_active to false and clearing the stored hashes.
    #[test]
    fn validate_next_key_hashes_empty_turns_off() {
        let mut previous = validated_first_params();
        previous.pre_rotation_active = true;
        previous.next_key_hashes = Some(Arc::new(vec![
            // Hash of z6Mkp7QveNebyWs4z1kJ7Aa7CymUjRpjPYnBYh6Cr1t6JoXY
            affinidi_secrets_resolver::secrets::Secret::base58_hash_string(
                "z6Mkp7QveNebyWs4z1kJ7Aa7CymUjRpjPYnBYh6Cr1t6JoXY",
            )
            .unwrap(),
        ]));

        let current = Parameters {
            next_key_hashes: Some(Arc::new(vec![])), // empty turns off
            update_keys: Some(Arc::new(vec![TEST_UPDATE_KEY.to_string()])),
            ..Default::default()
        };
        let result = current.validate(Some(&previous)).unwrap();
        assert!(!result.pre_rotation_active);
        assert!(result.next_key_hashes.is_none());
    }

    /// Given a first entry with non-empty nextKeyHashes,
    /// then validate() should activate pre-rotation.
    ///
    /// Providing nextKeyHashes on the genesis entry is how a DID controller
    /// opts into the pre-rotation security mechanism from the start.
    #[test]
    fn validate_next_key_hashes_value_activates() {
        let params = Parameters {
            scid: Some(Arc::new(SCID_HOLDER.to_string())),
            update_keys: Some(Arc::new(vec![TEST_UPDATE_KEY.to_string()])),
            next_key_hashes: Some(Arc::new(vec!["somehash".to_string()])),
            ..Default::default()
        };
        let result = params.validate(None).unwrap();
        assert!(result.pre_rotation_active);
    }

    /// Given a subsequent entry that omits updateKeys (None),
    /// then validate() should inherit active_update_keys from the previous entry.
    ///
    /// The tri-state convention applies: absent updateKeys means "no change,"
    /// so the resolver continues using the keys from the prior log entry.
    #[test]
    fn validate_update_keys_absent_inherits_previous() {
        let previous = validated_first_params();
        let current = Parameters {
            update_keys: None, // absent
            ..Default::default()
        };
        let result = current.validate(Some(&previous)).unwrap();
        assert_eq!(result.active_update_keys, previous.active_update_keys);
    }

    /// Given a subsequent entry with an empty updateKeys array,
    /// then validate() should store the empty array in update_keys.
    ///
    /// An empty updateKeys array is distinct from absent (None). It explicitly
    /// signals that no new keys are being set, which is used during deactivation
    /// or when clearing keys.
    #[test]
    fn validate_update_keys_empty_subsequent() {
        let previous = validated_first_params();
        let current = Parameters {
            update_keys: Some(Arc::new(vec![])),
            ..Default::default()
        };
        let result = current.validate(Some(&previous)).unwrap();
        assert!(result.update_keys.unwrap().is_empty());
    }

    /// Given a subsequent entry that sets portable=true,
    /// then validate() should return an error.
    ///
    /// The DID WebVH spec only allows enabling portability on the genesis entry.
    /// Allowing it later would let a DID be moved to a different domain after
    /// trust relationships have already been established.
    #[test]
    fn validate_portable_true_after_first_error() {
        let previous = validated_first_params();
        let current = Parameters {
            portable: Some(true),
            update_keys: Some(Arc::new(vec![TEST_UPDATE_KEY.to_string()])),
            ..Default::default()
        };
        let err = current.validate(Some(&previous)).unwrap_err();
        assert!(err.to_string().contains("Portable is being set to true"));
    }

    /// Given a subsequent entry that sets portable=false,
    /// then validate() should accept it and record portable=false.
    ///
    /// Disabling portability after the genesis entry is permitted by the spec,
    /// as it tightens (rather than loosens) the DID's binding guarantees.
    #[test]
    fn validate_portable_false_after_first() {
        let previous = validated_first_params();
        let current = Parameters {
            portable: Some(false),
            update_keys: Some(Arc::new(vec![TEST_UPDATE_KEY.to_string()])),
            ..Default::default()
        };
        let result = current.validate(Some(&previous)).unwrap();
        assert_eq!(result.portable, Some(false));
    }

    /// Given a first entry with deactivated=true,
    /// then validate() should return an error.
    ///
    /// A DID cannot be born deactivated -- the genesis entry must establish an
    /// active DID before deactivation can occur in a subsequent entry.
    #[test]
    fn validate_deactivated_first_entry_error() {
        let params = Parameters {
            scid: Some(Arc::new(SCID_HOLDER.to_string())),
            update_keys: Some(Arc::new(vec!["key".to_string()])),
            deactivated: Some(true),
            ..Default::default()
        };
        let err = params.validate(None).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot be deactivated on the first")
        );
    }

    /// Given a subsequent entry that is deactivated but still has non-empty updateKeys,
    /// then validate() should return an error.
    ///
    /// The spec requires that deactivation clears updateKeys (sets them to an empty
    /// array) to prevent any future updates. Retaining keys would be contradictory.
    #[test]
    fn validate_deactivated_non_empty_keys_error() {
        let previous = validated_first_params();
        let current = Parameters {
            deactivated: Some(true),
            update_keys: Some(Arc::new(vec!["non-empty".to_string()])),
            ..Default::default()
        };
        let err = current.validate(Some(&previous)).unwrap_err();
        assert!(
            err.to_string()
                .contains("deactivated, yet updateKeys are not null")
        );
    }

    /// Given a subsequent entry with deactivated=true and empty updateKeys,
    /// then validate() should succeed with empty keys and deactivated=true.
    ///
    /// This is the correct way to deactivate a DID per the spec: set deactivated
    /// to true and clear all updateKeys so no further modifications are possible.
    #[test]
    fn validate_deactivated_sets_empty_keys() {
        let previous = validated_first_params();
        let current = Parameters {
            deactivated: Some(true),
            update_keys: Some(Arc::new(vec![])),
            ..Default::default()
        };
        let result = current.validate(Some(&previous)).unwrap();
        assert!(result.update_keys.unwrap().is_empty());
        assert_eq!(result.deactivated, Some(true));
    }

    /// Given a previous entry with TTL=7200 and a current entry with TTL=None,
    /// then validate() should inherit the previous TTL value.
    ///
    /// Absent TTL means "no change" per the tri-state convention, so the resolved
    /// DID document should continue using the previously configured cache lifetime.
    #[test]
    fn validate_ttl_inherits_from_previous() {
        let mut previous = validated_first_params();
        previous.ttl = Some(7200);

        let current = Parameters {
            ttl: None,
            update_keys: Some(Arc::new(vec![TEST_UPDATE_KEY.to_string()])),
            ..Default::default()
        };
        let result = current.validate(Some(&previous)).unwrap();
        assert_eq!(result.ttl, Some(7200));
    }

    // ------------------------------------------------------------------------
    // validate_pre_rotation_keys() tests -- These test the static helper that
    // checks whether each updateKey's hash was pre-committed in the previous
    // entry's nextKeyHashes, which is the core mechanic of key pre-rotation.
    // ------------------------------------------------------------------------

    /// Given an updateKey whose hash exists in the nextKeyHashes list,
    /// then validate_pre_rotation_keys() should succeed.
    ///
    /// This is the happy path for pre-rotation: the controller committed to a
    /// key hash in a prior entry and is now presenting the actual key that
    /// matches that hash.
    #[test]
    fn pre_rotation_keys_valid() {
        let key = "z6Mkp7QveNebyWs4z1kJ7Aa7CymUjRpjPYnBYh6Cr1t6JoXY";
        let hash = affinidi_secrets_resolver::secrets::Secret::base58_hash_string(key).unwrap();
        let hashes = Some(Arc::new(vec![hash]));
        let keys = Arc::new(vec![key.to_string()]);
        assert!(Parameters::validate_pre_rotation_keys(&hashes, &keys).is_ok());
    }

    /// Given nextKeyHashes is None (not defined),
    /// then validate_pre_rotation_keys() should return an error.
    ///
    /// Pre-rotation requires that the previous entry committed key hashes.
    /// If no hashes exist, the pre-rotation chain is broken and validation
    /// must fail.
    #[test]
    fn pre_rotation_keys_missing_hashes_error() {
        let keys = Arc::new(vec!["somekey".to_string()]);
        let err = Parameters::validate_pre_rotation_keys(&None, &keys).unwrap_err();
        assert!(err.to_string().contains("nextKeyHashes must be defined"));
    }

    /// Given nextKeyHashes that do not match the presented updateKey,
    /// then validate_pre_rotation_keys() should return an error.
    ///
    /// This detects unauthorized key rotation attempts where the new key was
    /// not pre-committed. It is the primary security guarantee of the
    /// pre-rotation mechanism.
    #[test]
    fn pre_rotation_keys_not_in_hashes_error() {
        let hashes = Some(Arc::new(vec!["wrong_hash".to_string()]));
        let keys = Arc::new(vec![TEST_UPDATE_KEY.to_string()]);
        let err = Parameters::validate_pre_rotation_keys(&hashes, &keys).unwrap_err();
        assert!(
            err.to_string()
                .contains("was not specified in the previous nextKeyHashes")
        );
    }

    // ------------------------------------------------------------------------
    // ParametersBuilder tests -- These verify that the builder pattern for
    // constructing Parameters correctly sets defaults and accepts all
    // configurable options.
    // ------------------------------------------------------------------------

    /// Given a freshly constructed ParametersBuilder with no options set,
    /// then build() should produce Parameters with spec-defined defaults.
    ///
    /// This ensures the builder starts from a clean, predictable state:
    /// V1_0 method, no keys, no witnesses, not deactivated, no TTL, and
    /// pre-rotation disabled.
    #[test]
    fn builder_defaults() {
        let params = Parameters::new().build();
        assert!(params.scid.is_none());
        assert_eq!(params.method, Some(Version::V1_0));
        assert!(params.update_keys.is_none());
        assert!(params.portable.is_none());
        assert!(params.next_key_hashes.is_none());
        assert!(params.witness.is_none());
        assert!(params.watchers.is_none());
        assert_eq!(params.deactivated, Some(false));
        assert!(params.ttl.is_none());
        assert!(!params.pre_rotation_active);
    }

    /// Given a ParametersBuilder with every option explicitly set,
    /// then build() should produce Parameters reflecting all provided values.
    ///
    /// This confirms that every builder method correctly wires its value into
    /// the resulting Parameters struct, covering the full configuration surface.
    #[test]
    fn builder_all_options() {
        let params = Parameters::new()
            .with_method(Version::V1_0)
            .with_update_keys(vec!["key1".to_string()])
            .with_portable(true)
            .with_next_key_hashes(vec!["hash1".to_string()])
            .with_key_pre_rotation(true)
            .with_deactivated(false)
            .with_ttl(7200)
            .build();

        assert_eq!(params.method, Some(Version::V1_0));
        assert_eq!(params.update_keys.unwrap()[0], "key1");
        assert_eq!(params.portable, Some(true));
        assert_eq!(params.next_key_hashes.unwrap()[0], "hash1");
        assert!(params.pre_rotation_active);
        assert_eq!(params.deactivated, Some(false));
        assert_eq!(params.ttl, Some(7200));
    }

    /// Given a ParametersBuilder with a witness configuration (threshold=1, one witness),
    /// then build() should store the witness configuration in the Parameters.
    ///
    /// Witnesses provide third-party attestation of DID log entries. This test
    /// ensures the builder correctly passes through the full Witnesses struct
    /// including threshold and witness list.
    #[test]
    fn builder_with_witnesses() {
        let witnesses = Witnesses::Value {
            threshold: 1,
            witnesses: vec![Witness {
                id: "witness1".to_string(),
            }],
        };
        let params = Parameters::new().with_witnesses(witnesses.clone()).build();
        assert!(params.witness.is_some());
        assert_eq!(*params.witness.unwrap(), witnesses);
    }

    /// Given a ParametersBuilder with a single watcher configured,
    /// then build() should store the watcher list in the Parameters.
    ///
    /// Watchers monitor DID log integrity. This test confirms the builder
    /// correctly wraps the watcher list in an Arc for shared ownership.
    #[test]
    fn builder_with_watchers() {
        let params = Parameters::new()
            .with_watchers(vec!["watcher1".to_string()])
            .build();
        assert!(params.watchers.is_some());
        assert_eq!(params.watchers.unwrap()[0], "watcher1");
    }
}
