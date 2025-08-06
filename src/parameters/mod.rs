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
        if let Some(this_version) = self.method {
            if let Some(previous_version) = old_params.method {
                if this_version != previous_version {
                    diff.method = self.method
                }
            }
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
        attribute_name: &str,
    ) -> Result<Option<Arc<Vec<String>>>, DIDWebVHError> {
        let Some(current_value) = current else {
            // If current is None, then keep previous value
            return Ok(None);
        };

        if current_value.is_empty() {
            if let Some(previous) = previous {
                if previous.is_empty() {
                    // attribute was already empty, and thus setting it again to empty would be
                    // invalid
                    return Err(DIDWebVHError::ParametersError(format!(
                        "{attribute_name} cannot be empty when previous was also empty!"
                    )));
                }
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
            if let Some(previous) = previous {
                if previous.is_empty() {
                    // attribute was already empty, and thus setting it again to empty would be
                    // invalid
                    return Err(DIDWebVHError::ParametersError(
                        "Witnesses cannot be empty when previous was also empty!".to_string(),
                    ));
                }
            }
            Ok(Some(Arc::new(Witnesses::Empty {})))
        } else {
            // There are values
            debug!("values: {current_witness:#?}");
            current_witness.validate()?;
            if let Some(previous) = previous {
                if previous == current_witness {
                    return Ok(None);
                }
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
                    } else {
                        // If pre-rotation is enabled, then validate and add immediately to active keys
                        if update_keys.is_empty() {
                            return Err(DIDWebVHError::ParametersError(
                                "updateKeys cannot be empty".to_string(),
                            ));
                        }
                        if !new_parameters.pre_rotation_active && pre_rotation_previous_value {
                            // Key pre-rotation has been turned off
                            // Update keys must be part of the previous nextKeyHashes
                            Self::validate_pre_rotation_keys(
                                &previous.next_key_hashes,
                                update_keys,
                            )?;
                            new_parameters.update_keys = Some(update_keys.clone());
                            new_parameters.active_update_keys = update_keys.clone();
                        } else if new_parameters.pre_rotation_active {
                            // Key pre-rotation is active
                            // Update keys must be part of the previous nextKeyHashes
                            Self::validate_pre_rotation_keys(
                                &previous.next_key_hashes,
                                update_keys,
                            )?;
                            new_parameters.active_update_keys = update_keys.clone();
                        } else {
                            // No Key pre-rotation is active
                            new_parameters.update_keys = Some(update_keys.clone());
                            new_parameters.active_update_keys = update_keys.clone();
                        }
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
                    // Replace witness with the new value
                    witnesses.validate()?;
                    new_parameters.witness = Some(witnesses.clone());
                    new_parameters.active_witness = Some(witnesses.clone());
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
                    // Replace watchers with the new value
                    if watchers.is_empty() {
                        return Err(DIDWebVHError::ParametersError(
                            "watchers cannot be empty".to_string(),
                        ));
                    }
                    new_parameters.watchers = Some(watchers.clone());
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
            if let Some(update_keys) = &self.update_keys {
                if !update_keys.is_empty() {
                    return Err(DIDWebVHError::DeactivatedError(
                        "DID Parameters say deactivated, yet updateKeys are not null!".to_string(),
                    ));
                }
            }
            new_parameters.update_keys = Some(Arc::new(Vec::new()));
        }

        new_parameters.deactivated = self.deactivated;

        // Determine TTL
        if let Some(previous) = previous {
            match &self.ttl {
                None => {
                    // If absent, keep current TTL
                    new_parameters.ttl = previous.ttl;
                }
                Some(ttl) => {
                    // Replace ttl with the new value
                    new_parameters.ttl = Some(*ttl);
                }
            }
        } else {
            // First Log Entry
            match &self.ttl {
                None => {
                    new_parameters.ttl = None;
                }
                Some(ttl) => {
                    // Replace ttl with the new value
                    new_parameters.ttl = Some(*ttl);
                }
            }
        }

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
