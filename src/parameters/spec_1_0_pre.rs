/*!
*   Contains the parameters that define DID processing parameters
*   used when processing the current and previous Log Entry
*/

use crate::{Version, parameters::Parameters, witness::Witnesses};
use serde::{Deserialize, Serialize};
use std::{ops::Not, sync::Arc};

/// [https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters]
/// Parameters that help with the resolution of a webvh DID
///
/// Thin uses double options to allow for the following:
/// None = field wasn't specified
/// Some(None) = field was specified, but set to null
/// Some(Some(value)) = field was specified with a value
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameters1_0Pre {
    /// Is key pre-rotation active?
    #[serde(skip)]
    pub pre_rotation_active: bool,

    /// DID version specification
    /// Default: `did:webvh:1.0`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Self Certifying Identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scid: Option<Arc<String>>,

    /// Keys that are authorized to update future log entries
    #[serde(
        default,                                    // <- important for deserialization
        skip_serializing_if = "Option::is_none",    // <- important for serialization
        with = "::serde_with::rust::double_option",
    )]
    pub update_keys: Option<Option<Arc<Vec<String>>>>,

    /// Can you change the web address for this DID?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portable: Option<bool>,

    /// pre-rotation keys that must be shared prior to updating update keys
    #[serde(
        default,                                    // <- important for deserialization
        skip_serializing_if = "Option::is_none",    // <- important for serialization
        with = "::serde_with::rust::double_option",
    )]
    pub next_key_hashes: Option<Option<Arc<Vec<String>>>>,

    /// Parameters for witness nodes
    #[serde(
        default,                                    // <- important for deserialization
        skip_serializing_if = "Option::is_none",    // <- important for serialization
        with = "::serde_with::rust::double_option",
    )]
    pub witness: Option<Option<Arc<Witnesses>>>,

    /// DID watchers for this DID
    #[serde(
        default,                                    // <- important for deserialization
        skip_serializing_if = "Option::is_none",    // <- important for serialization
        with = "::serde_with::rust::double_option",
    )]
    pub watchers: Option<Option<Arc<Vec<String>>>>,

    /// Has this DID been revoked?
    #[serde(skip_serializing_if = "<&bool>::not", default)]
    pub deactivated: bool,

    /// time to live in seconds for a resolved DID document
    #[serde(
        default,                                    // <- important for deserialization
        skip_serializing_if = "Option::is_none",    // <- important for serialization
        with = "::serde_with::rust::double_option",
    )]
    pub ttl: Option<Option<u32>>,
}

impl Default for Parameters1_0Pre {
    fn default() -> Self {
        Parameters1_0Pre {
            pre_rotation_active: false,
            method: Some("did:webvh:1.0".to_string()),
            scid: None,
            update_keys: None,
            portable: None,
            next_key_hashes: None,
            witness: None,
            watchers: None,
            deactivated: false,
            ttl: None,
        }
    }
}

impl From<Parameters> for Parameters1_0Pre {
    fn from(value: Parameters) -> Self {
        let next_key_hashes = match value.next_key_hashes {
            Some(next_keys) => {
                if next_keys.is_empty() {
                    Some(None)
                } else {
                    Some(Some(next_keys.clone()))
                }
            }
            None => None,
        };

        let ttl = match value.ttl {
            Some(ttl) => {
                if ttl == 3600 {
                    Some(None)
                } else {
                    Some(Some(ttl))
                }
            }
            None => None,
        };

        let update_keys = match value.update_keys {
            Some(update_keys) => {
                if update_keys.is_empty() {
                    Some(None)
                } else {
                    Some(Some(update_keys.clone()))
                }
            }
            None => None,
        };

        let witness = match value.witness {
            Some(witness) => {
                if witness.is_empty() {
                    Some(None)
                } else {
                    Some(Some(witness.clone()))
                }
            }
            None => None,
        };

        let watchers = match value.watchers {
            Some(watchers) => {
                if watchers.is_empty() {
                    Some(None)
                } else {
                    Some(Some(watchers.clone()))
                }
            }
            None => None,
        };

        Parameters1_0Pre {
            deactivated: value.deactivated.unwrap_or_default(),
            pre_rotation_active: value.pre_rotation_active,
            method: Some(Version::V1_0Pre.to_string()),
            next_key_hashes,
            scid: value.scid.clone(),
            ttl,
            update_keys,
            portable: value.portable,
            witness,
            watchers,
        }
    }
}

impl From<Parameters1_0Pre> for Parameters {
    fn from(value: Parameters1_0Pre) -> Parameters {
        let next_key_hashes = match value.next_key_hashes {
            Some(Some(next_keys)) => Some(next_keys.clone()),
            Some(None) => Some(Arc::new(Vec::new())),
            None => None,
        };

        let ttl = match value.ttl {
            Some(Some(ttl)) => Some(ttl),
            Some(None) => Some(3600),
            None => None,
        };

        let update_keys = match value.update_keys {
            Some(Some(update_keys)) => Some(update_keys.clone()),
            Some(None) => Some(Arc::new(Vec::new())),
            None => None,
        };

        let witness = match value.witness {
            Some(Some(witness)) => Some(witness.clone()),
            Some(None) => Some(Arc::new(Witnesses::Empty {})),
            None => None,
        };

        let watchers = match value.watchers {
            Some(Some(watchers)) => Some(watchers.clone()),
            Some(None) => Some(Arc::new(Vec::new())),
            None => None,
        };

        Parameters {
            deactivated: Some(value.deactivated),
            pre_rotation_active: value.pre_rotation_active,
            method: Some(Version::V1_0),
            next_key_hashes,
            scid: value.scid.clone(),
            ttl,
            update_keys,
            portable: value.portable,
            witness,
            watchers,
            active_update_keys: Arc::new(Vec::new()), // This will be set during validation
            active_witness: None,                     // This will be set during validation
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        SCID_HOLDER,
        witness::{Witness, Witnesses},
    };

    use super::Parameters;

    #[test]
    fn watchers_absent_serialize() {
        // Tests to ensure that watchers set to absent won't serialize
        let parameters = Parameters {
            watchers: None,
            ..Default::default()
        };

        let values = serde_json::to_value(parameters).unwrap();

        assert!(values.get("watchers").is_none())
    }

    #[test]
    fn diff_no_changes_full() {
        let old_params = Parameters {
            method: Some(crate::Version::V1_0Pre),
            scid: Some(Arc::new("scid123".to_string())),
            update_keys: Some(Arc::new(vec![
                "z6Mkp7QveNebyWs4z1kJ7Aa7CymUjRpjPYnBYh6Cr1t6JoXY".to_string(),
                "z6MkqUa1LbqZ7EpevqrFC7XHAWM8CE49AKFWVjyu543NfVAp".to_string(),
            ])),
            portable: Some(true),
            next_key_hashes: Some(Arc::new(vec![
                "zQmS6fKbreQixpa6JueaSuDiL2VQAGosC45TDQdKHf5E155".to_string(),
                "zQmctZhRGCKrE2R58K9rkfA1aUL74mecrrJRvicz42resii".to_string(),
            ])),
            witness: Some(Arc::new(Witnesses::Value {
                threshold: 2,
                witnesses: vec![
                    Witness {
                        id: "witness1".to_string(),
                    },
                    Witness {
                        id: "witness2".to_string(),
                    },
                ],
            })),
            watchers: Some(Arc::new(vec!["watcher1".to_string()])),
            deactivated: Some(false),
            ttl: Some(3600),
            ..Default::default()
        };

        let new_params = old_params.clone();

        let result = old_params.diff(&new_params).expect("Diff failed");
        assert_eq!(serde_json::to_string(&result).unwrap(), "{}");
    }

    #[test]
    fn diff_no_changes_empty() {
        let old_params = Parameters {
            method: Some(crate::Version::V1_0Pre),
            ..Default::default()
        };

        let new_params = old_params.clone();

        let result = old_params.diff(&new_params).expect("Diff failed");
        assert_eq!(serde_json::to_string(&result).unwrap(), "{}");
    }

    #[test]
    fn diff_no_changes_method() {
        let old_params = Parameters::default();

        let new_params = Parameters {
            method: Some(crate::Version::V1_0Pre),
            ..Default::default()
        };

        let result = old_params.diff(&new_params).expect("Diff failed");
        assert_eq!(serde_json::to_string(&result).unwrap(), "{}");
    }

    #[test]
    fn pre_rotation_active() {
        // On first LogEntry, if next_hashes is configured, then pre-rotation is active
        let first_params = Parameters {
            update_keys: Some(Arc::new(vec![
                "z6Mkp7QveNebyWs4z1kJ7Aa7CymUjRpjPYnBYh6Cr1t6JoXY".to_string(),
            ])),
            next_key_hashes: Some(Arc::new(vec![
                "zQmS6fKbreQixpa6JueaSuDiL2VQAGosC45TDQdKHf5E155".to_string(),
            ])),
            scid: Some(Arc::new(SCID_HOLDER.to_string())),
            ..Default::default()
        };

        let validated = first_params
            .validate(None)
            .expect("First Log Entry should be valid");

        assert!(validated.pre_rotation_active);
    }

    // ****** Checking differential on Parameter attribute tri-state
    #[test]
    fn diff_tri_state_absent() {
        let diff = Parameters::diff_tri_state(&None, &None, "test");
        assert!(diff.is_ok_and(|a| a.is_none()));
    }

    #[test]
    fn diff_tri_state_empty() {
        // Absent --> Empty = Empty
        let diff = Parameters::diff_tri_state(&None, &Some(Arc::new(Vec::new())), "test")
            .expect("Parameters::diff_update_keys() error");
        assert!(diff.is_some_and(|a| a.is_empty()));

        // Values --> Empty = Empty
        let diff = Parameters::diff_tri_state(
            &Some(Arc::new(vec!["test".to_string()])),
            &Some(Arc::new(Vec::new())),
            "test",
        )
        .expect("Parameters::diff_update_keys() error");
        assert!(diff.is_some_and(|a| a.is_empty()));
    }

    #[test]
    fn diff_tri_state_double_empty() {
        assert!(
            Parameters::diff_tri_state(
                &Some(Arc::new(Vec::new())),
                &Some(Arc::new(Vec::new())),
                "test"
            )
            .is_err()
        );
    }

    #[test]
    fn diff_tri_state_value() {
        // From nothing to something
        let test = Some(Arc::new(vec!["test".to_string()]));
        let diff = Parameters::diff_tri_state(&None, &test.clone(), "test")
            .expect("Parameters::diff_update_keys error");
        assert!(diff == test);
    }

    #[test]
    fn diff_tri_state_same_value() {
        let diff = Parameters::diff_tri_state(
            &Some(Arc::new(vec!["test".to_string()])),
            &Some(Arc::new(vec!["test".to_string()])),
            "test",
        )
        .expect("Parameters::diff_update_keys error");
        assert!(diff.is_none());
    }

    #[test]
    fn diff_tri_state_different_value() {
        let diff = Parameters::diff_tri_state(
            &Some(Arc::new(vec!["old".to_string()])),
            &Some(Arc::new(vec!["new".to_string()])),
            "test",
        )
        .expect("Parameters::diff_update_keys error");
        assert!(diff.is_some_and(|a| a.first().unwrap().as_str() == "new"));
    }

    #[test]
    fn diff_update_keys_pre_rotation_empty() {
        let previous = Parameters {
            pre_rotation_active: true,
            ..Default::default()
        };

        let current = Parameters {
            update_keys: Some(Arc::new(Vec::new())),
            ..Default::default()
        };
        assert!(previous.diff(&current).is_err());
    }

    #[test]
    fn diff_update_keys_pre_rotation_none() {
        let previous = Parameters {
            pre_rotation_active: true,
            ..Default::default()
        };

        let current = Parameters {
            update_keys: None,
            ..Default::default()
        };
        assert!(previous.diff(&current).is_err());
    }
}
