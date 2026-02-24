/*!
*   Contains the parameters that define DID processing parameters
*   used when processing the current and previous Log Entry
*/

use crate::{Version, parameters::Parameters, witness::Witnesses};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// [https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters]
/// Parameters that help with the resolution of a webvh DID
///
/// None = field wasn't specified
/// Some(Empty Array/Object) = Cancel the previous Parameters value
/// Some(Value) = set to new value
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameters1_0 {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_keys: Option<Arc<Vec<String>>>,

    /// Can you change the web address for this DID?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portable: Option<bool>,

    /// pre-rotation keys that must be shared prior to updating update keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_key_hashes: Option<Arc<Vec<String>>>,

    /// Parameters for witness nodes
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
}

impl Default for Parameters1_0 {
    fn default() -> Self {
        Parameters1_0 {
            pre_rotation_active: false,
            method: Some("did:webvh:1.0".to_string()),
            scid: None,
            update_keys: None,
            portable: None,
            next_key_hashes: None,
            witness: None,
            watchers: None,
            deactivated: None,
            ttl: Some(3600),
        }
    }
}

impl From<Parameters> for Parameters1_0 {
    fn from(value: Parameters) -> Self {
        Parameters1_0 {
            deactivated: value.deactivated,
            pre_rotation_active: value.pre_rotation_active,
            method: value.method.map(|_| Version::V1_0.to_string()),
            next_key_hashes: value.next_key_hashes.clone(),
            scid: value.scid.clone(),
            ttl: value.ttl,
            update_keys: value.update_keys.clone(),
            portable: value.portable,
            witness: value.witness.clone(),
            watchers: value.watchers.clone(),
        }
    }
}

impl From<Parameters1_0> for Parameters {
    fn from(value: Parameters1_0) -> Parameters {
        Parameters {
            deactivated: value.deactivated,
            pre_rotation_active: value.pre_rotation_active,
            method: value.method.map(|_| Version::V1_0),
            next_key_hashes: value.next_key_hashes.clone(),
            scid: value.scid.clone(),
            ttl: value.ttl,
            update_keys: value.update_keys.clone(),
            portable: value.portable,
            witness: value.witness.clone(),
            watchers: value.watchers.clone(),
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
            method: Some(crate::Version::V1_0),
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
            method: Some(crate::Version::V1_0),
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
            method: Some(crate::Version::V1_0),
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
        // Both empty -> no change (not an error)
        let diff = Parameters::diff_tri_state(
            &Some(Arc::new(Vec::new())),
            &Some(Arc::new(Vec::new())),
            "test",
        )
        .expect("Both empty should not error");
        assert!(diff.is_none());
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

    // ****** Witness parameter tests

    /// Helper to create a minimal valid first-entry Parameters
    fn first_entry_params() -> Parameters {
        Parameters {
            scid: Some(Arc::new(SCID_HOLDER.to_string())),
            update_keys: Some(Arc::new(vec![
                "z6Mkp7QveNebyWs4z1kJ7Aa7CymUjRpjPYnBYh6Cr1t6JoXY".to_string(),
            ])),
            ..Default::default()
        }
    }

    fn sample_witnesses() -> Arc<Witnesses> {
        Arc::new(Witnesses::Value {
            threshold: 1,
            witnesses: vec![Witness {
                id: "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7lL8N8AC4Pp6".to_string(),
            }],
        })
    }

    fn sample_witnesses_2() -> Arc<Witnesses> {
        Arc::new(Witnesses::Value {
            threshold: 2,
            witnesses: vec![
                Witness {
                    id: "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7lL8N8AC4Pp6".to_string(),
                },
                Witness {
                    id: "z6MkqUa1LbqZ7EpevqrFC7XHAWM8CE49AKFWVjyu543NfVAp".to_string(),
                },
            ],
        })
    }

    // -- First log entry validate() tests --

    #[test]
    fn validate_first_entry_witness_none() {
        let params = first_entry_params();
        let validated = params.validate(None).expect("Should succeed");
        assert!(validated.witness.is_none());
        assert!(validated.active_witness.is_none());
    }

    #[test]
    fn validate_first_entry_witness_empty_object() {
        // witness: {} is valid per spec — means no witnesses configured
        let params = Parameters {
            witness: Some(Arc::new(Witnesses::Empty {})),
            ..first_entry_params()
        };
        let validated = params.validate(None).expect("witness: {} on first entry should succeed");
        assert!(validated.witness.is_none());
        assert!(validated.active_witness.is_none());
    }

    #[test]
    fn validate_first_entry_witness_with_values() {
        let params = Parameters {
            witness: Some(sample_witnesses()),
            ..first_entry_params()
        };
        let validated = params.validate(None).expect("Should succeed");
        assert!(validated.witness.is_some());
        assert!(validated.active_witness.is_some());
        assert!(!validated.witness.as_ref().unwrap().is_empty());
    }

    #[test]
    fn validate_first_entry_witness_invalid_threshold() {
        let params = Parameters {
            witness: Some(Arc::new(Witnesses::Value {
                threshold: 0,
                witnesses: vec![Witness {
                    id: "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7lL8N8AC4Pp6".to_string(),
                }],
            })),
            ..first_entry_params()
        };
        assert!(params.validate(None).is_err());
    }

    #[test]
    fn validate_first_entry_witness_threshold_exceeds_count() {
        let params = Parameters {
            witness: Some(Arc::new(Witnesses::Value {
                threshold: 3,
                witnesses: vec![Witness {
                    id: "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7lL8N8AC4Pp6".to_string(),
                }],
            })),
            ..first_entry_params()
        };
        assert!(params.validate(None).is_err());
    }

    // -- Subsequent log entry validate() tests --

    #[test]
    fn validate_subsequent_witness_absent_inherits_none() {
        let previous = Parameters {
            witness: None,
            active_witness: None,
            ..first_entry_params()
        };
        let current = Parameters {
            witness: None,
            ..first_entry_params()
        };
        let validated = current
            .validate(Some(&previous))
            .expect("Should succeed");
        assert!(validated.witness.is_none());
        assert!(validated.active_witness.is_none());
    }

    #[test]
    fn validate_subsequent_witness_absent_inherits_value() {
        let previous = Parameters {
            witness: Some(sample_witnesses()),
            active_witness: Some(sample_witnesses()),
            ..first_entry_params()
        };
        let current = Parameters {
            witness: None,
            ..first_entry_params()
        };
        let validated = current
            .validate(Some(&previous))
            .expect("Should succeed");
        // Inherits previous witness config
        assert!(validated.witness.is_some());
        assert!(validated.active_witness.is_some());
    }

    #[test]
    fn validate_subsequent_witness_empty_deactivates() {
        // Setting witness: {} on a subsequent entry deactivates witnessing
        let previous = Parameters {
            witness: Some(sample_witnesses()),
            active_witness: Some(sample_witnesses()),
            ..first_entry_params()
        };
        let current = Parameters {
            witness: Some(Arc::new(Witnesses::Empty {})),
            ..first_entry_params()
        };
        let validated = current
            .validate(Some(&previous))
            .expect("Deactivating witnesses should succeed");
        // witness config cleared, but active_witness still set for this entry's proof requirements
        assert!(validated.witness.is_none());
        assert!(validated.active_witness.is_some());
    }

    #[test]
    fn validate_subsequent_witness_new_value() {
        let previous = Parameters {
            witness: Some(sample_witnesses()),
            active_witness: Some(sample_witnesses()),
            ..first_entry_params()
        };
        let current = Parameters {
            witness: Some(sample_witnesses_2()),
            ..first_entry_params()
        };
        let validated = current
            .validate(Some(&previous))
            .expect("Should succeed");
        // New witness config set, active_witness uses previous entry's witnesses
        assert_eq!(validated.witness, Some(sample_witnesses_2()));
        assert_eq!(validated.active_witness, Some(sample_witnesses()));
    }

    #[test]
    fn validate_subsequent_witness_activate_from_none() {
        let previous = Parameters {
            witness: None,
            active_witness: None,
            ..first_entry_params()
        };
        let current = Parameters {
            witness: Some(sample_witnesses()),
            ..first_entry_params()
        };
        let validated = current
            .validate(Some(&previous))
            .expect("Activating witnesses should succeed");
        assert_eq!(validated.witness, Some(sample_witnesses()));
        // active_witness is previous (None) — new witnesses take effect after publication
        assert!(validated.active_witness.is_none());
    }

    // -- diff_witness() tests --

    #[test]
    fn diff_witness_both_absent() {
        let diff = Parameters::diff_witness(&None, &None).expect("Should succeed");
        assert!(diff.is_none());
    }

    #[test]
    fn diff_witness_current_absent() {
        // Current None means "keep previous", so diff is None
        let diff = Parameters::diff_witness(&Some(sample_witnesses()), &None)
            .expect("Should succeed");
        assert!(diff.is_none());
    }

    #[test]
    fn diff_witness_previous_absent_current_empty() {
        // Absent -> Empty = emit Empty (deactivation from no prior state)
        let diff =
            Parameters::diff_witness(&None, &Some(Arc::new(Witnesses::Empty {})))
                .expect("Should succeed");
        assert!(diff.is_some());
        assert!(diff.unwrap().is_empty());
    }

    #[test]
    fn diff_witness_previous_value_current_empty() {
        // Value -> Empty = emit Empty (deactivation)
        let diff = Parameters::diff_witness(
            &Some(sample_witnesses()),
            &Some(Arc::new(Witnesses::Empty {})),
        )
        .expect("Should succeed");
        assert!(diff.is_some());
        assert!(diff.unwrap().is_empty());
    }

    #[test]
    fn diff_witness_both_empty() {
        // Both empty -> no change (not an error)
        let diff = Parameters::diff_witness(
            &Some(Arc::new(Witnesses::Empty {})),
            &Some(Arc::new(Witnesses::Empty {})),
        )
        .expect("Both empty should not error");
        assert!(diff.is_none());
    }

    #[test]
    fn diff_witness_same_value() {
        // Same value -> no change
        let diff = Parameters::diff_witness(&Some(sample_witnesses()), &Some(sample_witnesses()))
            .expect("Should succeed");
        assert!(diff.is_none());
    }

    #[test]
    fn diff_witness_different_value() {
        // Different values -> emit new value
        let diff =
            Parameters::diff_witness(&Some(sample_witnesses()), &Some(sample_witnesses_2()))
                .expect("Should succeed");
        assert_eq!(diff, Some(sample_witnesses_2()));
    }

    #[test]
    fn diff_witness_absent_to_value() {
        // None -> Value = emit new value
        let diff = Parameters::diff_witness(&None, &Some(sample_witnesses()))
            .expect("Should succeed");
        assert_eq!(diff, Some(sample_witnesses()));
    }

    #[test]
    fn diff_witness_empty_to_value() {
        // Empty -> Value = emit new value (activation)
        let diff = Parameters::diff_witness(
            &Some(Arc::new(Witnesses::Empty {})),
            &Some(sample_witnesses()),
        )
        .expect("Should succeed");
        assert_eq!(diff, Some(sample_witnesses()));
    }

    // -- Serialization tests --

    #[test]
    fn witness_empty_serializes_to_empty_object() {
        let w = Witnesses::Empty {};
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn witness_empty_deserializes_from_empty_object() {
        let w: Witnesses = serde_json::from_str("{}").unwrap();
        assert!(w.is_empty());
    }

    #[test]
    fn witness_value_roundtrips() {
        let w = Witnesses::Value {
            threshold: 2,
            witnesses: vec![
                Witness {
                    id: "witness1".to_string(),
                },
                Witness {
                    id: "witness2".to_string(),
                },
            ],
        };
        let json = serde_json::to_string(&w).unwrap();
        let w2: Witnesses = serde_json::from_str(&json).unwrap();
        assert_eq!(w, w2);
    }

    #[test]
    fn parameters_with_witness_empty_serializes_without_witness() {
        // After validation, witness: {} on first entry is normalized to None,
        // so it should not appear in serialized output
        let params = Parameters {
            witness: Some(Arc::new(Witnesses::Empty {})),
            ..first_entry_params()
        };
        let validated = params.validate(None).unwrap();
        let json = serde_json::to_value(&validated).unwrap();
        assert!(json.get("witness").is_none());
    }

    // ****** Watcher parameter tests

    // -- First log entry validate() tests --

    #[test]
    fn validate_first_entry_watchers_none() {
        let params = first_entry_params();
        let validated = params.validate(None).expect("Should succeed");
        assert!(validated.watchers.is_none());
    }

    #[test]
    fn validate_first_entry_watchers_empty_array() {
        // watchers: [] is valid per spec — means no watchers configured
        let params = Parameters {
            watchers: Some(Arc::new(Vec::new())),
            ..first_entry_params()
        };
        let validated = params
            .validate(None)
            .expect("watchers: [] on first entry should succeed");
        assert!(validated.watchers.is_none());
    }

    #[test]
    fn validate_first_entry_watchers_with_values() {
        let params = Parameters {
            watchers: Some(Arc::new(vec!["https://watcher.example.com".to_string()])),
            ..first_entry_params()
        };
        let validated = params.validate(None).expect("Should succeed");
        assert!(validated.watchers.is_some());
        assert_eq!(validated.watchers.as_ref().unwrap().len(), 1);
    }

    // -- Subsequent log entry validate() tests --

    #[test]
    fn validate_subsequent_watchers_absent_inherits_none() {
        let previous = Parameters {
            watchers: None,
            ..first_entry_params()
        };
        let current = Parameters {
            watchers: None,
            ..first_entry_params()
        };
        let validated = current
            .validate(Some(&previous))
            .expect("Should succeed");
        assert!(validated.watchers.is_none());
    }

    #[test]
    fn validate_subsequent_watchers_absent_inherits_value() {
        let previous = Parameters {
            watchers: Some(Arc::new(vec!["https://watcher.example.com".to_string()])),
            ..first_entry_params()
        };
        let current = Parameters {
            watchers: None,
            ..first_entry_params()
        };
        let validated = current
            .validate(Some(&previous))
            .expect("Should succeed");
        assert_eq!(
            validated.watchers,
            Some(Arc::new(vec!["https://watcher.example.com".to_string()]))
        );
    }

    #[test]
    fn validate_subsequent_watchers_empty_deactivates() {
        let previous = Parameters {
            watchers: Some(Arc::new(vec!["https://watcher.example.com".to_string()])),
            ..first_entry_params()
        };
        let current = Parameters {
            watchers: Some(Arc::new(Vec::new())),
            ..first_entry_params()
        };
        let validated = current
            .validate(Some(&previous))
            .expect("Deactivating watchers should succeed");
        assert!(validated.watchers.is_none());
    }

    #[test]
    fn validate_subsequent_watchers_new_value() {
        let previous = Parameters {
            watchers: Some(Arc::new(vec!["https://old.example.com".to_string()])),
            ..first_entry_params()
        };
        let current = Parameters {
            watchers: Some(Arc::new(vec!["https://new.example.com".to_string()])),
            ..first_entry_params()
        };
        let validated = current
            .validate(Some(&previous))
            .expect("Should succeed");
        assert_eq!(
            validated.watchers,
            Some(Arc::new(vec!["https://new.example.com".to_string()]))
        );
    }

    #[test]
    fn validate_subsequent_watchers_activate_from_none() {
        let previous = Parameters {
            watchers: None,
            ..first_entry_params()
        };
        let current = Parameters {
            watchers: Some(Arc::new(vec!["https://watcher.example.com".to_string()])),
            ..first_entry_params()
        };
        let validated = current
            .validate(Some(&previous))
            .expect("Should succeed");
        assert!(validated.watchers.is_some());
    }

    // -- diff_tri_state watchers-specific tests --

    #[test]
    fn diff_watchers_both_empty() {
        // Both empty -> no change
        let diff = Parameters::diff_tri_state(
            &Some(Arc::new(Vec::new())),
            &Some(Arc::new(Vec::new())),
            "watchers",
        )
        .expect("Both empty watchers should not error");
        assert!(diff.is_none());
    }

    #[test]
    fn diff_watchers_value_to_empty() {
        let diff = Parameters::diff_tri_state(
            &Some(Arc::new(vec!["https://watcher.example.com".to_string()])),
            &Some(Arc::new(Vec::new())),
            "watchers",
        )
        .expect("Should succeed");
        assert!(diff.is_some_and(|a| a.is_empty()));
    }

    #[test]
    fn diff_watchers_absent_to_empty() {
        let diff = Parameters::diff_tri_state(
            &None,
            &Some(Arc::new(Vec::new())),
            "watchers",
        )
        .expect("Should succeed");
        assert!(diff.is_some_and(|a| a.is_empty()));
    }

    #[test]
    fn parameters_with_watchers_empty_serializes_without_watchers() {
        // After validation, watchers: [] on first entry is normalized to None
        let params = Parameters {
            watchers: Some(Arc::new(Vec::new())),
            ..first_entry_params()
        };
        let validated = params.validate(None).unwrap();
        let json = serde_json::to_value(&validated).unwrap();
        assert!(json.get("watchers").is_none());
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

    // ****** Parameters1_0 round-trip serialization tests
    //
    // These verify that deserialize → serialize produces identical JSON,
    // which is critical for signature and entry hash verification.

    use super::Parameters1_0;

    #[test]
    fn parameters_1_0_roundtrip_with_all_empty_values() {
        // Simulates the didwebvh-ts first entry parameters
        let json = serde_json::json!({
            "method": "did:webvh:1.0",
            "scid": "QmRYeabNZ8KSFrLXxWAK1VB5vx4XmU4w389T5xhp5qwVGS",
            "updateKeys": ["z6Mkiq4dQWqVEbtpmFButES3mBQ87y61jihJ7Wsh1x3iA9yT"],
            "portable": false,
            "nextKeyHashes": [],
            "watchers": [],
            "witness": {},
            "deactivated": false
        });

        let params: Parameters1_0 = serde_json::from_value(json.clone()).unwrap();
        let re_serialized = serde_json::to_value(&params).unwrap();

        assert_eq!(json, re_serialized, "Parameters1_0 round-trip must be lossless");
    }

    #[test]
    fn parameters_1_0_roundtrip_minimal() {
        // Only required fields, no optional fields
        let json = serde_json::json!({
            "method": "did:webvh:1.0",
            "scid": "QmRYeabNZ8KSFrLXxWAK1VB5vx4XmU4w389T5xhp5qwVGS",
            "updateKeys": ["z6Mkiq4dQWqVEbtpmFButES3mBQ87y61jihJ7Wsh1x3iA9yT"]
        });

        let params: Parameters1_0 = serde_json::from_value(json.clone()).unwrap();
        let re_serialized = serde_json::to_value(&params).unwrap();

        assert_eq!(json, re_serialized, "Minimal parameters round-trip must be lossless");
    }

    #[test]
    fn parameters_1_0_roundtrip_deactivated_false_preserved() {
        let json = serde_json::json!({
            "method": "did:webvh:1.0",
            "scid": "test",
            "updateKeys": ["key1"],
            "deactivated": false
        });

        let params: Parameters1_0 = serde_json::from_value(json.clone()).unwrap();
        let re_serialized = serde_json::to_value(&params).unwrap();

        assert_eq!(
            re_serialized.get("deactivated"),
            Some(&serde_json::json!(false)),
            "deactivated:false must be preserved in round-trip"
        );
    }

    #[test]
    fn parameters_1_0_roundtrip_deactivated_absent_stays_absent() {
        let json = serde_json::json!({
            "method": "did:webvh:1.0",
            "scid": "test",
            "updateKeys": ["key1"]
        });

        let params: Parameters1_0 = serde_json::from_value(json.clone()).unwrap();
        let re_serialized = serde_json::to_value(&params).unwrap();

        assert!(
            re_serialized.get("deactivated").is_none(),
            "absent deactivated must remain absent in round-trip"
        );
    }

    #[test]
    fn parameters_1_0_roundtrip_deactivated_true() {
        let json = serde_json::json!({
            "method": "did:webvh:1.0",
            "scid": "test",
            "updateKeys": [],
            "deactivated": true
        });

        let params: Parameters1_0 = serde_json::from_value(json.clone()).unwrap();
        let re_serialized = serde_json::to_value(&params).unwrap();

        assert_eq!(
            re_serialized.get("deactivated"),
            Some(&serde_json::json!(true)),
            "deactivated:true must be preserved"
        );
    }
}
