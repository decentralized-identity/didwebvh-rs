/*!
*   Handles converting a WebVH DID to a Web DID Document
*/

use crate::{
    DIDWebVHError, DIDWebVHState, log_entry_state::LogEntryState,
    resolve::implicit::update_implicit_services,
};
use regex::Regex;
use serde_json::Value;

impl DIDWebVHState {
    /// Converts the last LogEntry to a DID Web Document
    /// Will change the DID ID's as required
    /// NOTE: You may still want to check the resulting DID Document for validity
    pub fn to_web_did(&self) -> Result<Value, DIDWebVHError> {
        if let Some(log_entry) = self.log_entries.last() {
            log_entry.to_web_did()
        } else {
            // There is no Log Entry
            Err(DIDWebVHError::NotFound)
        }
    }
    ///
    /// Takes a did:webvh ID and converts it to a did:web ID
    pub fn convert_webvh_id_to_web_id(id: &str) -> String {
        // input: did:webvh:<SCID>:<path>
        let parts: Vec<&str> = id.split(':').collect();
        let mut new_did = String::new();
        new_did.push_str("did:web");
        for p in parts[3..].iter() {
            new_did.push(':');
            new_did.push_str(p);
        }
        new_did
    }
}

impl LogEntryState {
    /// Converts this LogEntry State to a DID Web Document
    /// Converts the DID references automatically
    /// NOTE: You may still want to check the resulting DID Document for validity
    pub fn to_web_did(&self) -> Result<Value, DIDWebVHError> {
        let state = self.get_state();
        if !state.is_object() {
            return Err(DIDWebVHError::DIDError(
                "State is not a valid JSON Object".to_string(),
            ));
        }

        to_web_did(state)
    }
}

fn to_web_did(old_state: &Value) -> Result<Value, DIDWebVHError> {
    // What is the new DID?
    let (webvh_did, web_did) = if let Some(id) = old_state.get("id")
        && let Some(id_str) = id.as_str()
    {
        (
            id_str.to_string(),
            DIDWebVHState::convert_webvh_id_to_web_id(id_str),
        )
    } else {
        return Err(DIDWebVHError::DIDError(
            "Couldn't find DID (id) attribute".to_string(),
        ));
    };

    let service = old_state.get("service");
    let mut old_state = old_state.clone();
    // Add implicit WebVH Services if not present
    update_implicit_services(service, &mut old_state, &webvh_did)?;

    let did_doc = serde_json::to_string(&old_state)
        .map_err(|e| DIDWebVHError::DIDError(format!("Couldn't serialize state: {}", e)))?;

    // Replace the existing did:webvh:<SCID> with did:web
    let re = Regex::new(r"(did:webvh:[^:]+)")
        .map_err(|e| DIDWebVHError::DIDError(format!("Couldn't create regex: {}", e)))?;
    let new_did_doc = re.replace_all(&did_doc, "did:web");

    let mut new_state: Value = serde_json::from_str(&new_did_doc)
        .map_err(|e| DIDWebVHError::DIDError(format!("Couldn't parse new state: {}", e)))?;

    // Set the DID id
    new_state
        .as_object_mut()
        .unwrap()
        .insert("id".to_string(), Value::String(web_did.clone()));

    // Reset the controller to be the webvh original ID
    new_state
        .as_object_mut()
        .unwrap()
        .insert("controller".to_string(), Value::String(webvh_did.clone()));

    // Update alsoKnownAs
    update_also_known_as(
        old_state.get("alsoKnownAs"),
        &mut new_state,
        &webvh_did,
        &web_did,
    )?;

    Ok(new_state)
}

// Manages the updates to the alsoKnownAs DID attribute
// Checks each entry, removes itself if it exists already
// Adds the WebVH entry if it doesn't exist
fn update_also_known_as(
    also_known_as: Option<&Value>,
    new_state: &mut Value,
    old_did: &str,
    new_did: &str,
) -> Result<(), DIDWebVHError> {
    let Some(also_known_as) = also_known_as else {
        // There is no alsoKnownAs, add the old_did
        new_state.as_object_mut().unwrap().insert(
            "alsoKnownAs".to_string(),
            Value::Array(vec![Value::String(old_did.to_string())]),
        );
        return Ok(());
    };

    let mut did_webvh_exists = false;
    let mut new_aliases = vec![];

    if let Some(aliases) = also_known_as.as_array() {
        for alias in aliases {
            if let Some(alias_str) = alias.as_str() {
                if alias_str == new_did {
                    // did:web already exists, skip it
                } else if alias_str == old_did {
                    // did:webvh already exists, add it
                    did_webvh_exists = true;
                    new_aliases.push(alias.clone());
                } else {
                    new_aliases.push(alias.clone());
                }
            }
        }
    } else {
        return Err(DIDWebVHError::DIDError(
            "alsoKnownAs is not an array".to_string(),
        ));
    }

    if !did_webvh_exists {
        // webvh DID isn't an alias, add it
        new_aliases.push(Value::String(old_did.to_string()));
    }

    new_state
        .as_object_mut()
        .unwrap()
        .insert("alsoKnownAs".to_string(), Value::Array(new_aliases));

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{DIDWebVHState, did_web::to_web_did};
    use serde::Deserialize;
    use serde_json::{Value, json};

    // Dummy struct to help with testing DID Services
    #[derive(Deserialize, PartialEq)]
    struct Service {
        pub id: String,
        #[serde(rename = "serviceEndpoint")]
        pub service_endpoint: String,
    }

    #[test]
    fn test_no_log_entry() {
        let state = DIDWebVHState::default();

        assert!(state.to_web_did().is_err());
    }

    #[test]
    fn test_id_conversion() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com:path"});

        let new_state = to_web_did(&old_state).expect("Couldn't convert to did:web");
        assert_eq!(
            new_state
                .get("id")
                .expect("Couldn't find (id)")
                .as_str()
                .expect("Expected a string for (id)"),
            "did:web:affinidi.com:path"
        );

        assert_eq!(
            new_state
                .get("controller")
                .expect("Couldn't find (controller)")
                .as_str()
                .expect("Expected a string for (controller)"),
            "did:webvh:acme1234:affinidi.com:path"
        );
    }

    #[test]
    fn test_missing_id() {
        let old_state = json!({"not_id": "did:webvh:acme1234:affinidi.com:path"});

        assert!(to_web_did(&old_state).is_err());
    }

    #[test]
    fn test_not_object() {
        let old_state = Value::String("Not an object".to_string());

        assert!(to_web_did(&old_state).is_err());
    }

    #[test]
    fn test_also_known_as_empty() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com"});

        let did_web = to_web_did(&old_state).expect("Couldn't convert to did:web");

        let also_known_as: Vec<String> = serde_json::from_value(
            did_web
                .get("alsoKnownAs")
                .expect("alsoKnownAs in did:web doesn't exist")
                .to_owned(),
        )
        .expect("Couldn't process alsoKnownAs attribute");

        assert_eq!(also_known_as.len(), 1);
        assert!(also_known_as.contains(&"did:webvh:acme1234:affinidi.com".to_string()));
    }

    #[test]
    fn test_also_known_as_existing_webvh() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com", "alsoKnownAs": ["did:webvh:acme1234:affinidi.com"]});

        let did_web = to_web_did(&old_state).expect("Couldn't convert to did:web");

        let also_known_as: Vec<String> = serde_json::from_value(
            did_web
                .get("alsoKnownAs")
                .expect("alsoKnownAs in did:web doesn't exist")
                .to_owned(),
        )
        .expect("Couldn't process alsoKnownAs attribute");

        assert_eq!(also_known_as.len(), 1);
        assert!(also_known_as.contains(&"did:webvh:acme1234:affinidi.com".to_string()));
    }

    #[test]
    fn test_also_known_as_existing_web() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com", "alsoKnownAs": ["did:web:affinidi.com"]});

        let did_web = to_web_did(&old_state).expect("Couldn't convert to did:web");

        let also_known_as: Vec<String> = serde_json::from_value(
            did_web
                .get("alsoKnownAs")
                .expect("alsoKnownAs in did:web doesn't exist")
                .to_owned(),
        )
        .expect("Couldn't process alsoKnownAs attribute");

        assert_eq!(also_known_as.len(), 1);
        assert!(!also_known_as.contains(&"did:web:affinidi.com".to_string()));
        assert!(also_known_as.contains(&"did:webvh:acme1234:affinidi.com".to_string()));
    }

    #[test]
    fn test_also_known_as_existing_many() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com", "alsoKnownAs": ["did:web:affinidi.com", "did:webvh:acme1234:affinidi.com", "did:web:unknown.com", "did:web:another.alias"]});

        let did_web = to_web_did(&old_state).expect("Couldn't convert to did:web");

        let also_known_as: Vec<String> = serde_json::from_value(
            did_web
                .get("alsoKnownAs")
                .expect("alsoKnownAs in did:web doesn't exist")
                .to_owned(),
        )
        .expect("Couldn't process alsoKnownAs attribute");

        assert_eq!(also_known_as.len(), 3);
        assert!(!also_known_as.contains(&"did:web:affinidi.com".to_string()));
        assert!(also_known_as.contains(&"did:web:unknown.com".to_string()));
        assert!(also_known_as.contains(&"did:webvh:acme1234:affinidi.com".to_string()));
    }

    #[test]
    fn test_services_none() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com"});

        let did_web = to_web_did(&old_state).expect("Couldn't convert to did:web");

        let services: Vec<Service> = serde_json::from_value(
            did_web
                .get("service")
                .expect("service in did:web doesn't exist")
                .to_owned(),
        )
        .expect("Couldn't process service attribute");

        assert_eq!(services.len(), 2);
        assert!(services.contains(&Service {
            id: "did:web:affinidi.com#files".to_string(),
            service_endpoint: "https://affinidi.com/".to_string()
        }));
        assert!(services.contains(&Service {
            id: "did:web:affinidi.com#whois".to_string(),
            service_endpoint: "https://affinidi.com/whois.vp".to_string()
        }));
    }

    #[test]
    fn test_services_none_custom_path() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com:custom:path"});

        let did_web = to_web_did(&old_state).expect("Couldn't convert to did:web");

        let services: Vec<Service> = serde_json::from_value(
            did_web
                .get("service")
                .expect("service in did:web doesn't exist")
                .to_owned(),
        )
        .expect("Couldn't process service attribute");

        assert_eq!(services.len(), 2);
        assert!(services.contains(&Service {
            id: "did:web:affinidi.com:custom:path#files".to_string(),
            service_endpoint: "https://affinidi.com/custom/path/".to_string()
        }));
        assert!(services.contains(&Service {
            id: "did:web:affinidi.com:custom:path#whois".to_string(),
            service_endpoint: "https://affinidi.com/custom/path/whois.vp".to_string()
        }));
    }
}
