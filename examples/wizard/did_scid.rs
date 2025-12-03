use dialoguer::{Confirm, theme::ColorfulTheme};
use didwebvh_rs::{DIDWebVHError, DIDWebVHState};
use serde_json::Value;

// Adds a did:scid:vh:1:.. aslias to alsoKnownAs
pub fn insert_scid_also_known_as(did_document: &mut Value, did: &str) -> Result<(), DIDWebVHError> {
    let did_scid_id = DIDWebVHState::convert_webvh_id_to_scid_id(did);

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Add ({did_scid_id}) to alsoKnownAs for the did:webvh document?"
        ))
        .default(true)
        .interact()
        .unwrap()
    {
        let also_known_as = did_document.get_mut("alsoKnownAs");

        let Some(also_known_as) = also_known_as else {
            // There is no alsoKnownAs, add the did:web
            did_document.as_object_mut().unwrap().insert(
                "alsoKnownAs".to_string(),
                Value::Array(vec![Value::String(did_scid_id.to_string())]),
            );
            return Ok(());
        };

        let mut new_aliases = vec![];
        let mut skip_flag = false;

        if let Some(aliases) = also_known_as.as_array() {
            for alias in aliases {
                if let Some(alias_str) = alias.as_str() {
                    if alias_str == did_scid_id {
                        // did:web already exists, skip it
                        skip_flag = true;
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

        if !skip_flag {
            // web DID isn't an alias, add it
            new_aliases.push(Value::String(did_scid_id.to_string()));
        }

        did_document
            .as_object_mut()
            .unwrap()
            .insert("alsoKnownAs".to_string(), Value::Array(new_aliases));
    }
    Ok(())
}
