use std::{fs::OpenOptions, io::Write};

use console::style;
use dialoguer::{Confirm, theme::ColorfulTheme};
use didwebvh_rs::{DIDWebVHError, DIDWebVHState, log_entry_state::LogEntryState};
use serde_json::Value;

// Checks to see if the did:web needs to be added to alsoKnownAs
pub fn insert_also_known_as(did_document: &mut Value, did: &str) -> Result<(), DIDWebVHError> {
    let did_web_id = DIDWebVHState::convert_webvh_id_to_web_id(did);

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Add ({did_web_id}) to alsoKnownAs for the did:webvh document?"
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
                Value::Array(vec![Value::String(did_web_id.to_string())]),
            );
            return Ok(());
        };

        let mut new_aliases = vec![];
        let mut skip_flag = false;

        if let Some(aliases) = also_known_as.as_array() {
            for alias in aliases {
                if let Some(alias_str) = alias.as_str() {
                    if alias_str == did_web_id {
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
            new_aliases.push(Value::String(did_web_id.to_string()));
        }

        did_document
            .as_object_mut()
            .unwrap()
            .insert("alsoKnownAs".to_string(), Value::Array(new_aliases));
    }
    Ok(())
}

// Save a did:web document (did.json)
pub fn save_did_web(log_entry: &LogEntryState) -> Result<(), DIDWebVHError> {
    let did_web = log_entry.to_web_did()?;

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("did.json")
        .map_err(|e| DIDWebVHError::LogEntryError(format!("Couldn't open file (did.json): {e}")))?;

    file.write_all(
        serde_json::to_string_pretty(&did_web)
            .map_err(|e| {
                DIDWebVHError::LogEntryError(format!(
                    "Couldn't serialize did:web Document to JSON. Reason: {e}",
                ))
            })?
            .as_bytes(),
    )
    .map_err(|e| {
        DIDWebVHError::LogEntryError(format!(
            "Couldn't append LogEntry to file(did.json). Reason: {e}",
        ))
    })?;

    println!(
        "{} {}",
        style("did:web saved to :").color256(69),
        style("did.json").color256(214),
    );

    Ok(())
}
