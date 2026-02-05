use console::style;
use dialoguer::{Confirm, theme::ColorfulTheme};
use didwebvh_rs::{DIDWebVHError, DIDWebVHState, log_entry_state::LogEntryState};
use serde_json::Value;
use std::{fs::OpenOptions, io::Write};

// Checks to see if the did:web needs to be added to alsoKnownAs
pub fn insert_web_also_known_as(did_document: &mut Value, did: &str) -> Result<(), DIDWebVHError> {
    let did_web_id = DIDWebVHState::convert_webvh_id_to_web_id(did);

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Add ({did_web_id}) to alsoKnownAs for the did:webvh document?"
        ))
        .default(true)
        .interact()
        .unwrap()
    {
        didwebvh_rs::create::add_web_also_known_as(did_document, did)?;
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
