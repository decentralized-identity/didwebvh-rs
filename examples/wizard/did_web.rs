use console::style;
use didwebvh_rs::{DIDWebVHError, log_entry_state::LogEntryState};
use std::{fs::OpenOptions, io::Write};

/// Save a did:web document (did.json) from a log entry state.
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
