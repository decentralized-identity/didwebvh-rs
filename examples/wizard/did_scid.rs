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
        didwebvh_rs::create::add_scid_also_known_as(did_document, did)?;
    }
    Ok(())
}
