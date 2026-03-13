//! Example: Create a DID and then update its document using `update_document()`.

use didwebvh_rs::affinidi_secrets_resolver::secrets::Secret;
use didwebvh_rs::prelude::*;
use serde_json::json;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Generate a signing key
    let mut signing_key = Secret::generate_ed25519(None, None);
    let pk = signing_key.get_public_keymultibase().unwrap();
    signing_key.id = format!("did:key:{pk}#{pk}");

    let parameters = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(pk.clone())])),
        portable: Some(false),
        ..Default::default()
    };

    let did_document = json!({
        "id": "did:webvh:{SCID}:example.com",
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": "did:webvh:{SCID}:example.com#key-0",
            "type": "Multikey",
            "publicKeyMultibase": pk,
            "controller": "did:webvh:{SCID}:example.com"
        }],
        "authentication": ["did:webvh:{SCID}:example.com#key-0"],
        "assertionMethod": ["did:webvh:{SCID}:example.com#key-0"],
    });

    // Create the initial log entry
    let mut state = DIDWebVHState::default();
    let entry = state
        .create_log_entry(None, &did_document, &parameters, &signing_key)
        .await
        .expect("Failed to create first log entry");
    println!("Created DID, version: {}", entry.get_version_id());

    // Get the actual document (with SCID replaced) for the update
    let current_doc = state.log_entries().last().unwrap().get_state().clone();

    // Add a service endpoint to the document
    let mut updated_doc = current_doc;
    if let Some(obj) = updated_doc.as_object_mut() {
        let did_id = obj["id"].as_str().unwrap().to_string();
        obj.insert(
            "service".to_string(),
            json!([{
                "id": format!("{did_id}#service-1"),
                "type": "LinkedDomains",
                "serviceEndpoint": "https://example.com"
            }]),
        );
    }

    // Update the document using the convenience API
    let entry = state
        .update_document(updated_doc, &signing_key)
        .await
        .expect("Failed to update document");
    println!("Updated DID, new version: {}", entry.get_version_id());
    println!(
        "Updated document:\n{}",
        serde_json::to_string_pretty(entry.get_state()).unwrap()
    );
}
