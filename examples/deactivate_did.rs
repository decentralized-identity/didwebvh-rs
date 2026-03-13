//! Example: Create a DID and then deactivate it using `deactivate()`.

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

    // Deactivate using the convenience API
    let entry = state
        .deactivate(&signing_key)
        .await
        .expect("Failed to deactivate DID");
    println!("Deactivated DID, version: {}", entry.get_version_id());
    println!("DID is now permanently deactivated.");
}
