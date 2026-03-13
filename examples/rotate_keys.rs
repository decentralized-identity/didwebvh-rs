//! Example: Create a DID and then rotate its update keys using `rotate_keys()`.

use didwebvh_rs::affinidi_secrets_resolver::secrets::Secret;
use didwebvh_rs::prelude::*;
use serde_json::json;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Generate the initial signing key
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

    // Generate a new key for rotation
    let mut new_key = Secret::generate_ed25519(None, None);
    let new_pk = new_key.get_public_keymultibase().unwrap();
    new_key.id = format!("did:key:{new_pk}#{new_pk}");

    // Rotate keys using the convenience API
    let entry = state
        .rotate_keys(vec![Multibase::new(new_pk.clone())], &signing_key)
        .await
        .expect("Failed to rotate keys");
    println!("Rotated keys, new version: {}", entry.get_version_id());
    println!("New update key: {new_pk}");
}
