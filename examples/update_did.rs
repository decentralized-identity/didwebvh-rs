//! Example: Create a DID and then update its document using `update_did()`.
//!
//! Demonstrates adding a service endpoint to an existing DID document
//! using the high-level programmatic update API.
//!
//! Run with: `cargo run --example update_did`

use affinidi_secrets_resolver::secrets::Secret;
use didwebvh_rs::prelude::*;
use serde_json::json;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Generate a signing key with the required did:key ID format
    let mut signing_key = Secret::generate_ed25519(None, None);
    let pk = signing_key.get_public_keymultibase().unwrap();
    signing_key.id = format!("did:key:{pk}#{pk}");

    // Create the DID using the high-level API
    let create_config = CreateDIDConfig::builder()
        .address("https://example.com/")
        .authorization_key(signing_key.clone())
        .did_document(json!({
            "id": "{DID}",
            "@context": ["https://www.w3.org/ns/did/v1"],
            "verificationMethod": [{
                "id": "{DID}#key-0",
                "type": "Multikey",
                "publicKeyMultibase": pk,
                "controller": "{DID}"
            }],
            "authentication": ["{DID}#key-0"],
            "assertionMethod": ["{DID}#key-0"],
        }))
        .parameters(Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(pk.clone())])),
            ..Default::default()
        })
        .build()
        .expect("Failed to build create config");

    let create_result = create_did(create_config)
        .await
        .expect("Failed to create DID");
    println!("Created DID: {}", create_result.did());

    // Build a new document with a service endpoint added
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(
            None,
            create_result.log_entry().get_state(),
            &Parameters {
                update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
                ..Default::default()
            },
            &signing_key,
        )
        .await
        .expect("Failed to rebuild state");

    let mut updated_doc = state.log_entries().last().unwrap().get_state().clone();
    let did_id = create_result.did().to_string();
    updated_doc.as_object_mut().unwrap().insert(
        "service".to_string(),
        json!([{
            "id": format!("{did_id}#service-1"),
            "type": "LinkedDomains",
            "serviceEndpoint": "https://example.com"
        }]),
    );

    // Update the DID using the high-level API
    let update_config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(signing_key)
        .document(updated_doc)
        .build()
        .expect("Failed to build update config");

    let update_result = update_did(update_config)
        .await
        .expect("Failed to update DID");

    println!("Updated DID: {}", update_result.did());
    println!("New version: {}", update_result.state().log_entries().len());
    println!(
        "Updated document:\n{}",
        serde_json::to_string_pretty(
            update_result
                .state()
                .log_entries()
                .last()
                .unwrap()
                .get_state()
        )
        .unwrap()
    );
}
