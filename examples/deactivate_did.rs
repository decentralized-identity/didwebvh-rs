//! Example: Create a DID and then permanently deactivate it using `update_did()`.
//!
//! Demonstrates irreversible DID deactivation. After deactivation, the DID
//! can no longer be updated or used for authentication or credential issuance.
//!
//! Run with: `cargo run --example deactivate_did`

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

    // Create the DID
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
            update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
            ..Default::default()
        })
        .build()
        .expect("Failed to build create config");

    let create_result = create_did(create_config)
        .await
        .expect("Failed to create DID");
    println!("Created DID: {}", create_result.did());

    // Rebuild state from the created log entry
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(
            None,
            create_result.log_entry().get_state(),
            &Parameters {
                update_keys: Some(Arc::new(vec![Multibase::new(
                    signing_key.get_public_keymultibase().unwrap(),
                )])),
                ..Default::default()
            },
            &signing_key,
        )
        .await
        .expect("Failed to rebuild state");

    // Deactivate using update_did()
    let update_config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(signing_key)
        .deactivate(true)
        .build()
        .expect("Failed to build update config");

    let result = update_did(update_config)
        .await
        .expect("Failed to deactivate DID");

    println!("Deactivated DID: {}", result.did());
    println!("DID is now permanently deactivated.");
    println!("Total log entries: {}", result.state().log_entries().len());
}
