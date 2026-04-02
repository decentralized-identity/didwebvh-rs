//! Example: Create a DID and then rotate its authorization keys using `update_did()`.

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

    // Generate a new key for rotation
    let mut new_key = Secret::generate_ed25519(None, None);
    let new_pk = new_key.get_public_keymultibase().unwrap();
    new_key.id = format!("did:key:{new_pk}#{new_pk}");

    // Rotate keys using update_did()
    let update_config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(signing_key)
        .update_keys(vec![Multibase::new(new_pk.clone())])
        .build()
        .expect("Failed to build update config");

    let result = update_did(update_config)
        .await
        .expect("Failed to rotate keys");

    println!(
        "Rotated keys, version: {}",
        result.state().log_entries().len()
    );
    println!("New authorization key: {new_pk}");
}
