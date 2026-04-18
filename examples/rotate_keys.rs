//! Example: Create a DID and then rotate its authorization keys using `update_did()`.
//!
//! Demonstrates replacing the DID's authorization keys so that future
//! updates must be signed with the new key.
//!
//! Run with: `cargo run --example rotate_keys`
//! Try PQC: `cargo run --example rotate_keys --features experimental-pqc -- --key-type ml-dsa-44`

#[path = "common/suite.rs"]
mod suite;

use clap::Parser;
use didwebvh_rs::{did_key::generate_did_key, prelude::*};
use serde_json::json;
use std::sync::Arc;

use suite::Suite;

#[derive(Parser, Debug)]
#[command(about = "Create a DID and rotate its authorization keys via update_did().")]
struct Args {
    /// Cryptographic suite used for BOTH the initial key and the rotated
    /// replacement. Rotation across suites (e.g. Ed25519 -> ML-DSA) works
    /// too at the API level — this flag just keeps the demo readable.
    #[arg(short = 'k', long, value_enum, default_value_t = Suite::default())]
    key_type: Suite,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let kt = args.key_type.key_type();

    // Generate the initial signing key
    let (_did, signing_key) = generate_did_key(kt).unwrap();
    let pk = signing_key.get_public_keymultibase().unwrap();

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

    // Generate a new key for rotation (same suite as the initial key).
    let (_new_did, new_key) = generate_did_key(kt).unwrap();
    let new_pk = new_key.get_public_keymultibase().unwrap();

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
