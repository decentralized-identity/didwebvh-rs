//! Example: Create a new DID using `create_did()`.
//!
//! Demonstrates the high-level programmatic API for DID creation with
//! `{DID}` placeholders, `also_known_as` aliases, and portability.
//!
//! Run with: `cargo run --example create`

use didwebvh_rs::affinidi_secrets_resolver::secrets::Secret;
use didwebvh_rs::prelude::*;
use serde_json::json;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Generate a signing key with the required did:key ID format
    let signing_key = Secret::generate_ed25519(None, None);

    // Build parameters — update_keys controls who can modify the DID
    let parameters = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(
            signing_key.get_public_keymultibase().unwrap(),
        )])),
        portable: Some(true),
        ..Default::default()
    };

    // Build the DID document — use "{DID}" as a placeholder for the final DID identifier.
    // It will be replaced with the actual DID (including SCID) during creation.
    let did_document = json!({
        "id": "{DID}",
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": "{DID}#key-0",
            "type": "Multikey",
            "publicKeyMultibase": signing_key.get_public_keymultibase().unwrap(),
            "controller": "{DID}"
        }],
        "authentication": ["{DID}#key-0"],
        "assertionMethod": ["{DID}#key-0"],
    });

    // Create the DID
    let config = CreateDIDConfig::builder()
        .address("https://example.com:8080/a/path")
        .authorization_key(signing_key)
        .did_document(did_document)
        .parameters(parameters)
        .also_known_as_web(true)
        .also_known_as_scid(true)
        .build()
        .unwrap();

    let result = create_did(config).await.unwrap();

    // result.did()        — the resolved DID identifier (with SCID)
    // result.log_entry()  — the signed first log entry (serialize to JSON for did.jsonl)
    // result.witness_proofs() — witness proofs (empty if no witnesses configured)
    println!("DID: {}", result.did());
    println!(
        "Log Entry: {}",
        serde_json::to_string_pretty(result.log_entry()).unwrap()
    );
}
