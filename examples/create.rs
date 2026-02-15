use didwebvh_rs::{
    create::{CreateDIDConfig, create_did},
    parameters::Parameters,
};
use didwebvh_rs::affinidi_secrets_resolver::secrets::Secret;
use serde_json::json;
use std::sync::Arc;

fn main() {

    // Generate or load a signing key
    let signing_key = Secret::generate_ed25519(None, None);

    // Build parameters with the signing key as an update key
    let parameters = Parameters {
        update_keys: Some(Arc::new(vec![
            signing_key.get_public_keymultibase().unwrap(),
        ])),
        portable: Some(true),
        ..Default::default()
    };

    // Build the DID document
    // "{DID}" can be used a placehoder that will be replaced by the builder with the final value
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

    let result = create_did(config).unwrap();

    // result.did        — the resolved DID identifier (with SCID)
    // result.log_entry  — the signed first log entry (serialize to JSON for did.jsonl)
    // result.witness_proofs — witness proofs (empty if no witnesses configured)
    println!("DID: {}", result.did);
    println!("Log Entry: {}", serde_json::to_string_pretty(&result.log_entry).unwrap());
}