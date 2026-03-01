// Test that a revoked DID is being handled correctly.
//
// Generates a DID programmatically, creates a few update entries, then
// deactivates it. Saves to a temp file and resolves from file to verify
// the resolved metadata reports `deactivated`.

use affinidi_secrets_resolver::secrets::Secret;
use chrono::{Duration, Utc};
use didwebvh_rs::{DIDWebVHState, parameters::Parameters};
use serde_json::{json, Value};
use std::sync::Arc;

/// Generate an ed25519 Secret with a proper `did:key:...#...` id
/// so that the DataIntegrityProof verification_method matches the format
/// expected by `check_signing_key_authorized`.
fn generate_signing_key() -> Secret {
    let mut key = Secret::generate_ed25519(None, None);
    let pk = key.get_public_keymultibase().unwrap();
    key.id = format!("did:key:{pk}#{pk}");
    key
}

fn did_doc_with_key(did: &str, key: &Secret) -> Value {
    let pk = key.get_public_keymultibase().unwrap();
    json!({
        "id": did,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{did}#key-0"),
            "type": "Multikey",
            "publicKeyMultibase": pk,
            "controller": did
        }],
        "authentication": [format!("{did}#key-0")],
        "assertionMethod": [format!("{did}#key-0")],
    })
}

/// Build a DID with 3 normal entries then a 4th deactivation entry,
/// each with strictly increasing versionTime. Returns the DIDWebVHState
/// and the resolved DID string.
fn build_revoked_did() -> (DIDWebVHState, String) {
    let base_time = (Utc::now() - Duration::seconds(100)).fixed_offset();

    // Entry 1: create the DID
    let key1 = generate_signing_key();
    let key2 = generate_signing_key();

    let params1 = Parameters {
        update_keys: Some(Arc::new(vec![key1.get_public_keymultibase().unwrap()])),
        next_key_hashes: Some(Arc::new(vec![
            key2.get_public_keymultibase_hash().unwrap(),
        ])),
        portable: Some(false),
        ..Default::default()
    };
    let doc = did_doc_with_key("did:webvh:{SCID}:localhost%3A8000", &key1);

    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(Some(base_time), &doc, &params1, &key1)
        .expect("Failed to create entry 1");

    // Get the actual DID (with resolved SCID)
    let actual_doc = state.log_entries.last().unwrap().get_state().clone();
    let did = actual_doc
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();

    // Entry 2: normal update (rotate keys)
    let key3 = generate_signing_key();
    let params2 = Parameters {
        update_keys: Some(Arc::new(vec![key2.get_public_keymultibase().unwrap()])),
        next_key_hashes: Some(Arc::new(vec![
            key3.get_public_keymultibase_hash().unwrap(),
        ])),
        ..Default::default()
    };
    state
        .create_log_entry(
            Some(base_time + Duration::seconds(1)),
            &actual_doc,
            &params2,
            &key2,
        )
        .expect("Failed to create entry 2");

    // Entry 3: another normal update (disable pre-rotation)
    let params3 = Parameters {
        update_keys: Some(Arc::new(vec![key3.get_public_keymultibase().unwrap()])),
        next_key_hashes: Some(Arc::new(vec![])),
        ..Default::default()
    };
    state
        .create_log_entry(
            Some(base_time + Duration::seconds(2)),
            &actual_doc,
            &params3,
            &key3,
        )
        .expect("Failed to create entry 3");

    // Entry 4: deactivation (signed with key3, the current update key)
    let params4 = Parameters {
        update_keys: Some(Arc::new(vec![])),
        deactivated: Some(true),
        ..Default::default()
    };
    state
        .create_log_entry(
            Some(base_time + Duration::seconds(3)),
            &actual_doc,
            &params4,
            &key3,
        )
        .expect("Failed to create entry 4 (deactivation)");

    (state, did)
}

/// Save log entries to a test file
fn save_to_file(state: &DIDWebVHState, path: &str) {
    for entry in &state.log_entries {
        entry
            .log_entry
            .save_to_file(path)
            .expect("Failed to save log entry");
    }
}

#[tokio::test]
async fn test_revoked_did() {
    let path = "tests/test_vectors/revoked-did-test1.jsonl";
    let (state, did) = build_revoked_did();
    save_to_file(&state, path);

    let mut resolver = DIDWebVHState::default();
    let (_, metadata) = resolver
        .resolve_file(&did, path, None)
        .await
        .expect("Couldn't resolve revoked DID");

    // Clean up
    let _ = std::fs::remove_file(path);

    assert!(metadata.deactivated);
}

#[tokio::test]
async fn test_revoked_status_earlier_version() {
    let path = "tests/test_vectors/revoked-did-test2.jsonl";
    let (state, did) = build_revoked_did();
    save_to_file(&state, path);

    // Query version 2 — even though it wasn't itself deactivated,
    // the DID-level deactivation should still be reported
    let version_2_id = state.log_entries[1].get_version_id();
    let did_with_version = format!("{did}?versionId={version_2_id}");

    let mut resolver = DIDWebVHState::default();
    let (_, metadata) = resolver
        .resolve_file(&did_with_version, path, None)
        .await
        .expect("Couldn't resolve revoked DID at earlier version");

    // Clean up
    let _ = std::fs::remove_file(path);

    assert!(metadata.deactivated);
}
