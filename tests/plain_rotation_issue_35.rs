//! Regression test for issue #35.
//!
//! A didwebvh 1.0 log that rotates `updateKeys` without pre-rotation
//! (no `nextKeyHashes`) must resolve. Prior to the fix, `Parameters::validate`
//! set `active_update_keys` to the *current* entry's newly-declared keys for
//! the no-pre-rotation branch, so the previous-entry key that actually signed
//! the rotation was rejected as unauthorized — and `validate()` then silently
//! truncated the log down to the genesis entry.
//!
//! This test builds the log with our own `update_did()` (which is
//! spec-compliant) and re-runs `validate()` to drive the read path that
//! contained the bug.
//!
//! A second test (`#[ignore]`) loads a fixture produced by the
//! `didwebvh-ts` reference resolver. That implementation substitutes
//! `"{SCID}"` for `versionId` when computing entryHashes for non-genesis
//! entries, contrary to the spec (§"Entry Hash Generation and Verification"
//! requires the previous entry's full `versionId`). Until that is resolved
//! upstream the cross-impl fixture cannot validate cleanly here.

use std::sync::Arc;

use didwebvh_rs::{
    DIDWebVHState, Multibase,
    affinidi_secrets_resolver::secrets::Secret,
    log_entry_state::LogEntryValidationStatus,
    parameters::Parameters,
    update::{UpdateDIDConfig, update_did},
};
use serde_json::json;

#[tokio::test]
async fn plain_rotation_chain_validates_after_fix() {
    // Build a 3-entry plain-rotation chain: K1 -> K2 -> K3, with no
    // `nextKeyHashes` anywhere. Each entry is signed by the previous
    // entry's key (the no-pre-rotation rule).

    let k1 = generate_key();
    let pk1 = k1.get_public_keymultibase().unwrap();

    let doc = json!({
        "id": "did:webvh:{SCID}:example.com",
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": "did:webvh:{SCID}:example.com#key-0",
            "type": "Multikey",
            "publicKeyMultibase": pk1,
            "controller": "did:webvh:{SCID}:example.com"
        }],
        "authentication": ["did:webvh:{SCID}:example.com#key-0"],
        "assertionMethod": ["did:webvh:{SCID}:example.com#key-0"],
    });

    let params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(&pk1)])),
        ..Default::default()
    };

    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(None, &doc, &params, &k1)
        .await
        .expect("create entry 1");

    // Entry 2: rotate K1 -> K2, signed by K1.
    let k2 = generate_key();
    let pk2 = k2.get_public_keymultibase().unwrap();
    let cfg = UpdateDIDConfig::<_, Secret>::builder()
        .state(state)
        .signing_key(k1)
        .update_keys(vec![Multibase::new(&pk2)])
        .build()
        .unwrap();
    let result = update_did(cfg).await.expect("update to K2");
    let state = result.into_state();
    assert_eq!(state.log_entries().len(), 2);

    // Entry 3: rotate K2 -> K3, signed by K2.
    let k3 = generate_key();
    let pk3 = k3.get_public_keymultibase().unwrap();
    let cfg = UpdateDIDConfig::<_, Secret>::builder()
        .state(state)
        .signing_key(k2)
        .update_keys(vec![Multibase::new(&pk3)])
        .build()
        .unwrap();
    let result = update_did(cfg).await.expect("update to K3");
    let mut state = result.into_state();
    assert_eq!(state.log_entries().len(), 3);

    // Reset validation status on every entry so validate() runs the full
    // verification path that was broken pre-fix (silent fallback).
    for entry in state.log_entries_mut() {
        entry.validation_status = LogEntryValidationStatus::NotValidated;
    }

    state
        .validate()
        .expect("plain-rotation chain must validate end-to-end");

    assert_eq!(
        state.log_entries().len(),
        3,
        "all 3 entries must survive validation; truncation indicates issue #35 \
         has regressed (no-pre-rotation auth check rejecting the previous-entry key)"
    );
    assert!(state.validated());
}

/// Cross-implementation fixture from `didwebvh-ts`.
///
/// IGNORED: didwebvh-ts substitutes the literal `"{SCID}"` for `versionId`
/// when computing entryHashes for entries N>1. Per the didwebvh 1.0 spec
/// (§"Entry Hash Generation and Verification") the predecessor must be the
/// previous entry's full `versionId`. Re-enable once the upstream behaviour
/// converges with the spec.
#[test]
#[ignore = "blocked on didwebvh-ts entryHash placeholder bug"]
fn ts_produced_plain_rotation_log_resolves() {
    let mut state = DIDWebVHState::default();
    state
        .load_log_entries_from_file("tests/test_vectors/plain_rotation_no_prerotation.jsonl")
        .expect("load fixture");
    state.validate().expect("plain-rotation log must validate");
    assert_eq!(state.log_entries().len(), 3);
}

fn generate_key() -> Secret {
    let mut key = Secret::generate_ed25519(None, None);
    let pk = key.get_public_keymultibase().unwrap();
    key.id = format!("did:key:{pk}#{pk}");
    key
}
