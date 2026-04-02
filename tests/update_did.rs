/*!
 * Tests for the programmatic update_did() API.
 *
 * These tests create a DID via DIDWebVHState::create_log_entry,
 * then exercise the update API for various operations.
 */

use didwebvh_rs::{
    DIDWebVHState, Multibase,
    affinidi_secrets_resolver::secrets::Secret,
    parameters::Parameters,
    update::{UpdateDIDConfig, update_did},
    witness::Witnesses,
};
use serde_json::json;
use std::sync::Arc;

fn generate_signing_key() -> Secret {
    let mut key = Secret::generate_ed25519(None, None);
    let pk = key.get_public_keymultibase().unwrap();
    key.id = format!("did:key:{pk}#{pk}");
    key
}

/// Helper: create a DID and return the state ready for update tests.
async fn create_test_did(portable: bool) -> (DIDWebVHState, Secret, String) {
    let key = generate_signing_key();
    let pk = key.get_public_keymultibase().unwrap();

    let doc = json!({
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

    let mut params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
        ..Default::default()
    };
    if portable {
        params.portable = Some(true);
    }

    let mut state = DIDWebVHState::default();
    let entry = state
        .create_log_entry(None, &doc, &params, &key)
        .await
        .unwrap();

    let did = entry
        .get_state()
        .get("id")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    (state, key, did)
}

// ─────────── Builder tests ───────────

#[test]
fn update_config_builder_missing_state_errors() {
    let key = generate_signing_key();
    let result = UpdateDIDConfig::builder().signing_key(key).build();
    assert!(result.is_err());
}

#[test]
fn update_config_builder_missing_signing_key_errors() {
    let state = DIDWebVHState::default();
    let result = UpdateDIDConfig::<Secret, Secret>::builder()
        .state(state)
        .build();
    assert!(result.is_err());
}

#[test]
fn update_config_builder_empty_state_errors() {
    let key = generate_signing_key();
    let state = DIDWebVHState::default();
    let result = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .build();
    assert!(result.is_err());
}

// ─────────── Integration tests ───────────

#[tokio::test]
async fn update_document() {
    let (state, key, did) = create_test_did(false).await;

    let mut new_doc = state.log_entries().last().unwrap().get_state().clone();
    new_doc.as_object_mut().unwrap().insert(
        "service".to_string(),
        json!([{
            "id": format!("{did}#svc"),
            "type": "TestService",
            "serviceEndpoint": "https://example.com/svc"
        }]),
    );

    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .document(new_doc)
        .build()
        .unwrap();

    let result = update_did(config).await.unwrap();
    assert_eq!(result.did(), did);
    assert_eq!(result.state().log_entries().len(), 2);

    let log_json = serde_json::to_string(result.log_entry()).unwrap();
    assert!(log_json.contains("TestService"));
}

#[tokio::test]
async fn rotate_keys() {
    let (state, key, _) = create_test_did(false).await;

    let new_key = generate_signing_key();
    let new_pk = new_key.get_public_keymultibase().unwrap();

    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .update_keys(vec![Multibase::new(new_pk)])
        .build()
        .unwrap();

    let result = update_did(config).await.unwrap();
    assert_eq!(result.state().log_entries().len(), 2);
}

#[tokio::test]
async fn update_ttl() {
    let (state, key, _) = create_test_did(false).await;

    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .ttl(7200)
        .build()
        .unwrap();

    let result = update_did(config).await.unwrap();
    assert_eq!(result.state().log_entries().len(), 2);
}

#[tokio::test]
async fn deactivate_did() {
    let (state, key, did) = create_test_did(false).await;

    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .deactivate(true)
        .build()
        .unwrap();

    let result = update_did(config).await.unwrap();
    assert_eq!(result.did(), did);
    assert_eq!(result.state().log_entries().len(), 2);
}

#[tokio::test]
async fn migrate_requires_portable() {
    let (state, key, _) = create_test_did(false).await;

    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .migrate_to("https://new.example.com/")
        .build()
        .unwrap();

    let result = update_did(config).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn migrate_portable_did() {
    let (state, key, old_did) = create_test_did(true).await;

    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .migrate_to("https://new.example.com/")
        .build()
        .unwrap();

    let result = update_did(config).await.unwrap();

    assert!(result.did().contains("new.example.com"));
    assert!(!result.did().contains("{SCID}"));

    // Old DID should be in alsoKnownAs
    let log_json = serde_json::to_string(result.log_entry()).unwrap();
    assert!(log_json.contains(&old_did));
    assert_eq!(result.state().log_entries().len(), 2);
}

#[tokio::test]
async fn update_witnesses() {
    let (state, key, _) = create_test_did(false).await;

    let witnesses = Witnesses::builder()
        .threshold(1)
        .witness(Multibase::new("did:key:z6Mk_fake_witness"))
        .build()
        .unwrap();

    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .witness(witnesses)
        .build()
        .unwrap();

    let result = update_did(config).await.unwrap();
    assert_eq!(result.state().log_entries().len(), 2);
}

#[tokio::test]
async fn multiple_sequential_updates() {
    let (state, key, _) = create_test_did(false).await;

    // First update: add TTL
    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key.clone())
        .ttl(3600)
        .build()
        .unwrap();
    let result = update_did(config).await.unwrap();
    assert_eq!(result.state().log_entries().len(), 2);

    // Second update: change TTL
    let config = UpdateDIDConfig::builder()
        .state(result.into_state())
        .signing_key(key.clone())
        .ttl(7200)
        .build()
        .unwrap();
    let result = update_did(config).await.unwrap();
    assert_eq!(result.state().log_entries().len(), 3);

    // Third update: deactivate
    let config = UpdateDIDConfig::builder()
        .state(result.into_state())
        .signing_key(key)
        .deactivate(true)
        .build()
        .unwrap();
    let result = update_did(config).await.unwrap();
    assert_eq!(result.state().log_entries().len(), 4);
}
