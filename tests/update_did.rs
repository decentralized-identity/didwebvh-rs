/*!
 * Tests for the programmatic update_did() API.
 *
 * These tests create a DID via DIDWebVHState::create_log_entry,
 * then exercise the update API for various operations.
 */

use affinidi_secrets_resolver::secrets::Secret;
use didwebvh_rs::{
    DIDWebVHState, Multibase,
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

#[tokio::test]
async fn combined_document_and_parameter_update() {
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

    let new_key = generate_signing_key();
    let new_pk = new_key.get_public_keymultibase().unwrap();

    // Document + key rotation + TTL in one update
    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .document(new_doc)
        .update_keys(vec![Multibase::new(new_pk)])
        .ttl(1800)
        .build()
        .unwrap();

    let result = update_did(config).await.unwrap();
    assert_eq!(result.state().log_entries().len(), 2);
    let log_json = serde_json::to_string(result.log_entry()).unwrap();
    assert!(log_json.contains("TestService"));
}

#[tokio::test]
async fn disable_portability() {
    let (state, key, _) = create_test_did(true).await; // portable

    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .disable_portability()
        .build()
        .unwrap();

    let result = update_did(config).await.unwrap();
    assert_eq!(result.state().log_entries().len(), 2);
}

#[tokio::test]
async fn update_watchers() {
    let (state, key, _) = create_test_did(false).await;

    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .watchers(vec!["https://watcher.example.com".to_string()])
        .build()
        .unwrap();

    let result = update_did(config).await.unwrap();
    assert_eq!(result.state().log_entries().len(), 2);
}

#[tokio::test]
async fn disable_watchers() {
    let (state, key, _) = create_test_did(false).await;

    // First add watchers
    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key.clone())
        .watchers(vec!["https://watcher.example.com".to_string()])
        .build()
        .unwrap();
    let result = update_did(config).await.unwrap();

    // Then disable them with empty vec
    let config = UpdateDIDConfig::builder()
        .state(result.into_state())
        .signing_key(key)
        .watchers(vec![])
        .build()
        .unwrap();
    let result = update_did(config).await.unwrap();
    assert_eq!(result.state().log_entries().len(), 3);
}

// ─────────── Hash-chain safety: implicit services never poison `state` ───────────
//
// The implicit `#files`/`#whois` services are resolution-time only. They MUST
// NOT be folded into the LogEntry's stored `state` — that's the field that
// gets JCS-canonicalized into the entry hash and signed by the
// `eddsa-jcs-2022` proof. If a future refactor accidentally swaps in
// `get_did_document()` (which adds implicits) for `get_state()` (which
// doesn't) anywhere in the update / rotate / deactivate / migrate path, the
// stored `state` would silently start carrying implicit services and every
// downstream resolver (including didwebvh-ts) would compute a different hash
// for the next entry — breaking the chain.
//
// These tests pin the invariant directly: after every operation, scan the
// stored `state` of every log entry and assert it carries no implicit
// services that the user didn't put there.

/// Returns true if `state.service` contains a service whose `id` is the
/// relative form `#whois`/`#files` or the absolute form `<did>#whois`/`<did>#files`.
fn state_contains_implicit_services(state: &serde_json::Value, did: &str) -> bool {
    let absolute_whois = format!("{did}#whois");
    let absolute_files = format!("{did}#files");
    state
        .get("service")
        .and_then(|v| v.as_array())
        .is_some_and(|svcs| {
            svcs.iter().any(|s| {
                s.get("id").and_then(|v| v.as_str()).is_some_and(|id| {
                    id == "#whois" || id == "#files" || id == absolute_whois || id == absolute_files
                })
            })
        })
}

/// After `create_log_entry`, the stored `state` MUST be exactly the document
/// the caller passed — no `service` field if none was supplied. Conversely
/// `get_did_document()` MUST add the implicit services. This is the baseline
/// invariant the rest of these tests rely on.
#[tokio::test]
async fn create_does_not_inject_implicit_services_into_state() {
    let (state, _key, did) = create_test_did(false).await;
    let entry = state.log_entries().last().unwrap();

    // Stored state: no implicits.
    assert!(
        entry.get_state().get("service").is_none(),
        "create_log_entry must not inject `service` into stored state"
    );
    assert!(!state_contains_implicit_services(entry.get_state(), &did));

    // Resolution-time view: implicits ARE present.
    let resolved = entry.get_did_document().unwrap();
    assert!(
        state_contains_implicit_services(&resolved, &did),
        "get_did_document() must add implicit #files/#whois"
    );
}

/// `update_did` with no document override should pick up `state` from the
/// previous entry via `get_state()` (raw). After the update, the new entry's
/// stored `state` must still be implicit-free. This is the regression guard
/// for `src/update.rs:374`.
#[tokio::test]
async fn update_no_document_override_does_not_poison_state() {
    let (state, key, did) = create_test_did(false).await;

    // Update parameters only (TTL change). No document override.
    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .ttl(7200)
        .build()
        .unwrap();
    let result = update_did(config).await.unwrap();

    // Every entry must remain implicit-free.
    for (i, entry) in result.state().log_entries().iter().enumerate() {
        assert!(
            !state_contains_implicit_services(entry.get_state(), &did),
            "entry {i}: implicit services leaked into stored state",
        );
    }
}

/// `rotate_keys` reuses the previous document via the `current_document()`
/// helper (`get_state().clone()`). Pin that the rotated entry's stored state
/// stays implicit-free.
#[tokio::test]
async fn rotate_keys_does_not_poison_state() {
    let (state, key, did) = create_test_did(false).await;
    let new_key = generate_signing_key();
    let new_pk = new_key.get_public_keymultibase().unwrap();

    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .update_keys(vec![Multibase::new(new_pk)])
        .build()
        .unwrap();
    let result = update_did(config).await.unwrap();

    for (i, entry) in result.state().log_entries().iter().enumerate() {
        assert!(
            !state_contains_implicit_services(entry.get_state(), &did),
            "entry {i}: implicit services leaked into stored state after rotate",
        );
    }
}

/// `deactivate` produces a final entry whose document is taken from the
/// previous entry via `get_state().clone()`. Pin that the final entry's
/// stored state stays implicit-free.
#[tokio::test]
async fn deactivate_does_not_poison_state() {
    let (state, key, did) = create_test_did(false).await;

    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .deactivate(true)
        .build()
        .unwrap();
    let result = update_did(config).await.unwrap();

    for (i, entry) in result.state().log_entries().iter().enumerate() {
        assert!(
            !state_contains_implicit_services(entry.get_state(), &did),
            "entry {i}: implicit services leaked into stored state after deactivate",
        );
    }
}

/// `migrate` rewrites every `did:webvh:OLD` reference in the document with
/// the new DID. The source is `last_entry.get_state()` (raw) — the rewrite
/// must NOT pull in implicits along the way.
#[tokio::test]
async fn migrate_does_not_poison_state() {
    let (state, key, _old_did) = create_test_did(true).await; // portable=true

    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key)
        .migrate_to("https://newdomain.example/")
        .build()
        .unwrap();
    let result = update_did(config).await.unwrap();

    let new_did = result.did().to_string();
    for (i, entry) in result.state().log_entries().iter().enumerate() {
        assert!(
            !state_contains_implicit_services(entry.get_state(), &new_did),
            "entry {i}: implicit services leaked into stored state after migrate",
        );
    }
}

/// A multi-step sequence (update → rotate → deactivate) must NEVER poison
/// any entry's stored state. This is the end-to-end guard: even if a single
/// operation forgot to use the raw state, the chain of operations would
/// surface it here.
#[tokio::test]
async fn multi_step_sequence_does_not_poison_state() {
    let (state, key, did) = create_test_did(false).await;

    // 1. Add a TTL update (no document override).
    let config = UpdateDIDConfig::builder()
        .state(state)
        .signing_key(key.clone())
        .ttl(1800)
        .build()
        .unwrap();
    let result = update_did(config).await.unwrap();

    // 2. Rotate keys.
    let new_key = generate_signing_key();
    let new_pk = new_key.get_public_keymultibase().unwrap();
    let config = UpdateDIDConfig::builder()
        .state(result.into_state())
        .signing_key(key)
        .update_keys(vec![Multibase::new(new_pk)])
        .build()
        .unwrap();
    let result = update_did(config).await.unwrap();

    // 3. Deactivate.
    let config = UpdateDIDConfig::builder()
        .state(result.into_state())
        .signing_key(new_key)
        .deactivate(true)
        .build()
        .unwrap();
    let result = update_did(config).await.unwrap();

    assert_eq!(result.state().log_entries().len(), 4);
    for (i, entry) in result.state().log_entries().iter().enumerate() {
        assert!(
            !state_contains_implicit_services(entry.get_state(), &did),
            "entry {i}: implicit services leaked into stored state during sequence",
        );
        // Belt-and-braces: verify each entry's signed bytes are still valid
        // after the chain. If `state` had been poisoned mid-chain, the next
        // entry's previous-hash linkage would have diverged from spec.
        let prev = if i == 0 {
            None
        } else {
            Some(&result.state().log_entries()[i - 1].log_entry)
        };
        entry
            .log_entry
            .verify_log_entry(
                prev,
                prev.map(|_| &result.state().log_entries()[i - 1].validated_parameters),
            )
            .unwrap_or_else(|e| panic!("entry {i}: re-verification failed after chain: {e:?}"));
    }
}
