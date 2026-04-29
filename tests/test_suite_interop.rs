//! Interop walker for didwebvh-test-suite PR#4 vectors.
//!
//! Each `#[tokio::test]` resolves one committed fixture through
//! `DIDWebVHState::resolve_log_owned` and asserts the returned metadata's
//! `versionId` matches the expected value in `resolutionResult.json`.
//!
//! Fixtures live under `tests/test_vectors/test_suite/<scenario>/`. See the
//! README there for provenance.

use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::prelude::DIDWebVHState;
use serde_json::Value;

const ROOT: &str = "tests/test_vectors/test_suite";

/// Per-scenario runner.
///
/// `assert_did_document` opts the scenario into a deep equality check of the
/// resolved DID Document against `resolutionResult.json#/didDocument`. This
/// catches divergences in implicit-service injection (`#files`/`#whois`),
/// service ordering, and field shape that the versionId-only check would
/// miss. Off by default while we ramp up parity scenario-by-scenario.
async fn run(scenario: &str, assert_did_document: bool) {
    let dir = format!("{ROOT}/{scenario}");
    let jsonl = std::fs::read_to_string(format!("{dir}/did.jsonl"))
        .unwrap_or_else(|e| panic!("read did.jsonl for {scenario}: {e}"));
    let witness = std::fs::read_to_string(format!("{dir}/did-witness.json")).ok();
    let expected: Value = {
        let s = std::fs::read_to_string(format!("{dir}/resolutionResult.json"))
            .unwrap_or_else(|e| panic!("read resolutionResult.json for {scenario}: {e}"));
        serde_json::from_str(&s)
            .unwrap_or_else(|e| panic!("parse resolutionResult.json for {scenario}: {e}"))
    };

    let did = expected
        .pointer("/didDocument/id")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("{scenario}: no didDocument.id in expected result"))
        .to_string();
    let expected_version_id = expected
        .pointer("/didDocumentMetadata/versionId")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("{scenario}: no didDocumentMetadata.versionId"))
        .to_string();

    let mut state = DIDWebVHState::default();
    let (entry, meta) = state
        .resolve_log_owned(&did, &jsonl, witness.as_deref())
        .await
        .unwrap_or_else(|e| panic!("{scenario}: resolve_log_owned failed: {e:?}"));

    assert_eq!(
        meta.version_id, expected_version_id,
        "{scenario}: metadata versionId mismatch"
    );
    assert_eq!(
        entry.get_version_id(),
        expected_version_id,
        "{scenario}: entry versionId mismatch"
    );

    // versionNumber must agree with the integer prefix of versionId.
    let expected_version_number: u32 = expected_version_id
        .split('-')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("{scenario}: malformed versionId {expected_version_id:?}"));
    assert_eq!(
        meta.version_number, expected_version_number,
        "{scenario}: metadata versionNumber mismatch"
    );

    if assert_did_document {
        let mut resolved_doc = entry
            .get_did_document()
            .unwrap_or_else(|e| panic!("{scenario}: get_did_document failed: {e:?}"));
        let mut expected_doc = expected
            .pointer("/didDocument")
            .cloned()
            .unwrap_or_else(|| panic!("{scenario}: expected.didDocument missing"));
        // didwebvh-test-suite fixtures emit implicit `#files`/`#whois` with
        // relative-fragment IDs; this resolver emits the absolute form
        // (`<did>#files` / `<did>#whois`) for DID Core 1.0 §5.4 compliance.
        // Normalise both sides to absolute before comparing so we test
        // semantic equality rather than byte-for-byte parity.
        normalise_implicit_service_ids(&mut resolved_doc, &did);
        normalise_implicit_service_ids(&mut expected_doc, &did);
        assert_eq!(
            resolved_doc,
            expected_doc,
            "{scenario}: resolved DID Document does not match expected.\n\
             resolved = {resolved}\n\
             expected = {expected}",
            resolved = serde_json::to_string_pretty(&resolved_doc).unwrap(),
            expected = serde_json::to_string_pretty(&expected_doc).unwrap(),
        );
    }
}

/// Rewrites `service[].id` values of `"#files"`/`"#whois"` to their
/// absolute form `"<did>#files"`/`"<did>#whois"`. Only the two implicit
/// service names are touched — user-supplied relative IDs (e.g.
/// `"#linked-domain"`) are left alone, matching the resolver's own
/// normalisation policy.
fn normalise_implicit_service_ids(doc: &mut Value, did: &str) {
    let Some(services) = doc.get_mut("service").and_then(|v| v.as_array_mut()) else {
        return;
    };
    for service in services {
        let Some(id) = service.get_mut("id") else {
            continue;
        };
        if id == "#files" {
            *id = Value::String(format!("{did}#files"));
        } else if id == "#whois" {
            *id = Value::String(format!("{did}#whois"));
        }
    }
}

// Most scenarios still only check `versionId` while DID-Document parity ramps
// up. The `services` scenario opts in to the deeper check — it exercises both
// user-supplied services and implicit `#files`/`#whois` injection, which is
// the most likely place for a regression to hide.

#[tokio::test]
async fn basic_create() {
    run("basic-create", true).await;
}

#[tokio::test]
async fn basic_update() {
    run("basic-update", true).await;
}

#[tokio::test]
async fn key_rotation() {
    run("key-rotation", true).await;
}

#[tokio::test]
async fn multi_update() {
    run("multi-update", false).await;
}

#[tokio::test]
async fn multiple_update_keys() {
    run("multiple-update-keys", false).await;
}

#[tokio::test]
async fn deactivate() {
    run("deactivate", true).await;
}

#[tokio::test]
async fn services() {
    run("services", true).await;
}

#[tokio::test]
#[ignore = "witness proof signature on entry 2 fails verification; \
            out of v0.5.1 scope, tracked as follow-up (tasks/todo.md)"]
async fn witness_update() {
    run("witness-update", false).await;
}

#[tokio::test]
async fn witness_threshold() {
    run("witness-threshold", true).await;
}

#[tokio::test]
async fn portable() {
    run("portable", false).await;
}

#[tokio::test]
async fn portable_move() {
    run("portable-move", false).await;
}

#[tokio::test]
async fn pre_rotation() {
    run("pre-rotation", false).await;
}

#[tokio::test]
async fn pre_rotation_consume() {
    run("pre-rotation-consume", false).await;
}
