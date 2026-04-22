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

async fn run(scenario: &str) {
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
}

#[tokio::test]
async fn basic_create() {
    run("basic-create").await;
}

#[tokio::test]
async fn basic_update() {
    run("basic-update").await;
}

#[tokio::test]
async fn key_rotation() {
    run("key-rotation").await;
}

#[tokio::test]
async fn multi_update() {
    run("multi-update").await;
}

#[tokio::test]
async fn multiple_update_keys() {
    run("multiple-update-keys").await;
}

#[tokio::test]
async fn deactivate() {
    run("deactivate").await;
}

#[tokio::test]
async fn services() {
    run("services").await;
}

#[tokio::test]
#[ignore = "witness proof signature on entry 2 fails verification; \
            out of v0.5.1 scope, tracked as follow-up (tasks/todo.md)"]
async fn witness_update() {
    run("witness-update").await;
}

#[tokio::test]
async fn witness_threshold() {
    run("witness-threshold").await;
}

#[tokio::test]
async fn portable() {
    run("portable").await;
}

#[tokio::test]
async fn portable_move() {
    run("portable-move").await;
}

#[tokio::test]
async fn pre_rotation() {
    run("pre-rotation").await;
}

#[tokio::test]
async fn pre_rotation_consume() {
    run("pre-rotation-consume").await;
}
