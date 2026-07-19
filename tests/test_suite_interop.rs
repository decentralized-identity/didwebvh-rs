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

/// Resolves a scenario expecting failure, returning the error string.
///
/// Used for fixtures whose committed `resolutionResult.json` this
/// implementation deliberately does not reproduce — see `witness_update`.
async fn run_expect_error(scenario: &str) -> String {
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

    let mut state = DIDWebVHState::default();
    match state
        .resolve_log_owned(&did, &jsonl, witness.as_deref())
        .await
    {
        Ok((_, meta)) => panic!(
            "{scenario}: expected resolution to fail, but it resolved to {}",
            meta.version_id
        ),
        Err(e) => format!("{e:?}"),
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

/// Deliberate divergence from the committed fixture — this asserts a security
/// property, not a parity failure.
///
/// The `witness-update` vector's entry 2 lowers its own witness config from
/// `{threshold: 2, witnesses: [A, B]}` to `{threshold: 1, witnesses: [A]}` and
/// supplies a single proof (from A). Its `resolutionResult.json` expects
/// version 2 to resolve, which means the reference generator evaluated entry 2
/// against the *new* config it declares.
///
/// This resolver evaluates it against the previously-active config
/// (threshold 2) and rejects it, per didwebvh 1.0:
///
/// - "the resolver MUST confirm that the `did-witness.json` file contains
///   verified witness Data Integrity proofs from a threshold of the **then
///   active** witnesses"
/// - "rotating the keys authorized to update a DID or changing the witnesses
///   for a DID take effect only *after* the entry in which they are defined
///   has been published"
///
/// Accepting the fixture's reading would make witnessing bypassable: an
/// attacker holding a compromised update key could publish an entry setting
/// `{threshold: 1, witnesses: [attacker]}`, sign the single required proof
/// themselves, and have it accepted — defeating the entire purpose of the
/// witness mechanism. The whole point of witnesses is to bound the damage
/// from exactly that compromise.
///
/// This test therefore pins the rejection. If it starts failing because the
/// entry now resolves, that is a genuine security regression, not a fixture
/// drift. The previous `#[ignore]` on this test also misdiagnosed the cause
/// ("witness proof signature on entry 2 fails verification") — the signature
/// is fine; the threshold is not met.
///
/// Tracked upstream: the vector and the spec's normative text disagree, and
/// the discrepancy should be raised against didwebvh-test-suite.
#[tokio::test]
async fn witness_update_rejects_self_lowered_threshold() {
    let err = run_expect_error("witness-update").await;
    assert!(
        err.contains("threshold") && err.contains("not met"),
        "expected a witness-threshold rejection, got: {err}"
    );
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
