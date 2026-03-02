/// Tests loading the output of a complex WebVH DID generated using `generate_history`
use didwebvh_rs::{DIDWebVHState, log_entry::LogEntryMethods};

const BASE_DID: &str = "did:webvh:QmSnw6YkSm2Tu8pASb6VdxuSU2PetvSoLumFfVh5VafiKT:test.affinidi.com";
const LOG_FILE: &str = "tests/test_vectors/did-generate_history.jsonl";
const WITNESS_FILE: &str = "tests/test_vectors/did-witness-generate_history.json";

#[test]
fn load_generate_history() {
    let mut webvh = DIDWebVHState::default();
    webvh
        .load_log_entries_from_file(LOG_FILE)
        .expect("Failed to load log entries from file");
    webvh.load_witness_proofs_from_file(WITNESS_FILE);

    assert!(webvh.validate().is_ok());
}

#[tokio::test]
async fn get_specific_version_number() {
    let mut webvh = DIDWebVHState::default();
    let did = format!("{BASE_DID}?versionNumber=20");
    let (log_entry, _) = webvh
        .resolve_file(&did, LOG_FILE, Some(WITNESS_FILE))
        .await
        .expect("Couldn't resolve DID");

    assert_eq!(
        log_entry.get_version_id(),
        "20-QmXxgJRibisqnyXNEeAHLrW3qmu5vhmH5QgSttMgvDmwvp"
    );
}

#[tokio::test]
async fn get_specific_version_id() {
    let mut webvh = DIDWebVHState::default();
    let did = format!(
        "{BASE_DID}?versionId=3-QmSYiwKZbc7zwABzVrwJjHrXAS71Tf7evX6KM9EGrGnY26"
    );
    let (log_entry, _) = webvh
        .resolve_file(&did, LOG_FILE, Some(WITNESS_FILE))
        .await
        .expect("Couldn't resolve DID");

    assert_eq!(
        log_entry.get_version_id(),
        "3-QmSYiwKZbc7zwABzVrwJjHrXAS71Tf7evX6KM9EGrGnY26"
    );
}

#[tokio::test]
async fn get_specific_version_time() {
    let mut webvh = DIDWebVHState::default();
    // versionTime=2026-03-01T17:59:55Z matches entry 2 exactly
    let did = format!("{BASE_DID}?versionTime=2026-03-01T17:59:55Z");
    let (log_entry, _) = webvh
        .resolve_file(&did, LOG_FILE, Some(WITNESS_FILE))
        .await
        .expect("Couldn't resolve DID");

    assert_eq!(
        log_entry.get_version_id(),
        "2-Qmc5Uf8gyrERWnB46iFstQdrwuK9ALsfaxV79ra1Q6ZLgd"
    );
}

#[tokio::test]
async fn resolve_latest_no_query_params() {
    let mut webvh = DIDWebVHState::default();
    let (log_entry, _) = webvh
        .resolve_file(BASE_DID, LOG_FILE, Some(WITNESS_FILE))
        .await
        .expect("Couldn't resolve DID");

    assert_eq!(
        log_entry.get_version_id(),
        "120-QmVc27Q3M3o1xxPJbo5xcTjeEVeAqQuMAMskFXNQvQftfi"
    );
}
