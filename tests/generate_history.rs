/// Tests loading the output of a complex WebVH DID generated using `generate_history`
use didwebvh_rs::{DIDWebVHState, log_entry::LogEntryMethods};

#[test]
fn load_generate_history() {
    let mut webvh = DIDWebVHState::default();
    webvh
        .load_log_entries_from_file("tests/test_vectors/did-generate_history.jsonl")
        .expect("Failed to load log entries from file");
    webvh.load_witness_proofs_from_file("tests/test_vectors/did-witness-generate_history.json");

    assert!(webvh.validate().is_ok());
}

#[tokio::test]
async fn get_specific_version_number() {
    let mut webvh = DIDWebVHState::default();
    let (log_entry, _) = webvh.resolve_file("did:webvh:QmSnw6YkSm2Tu8pASb6VdxuSU2PetvSoLumFfVh5VafiKT:test.affinidi.com?versionNumber=20", "tests/test_vectors/did-generate_history.jsonl", Some("tests/test_vectors/did-witness-generate_history.json")).await.expect("Couldn't resolve DID");

    assert_eq!(
        log_entry.get_version_id(),
        "20-QmXxgJRibisqnyXNEeAHLrW3qmu5vhmH5QgSttMgvDmwvp"
    );
}
