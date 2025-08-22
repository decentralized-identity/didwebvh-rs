/// Tests loading the output of a complex WebVH DID generated using `generate_history`
use didwebvh_rs::DIDWebVHState;

mod common;

#[test]
fn load_generate_history() {
    let mut webvh = DIDWebVHState::default();
    webvh
        .load_log_entries_from_file("tests/test_vectors/did-generate_history.jsonl")
        .expect("Failed to load log entries from file");
    webvh.load_witness_proofs_from_file("tests/test_vectors/did-witness-generate_history.json");

    assert!(webvh.validate().is_ok());
}
