// Test that a non portable DID is being handled correctly.

use didwebvh_rs::{DIDWebVHError, DIDWebVHState};

#[tokio::test]
pub async fn test_invalid_ported_did() {
    let mut webvh = DIDWebVHState::default();

    webvh
        .load_log_entries_from_file("tests/test_vectors/invalid-ported.jsonl")
        .expect("Failed to load log entries from file");

    let err = webvh.validate().expect_err("expected validation to fail");

    assert!(matches!(
        err,
        DIDWebVHError::ValidationError(ref msg)
            if msg.contains("The DID is not portable")
    ));
}
