// Test that a revoked DID is being handled correctly.

use didwebvh_rs::DIDWebVHState;

#[tokio::test]
pub async fn test_revoked_did() {
    let mut state = DIDWebVHState::default();

    state
        .load_log_entries_from_file("tests/test_vectors/revoked-did.jsonl")
        .expect("Couldn't load Revoked DID test vector");

    let (_, metadata) = state
        .resolve_file(
            "did:webvh:QmWC6mWD7HSbkkqvyZ64mfrK4JiSMFxgCeh3awNzRdwfMr:localhost%3A8000",
            "tests/test_vectors/revoked-did.jsonl",
            None,
        )
        .await
        .expect("Couldn't resolve Revoked DID test vector");

    // Should be deactivated
    assert!(metadata.deactivated);
}

#[tokio::test]
pub async fn test_revoked_status_earlier_version() {
    let mut state = DIDWebVHState::default();

    state
        .load_log_entries_from_file("tests/test_vectors/revoked-did.jsonl")
        .expect("Couldn't load Revoked DID test vector");

    let (_, metadata) = state
        .resolve_file(
            "did:webvh:QmWC6mWD7HSbkkqvyZ64mfrK4JiSMFxgCeh3awNzRdwfMr:localhost%3A8000?versionId=2-QmcQ9JJcusHWRP9iYJdrwbj3q6YN9gGKhQmtoZk4anHw1t",
            "tests/test_vectors/revoked-did.jsonl",
            None,
        )
        .await
        .expect("Couldn't resolve Revoked DID test vector");

    // Should be deactivated
    assert!(metadata.deactivated);
}
