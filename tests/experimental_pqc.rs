//! End-to-end tests for the `experimental-pqc` feature.
//!
//! These tests compile-gated on `experimental-pqc` so the stable default
//! build remains unaffected. They exercise the full PQC path that the
//! examples demonstrate:
//!
//! - [`roundtrip_ml_dsa_44_did`] — create a DID signed with ML-DSA-44,
//!   rotate its update keys once, validate end-to-end. Exercises:
//!   `did_key::generate_did_key` + `DataIntegrityProof::sign` +
//!   `proof.verify_with_public_key` on a PQC cryptosuite.
//! - [`witness_pqc_suite_requires_runtime_opt_in`] — proves that a
//!   witness proof signed with `MlDsa44Jcs2024` is rejected by the
//!   spec-strict default `WitnessVerifyOptions` (the spec mandates
//!   `eddsa-jcs-2022` for witnesses) and accepted when the caller
//!   explicitly widens `extra_allowed_suites`.
//!
//! Not gated on any runtime environment — all cryptographic primitives
//! are in-process. Failure here is a clear regression of the PQC surface.

#![cfg(feature = "experimental-pqc")]

use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
use affinidi_secrets_resolver::secrets::Secret;
use didwebvh_rs::{
    DIDWebVHState, Multibase,
    did_key::generate_did_key,
    parameters::Parameters,
    prelude::KeyType,
    update::{UpdateDIDConfig, update_did},
    witness::WitnessVerifyOptions,
};
use serde_json::json;

/// Creates a minimal signed genesis log entry using an ML-DSA-44 update key,
/// rotates it to a second ML-DSA-44 key, and asserts the whole 2-entry log
/// validates cleanly without any `extra_allowed_suites` runtime override.
///
/// The test covers the entire "create + rotate + validate" path for PQC:
/// key generation via `generate_did_key(KeyType::MlDsa44)`, signing via
/// `DataIntegrityProof::sign` with the default `SignOptions` (which picks
/// the suite from the signer's key type), and verification inside
/// `DIDWebVHState::validate_with`.
#[tokio::test]
async fn roundtrip_ml_dsa_44_did() {
    let (_did1, k1) = generate_did_key(KeyType::MlDsa44).expect("generate K1");
    let pk1 = k1.get_public_keymultibase().unwrap();

    let doc = json!({
        "id": "did:webvh:{SCID}:example.com",
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": "did:webvh:{SCID}:example.com#key-0",
            "type": "Multikey",
            "publicKeyMultibase": pk1,
            "controller": "did:webvh:{SCID}:example.com"
        }],
        "authentication": ["did:webvh:{SCID}:example.com#key-0"],
        "assertionMethod": ["did:webvh:{SCID}:example.com#key-0"],
    });

    let params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(&pk1)])),
        ..Default::default()
    };

    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(None, &doc, &params, &k1)
        .await
        .expect("create genesis entry");

    // Rotate K1 -> K2 (second ML-DSA-44 key), signed by K1 per the
    // no-pre-rotation spec rule.
    let (_did2, k2) = generate_did_key(KeyType::MlDsa44).expect("generate K2");
    let pk2 = k2.get_public_keymultibase().unwrap();
    let cfg = UpdateDIDConfig::<_, Secret>::builder()
        .state(state)
        .signing_key(k1)
        .update_keys(vec![Multibase::new(&pk2)])
        .build()
        .unwrap();
    let mut state = update_did(cfg).await.expect("rotate to K2").into_state();
    assert_eq!(state.log_entries().len(), 2);

    // Fresh-load path: reset validation status and re-run validate().
    for entry in state.log_entries_mut() {
        entry.validation_status =
            didwebvh_rs::log_entry_state::LogEntryValidationStatus::NotValidated;
    }

    let report = state
        .validate()
        .expect("ML-DSA-44 log must validate end-to-end");
    assert!(
        report.truncated.is_none(),
        "unexpected truncation: {:?}",
        report.truncated
    );
    assert_eq!(state.log_entries().len(), 2);
    assert!(state.validated());
}

/// A witness proof signed with an ML-DSA cryptosuite must be rejected by
/// the spec-strict default `WitnessVerifyOptions`, and accepted once the
/// caller explicitly adds `MlDsa44Jcs2024` to `extra_allowed_suites`.
///
/// Exercises the runtime escape hatch advertised in the "Experimental PQC
/// support" README section — proves it is not dead code.
#[tokio::test]
async fn witness_pqc_suite_requires_runtime_opt_in() {
    // A witness attests to a versionId. The signing document is just
    // {"versionId": "<...>"} per didwebvh 1.0 §"The Witness Proofs File".
    let version_id = "1-QmExampleVersionIdForTest";
    let doc = json!({ "versionId": version_id });

    // Sign the witness proof with an ML-DSA-44 signer + the matching
    // cryptosuite. Default SignOptions picks the suite from the signer's
    // key type, which is MlDsa44 -> MlDsa44Jcs2024.
    let (_did, witness_key) = generate_did_key(KeyType::MlDsa44).expect("generate PQC witness key");
    let proof = DataIntegrityProof::sign(&doc, &witness_key, SignOptions::new())
        .await
        .expect("sign PQC witness proof");
    assert_eq!(proof.cryptosuite, CryptoSuite::MlDsa44Jcs2024);

    // Strict verification rejects the non-`eddsa-jcs-2022` suite even
    // though the underlying signature is cryptographically valid.
    let strict = WitnessVerifyOptions::new();
    let err = strict
        .check_proof_shape(&proof)
        .expect_err("strict defaults must reject ML-DSA witness proofs");
    assert!(
        err.to_string().contains("eddsa-jcs-2022"),
        "error message should explain the spec rule; got: {err}"
    );

    // Runtime opt-in: widen the accepted set, same proof, now passes.
    let lenient = WitnessVerifyOptions::new().with_extra_allowed_suite(CryptoSuite::MlDsa44Jcs2024);
    lenient
        .check_proof_shape(&proof)
        .expect("extra_allowed_suites must admit MlDsa44Jcs2024");
}
