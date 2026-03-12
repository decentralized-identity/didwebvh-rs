/*!
*   Shared test utilities for the didwebvh-rs crate.
*
*   Provides common helpers used across multiple test modules to avoid
*   code duplication. All items are `pub(crate)` and only compiled in test builds.
*/

use affinidi_data_integrity::{DataIntegrityProof, crypto_suites::CryptoSuite};
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::parameters::Parameters;

/// A well-known ed25519 multibase public key used as a default in parameter tests.
///
/// This avoids repeating the same 49-character string across dozens of test sites.
#[cfg(test)]
pub const TEST_UPDATE_KEY: &str = "z6Mkp7QveNebyWs4z1kJ7Aa7CymUjRpjPYnBYh6Cr1t6JoXY";

/// Generates a fresh Ed25519 signing key with a `did:key` URI.
///
/// The key ID is set to `did:key:{pk}#{pk}` where `pk` is the public key
/// in multibase format. This matches the format expected by the log entry
/// signing and verification logic.
pub fn generate_signing_key() -> Secret {
    let mut key = Secret::generate_ed25519(None, None);
    let pk = key.get_public_keymultibase().unwrap();
    key.id = format!("did:key:{pk}#{pk}");
    key
}

/// Builds a minimal but valid DID document for testing purposes.
///
/// The document includes a single `Multikey` verification method derived from the
/// provided signing key, along with `authentication` and `assertionMethod` references.
/// This is the smallest document that satisfies the WebVH validation requirements.
pub fn did_doc_with_key(did: &str, key: &Secret) -> Value {
    let pk = key.get_public_keymultibase().unwrap();
    json!({
        "id": did,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{did}#key-0"),
            "type": "Multikey",
            "publicKeyMultibase": pk,
            "controller": did
        }],
        "authentication": [format!("{did}#key-0")],
        "assertionMethod": [format!("{did}#key-0")],
    })
}

/// Generates a signing key and matching [`Parameters`] with `update_keys` set.
///
/// Returns a tuple of `(Secret, Parameters)` ready for use in DID creation tests.
pub fn key_and_params() -> (Secret, Parameters) {
    let key = generate_signing_key();
    let params = Parameters {
        update_keys: Some(Arc::new(vec![key.get_public_keymultibase().unwrap()])),
        ..Default::default()
    };
    (key, params)
}

/// Creates a minimal `DataIntegrityProof` for use in tests.
///
/// The `vm` parameter sets the `verification_method` field, which is the
/// key used to track which witness produced the proof. All other fields
/// are populated with placeholder values sufficient for unit testing.
pub fn make_test_proof(vm: &str) -> DataIntegrityProof {
    DataIntegrityProof {
        type_: "test".to_string(),
        created: None,
        context: None,
        cryptosuite: CryptoSuite::EddsaJcs2022,
        proof_purpose: "test".to_string(),
        proof_value: None,
        verification_method: vm.to_string(),
    }
}
