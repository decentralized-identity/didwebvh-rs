//! `did:key` helpers for tests, examples and the interactive CLI.
//!
//! Replaces the previous dependency on `affinidi_tdk::dids::DID::generate_did_key`
//! with a direct call against `affinidi-did-common` + `affinidi-secrets-resolver`.
//! Dropping tdk as a runtime dep (it was pulled in solely for this one helper)
//! removes messaging-SDK / meeting-place transitive deps from consumers of the
//! `cli` feature.

use affinidi_did_common::{DID, KeyMaterialFormat};
use affinidi_secrets_resolver::secrets::{KeyType, Secret};

use crate::DIDWebVHError;

/// Generate a fresh `did:key` identifier and return `(did, secret)`.
///
/// The returned `Secret.id` is set to the full DID URL (`did:key:{mb}#{mb}`)
/// so the secret can be used directly as a signer for log entries and
/// witness proofs.
pub fn generate_did_key(key_type: KeyType) -> Result<(String, Secret), DIDWebVHError> {
    let (did, key_material) = DID::generate_key(key_type)
        .map_err(|e| DIDWebVHError::DIDError(format!("did:key generation failed: {e}")))?;

    let jwk = match &key_material.format {
        KeyMaterialFormat::JWK(jwk) => jwk,
        _ => {
            return Err(DIDWebVHError::DIDError(
                "did-common returned non-JWK key material; cannot build Secret".to_string(),
            ));
        }
    };

    let mut secret = Secret::from_jwk(jwk)
        .map_err(|e| DIDWebVHError::DIDError(format!("JWK -> Secret conversion failed: {e}")))?;
    secret.id = key_material.id.clone();
    Ok((did.to_string(), secret))
}
