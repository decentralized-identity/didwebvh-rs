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
///
/// Classical suites (Ed25519, X25519, P-256/384, secp256k1) go through
/// `affinidi_did_common::DID::generate_key` so new classical types land
/// automatically when upstream adds them. PQC suites (`ml-dsa-*`,
/// `slh-dsa-sha2-128s`) are handled in-crate because `did-common` 0.3.x
/// doesn't cover them yet; if upstream adds PQC support later, this
/// fallback can be removed.
pub fn generate_did_key(key_type: KeyType) -> Result<(String, Secret), DIDWebVHError> {
    match key_type {
        #[cfg(feature = "experimental-pqc")]
        KeyType::MlDsa44 => Ok(did_key_from_secret(Secret::generate_ml_dsa_44(None, None))),
        #[cfg(feature = "experimental-pqc")]
        KeyType::MlDsa65 => Ok(did_key_from_secret(Secret::generate_ml_dsa_65(None, None))),
        #[cfg(feature = "experimental-pqc")]
        KeyType::MlDsa87 => Ok(did_key_from_secret(Secret::generate_ml_dsa_87(None, None))),
        #[cfg(feature = "experimental-pqc")]
        KeyType::SlhDsaSha2_128s => Ok(did_key_from_secret(Secret::generate_slh_dsa_sha2_128s(
            None,
        ))),
        _ => generate_did_key_via_did_common(key_type),
    }
}

/// Classical suites (Ed25519, X25519, P-256/384, secp256k1): delegate to
/// `did-common`'s built-in generator, which handles multicodec + JWK
/// construction for us.
fn generate_did_key_via_did_common(key_type: KeyType) -> Result<(String, Secret), DIDWebVHError> {
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

/// PQC suites: `Secret::generate_*` already has the public bytes; we just
/// need to build the `did:key:{mb}` URI and set `secret.id` to the full
/// `did:key:{mb}#{mb}` verification-method URL so the `Signer` impl works
/// straight away.
#[cfg(feature = "experimental-pqc")]
fn did_key_from_secret(mut secret: Secret) -> (String, Secret) {
    let mb = secret
        .get_public_keymultibase()
        .expect("generate_* produced a Secret with decodable public bytes");
    let did = format!("did:key:{mb}");
    secret.id = format!("{did}#{mb}");
    (did, secret)
}
