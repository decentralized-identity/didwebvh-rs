//! Demonstrates implementing a custom [`Signer`] for use with `didwebvh-rs`.
//!
//! In production you might delegate to an HSM, KMS, or remote signing service.
//! This example shows the trait contract using a simple in-memory ed25519 key.

use affinidi_data_integrity::DataIntegrityError;
use didwebvh_rs::prelude::*;
use serde_json::json;
use std::sync::Arc;

/// A minimal custom signer backed by an in-memory ed25519 key.
///
/// Replace the inner `Secret` with your own signing backend
/// (e.g. AWS KMS, HashiCorp Vault, PKCS#11 HSM).
struct MyKmsSigner {
    inner: Secret,
}

impl MyKmsSigner {
    fn new() -> Self {
        Self {
            inner: Secret::generate_ed25519(None, None),
        }
    }

    fn public_key_multibase(&self) -> String {
        self.inner.get_public_keymultibase().unwrap()
    }
}

#[async_trait]
impl Signer for MyKmsSigner {
    fn key_type(&self) -> KeyType {
        self.inner.key_type()
    }

    fn verification_method(&self) -> &str {
        self.inner.verification_method()
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DataIntegrityError> {
        // In a real KMS, this would make an async API call
        self.inner.sign(data).await
    }
}

#[tokio::main]
async fn main() {
    let signer = MyKmsSigner::new();
    let pub_mb = signer.public_key_multibase();

    let parameters = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(&pub_mb)])),
        portable: Some(true),
        ..Default::default()
    };

    let did_document = json!({
        "id": "{DID}",
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": "{DID}#key-0",
            "type": "Multikey",
            "publicKeyMultibase": pub_mb,
            "controller": "{DID}"
        }],
        "authentication": ["{DID}#key-0"],
        "assertionMethod": ["{DID}#key-0"],
    });

    // Use builder_generic() to pass a custom Signer implementation
    let config: CreateDIDConfig<MyKmsSigner, Secret> = CreateDIDConfig::builder_generic()
        .address("https://example.com:8080/custom-signer")
        .authorization_key(signer)
        .did_document(did_document)
        .parameters(parameters)
        .build()
        .unwrap();

    let result = create_did(config).await.unwrap();

    println!("DID created with custom signer: {}", result.did());
    println!(
        "Log Entry: {}",
        serde_json::to_string_pretty(result.log_entry()).unwrap()
    );
}
