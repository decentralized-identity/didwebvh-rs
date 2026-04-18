//! Demonstrates implementing a custom [`Signer`] for use with `didwebvh-rs`.
//!
//! In production you might delegate to an HSM, KMS, or remote signing service.
//! This example shows the trait contract using a simple in-memory Ed25519 key.
//!
//! The `Signer` trait is suite-agnostic — `key_type()` can return any variant
//! supported by the inner signing backend, including PQC variants under the
//! `experimental-pqc` feature. This example picks Ed25519 for concision;
//! swap the inner backend for a KMS/HSM and return whatever suite it offers.

#[path = "common/suite.rs"]
mod suite;

use affinidi_data_integrity::DataIntegrityError;
use clap::Parser;
use didwebvh_rs::{did_key::generate_did_key, prelude::*};
use serde_json::json;
use std::sync::Arc;
use suite::Suite;

#[derive(Parser, Debug)]
#[command(about = "Create a DID with a custom Signer wrapping the chosen suite.")]
struct Args {
    #[arg(short = 'k', long, value_enum, default_value_t = Suite::default())]
    key_type: Suite,
}

/// A minimal custom signer backed by an in-memory Secret.
///
/// Replace the inner `Secret` with your own signing backend
/// (e.g. AWS KMS, HashiCorp Vault, PKCS#11 HSM). The signer stays
/// suite-agnostic — it just delegates through to whatever key it wraps.
struct MyKmsSigner {
    inner: Secret,
}

impl MyKmsSigner {
    fn new(suite: Suite) -> Self {
        let (_did, inner) =
            generate_did_key(suite.key_type()).expect("did:key generation for chosen suite");
        Self { inner }
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
    let args = Args::parse();
    let signer = MyKmsSigner::new(args.key_type);
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
