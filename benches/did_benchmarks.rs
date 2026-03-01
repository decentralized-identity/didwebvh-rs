use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use didwebvh_rs::{
    DIDWebVHState,
    create::{CreateDIDConfig, create_did},
    parameters::Parameters,
};
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::runtime::Runtime;

fn did_document_template() -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:webvh:{SCID}:example.com",
        "authentication": ["did:webvh:{SCID}:example.com#key-0"],
        "assertionMethod": ["did:webvh:{SCID}:example.com#key-0"],
        "verificationMethod": [{
            "id": "did:webvh:{SCID}:example.com#key-0",
            "type": "Multikey",
            "controller": "did:webvh:{SCID}:example.com",
            "publicKeyMultibase": "{DID_KEY}"
        }]
    })
}

fn setup_basic_creation() -> CreateDIDConfig {
    let key = Secret::generate_ed25519(None, None);
    let pub_mb = key.get_public_keymultibase().unwrap();

    let mut doc = did_document_template();
    // Replace the placeholder key with the actual public key
    if let Some(vm) = doc["verificationMethod"].as_array_mut() {
        if let Some(entry) = vm.first_mut() {
            entry["publicKeyMultibase"] = Value::String(pub_mb.clone());
        }
    }

    let parameters = Parameters {
        update_keys: Some(Arc::new(vec![pub_mb])),
        portable: Some(true),
        ..Default::default()
    };

    CreateDIDConfig::builder()
        .address("https://example.com/")
        .authorization_key(key)
        .did_document(doc)
        .parameters(parameters)
        .build()
        .expect("Failed to build CreateDIDConfig")
}

fn setup_creation_with_aliases() -> CreateDIDConfig {
    let key = Secret::generate_ed25519(None, None);
    let pub_mb = key.get_public_keymultibase().unwrap();

    let mut doc = did_document_template();
    if let Some(vm) = doc["verificationMethod"].as_array_mut() {
        if let Some(entry) = vm.first_mut() {
            entry["publicKeyMultibase"] = Value::String(pub_mb.clone());
        }
    }

    let parameters = Parameters {
        update_keys: Some(Arc::new(vec![pub_mb])),
        portable: Some(true),
        ..Default::default()
    };

    CreateDIDConfig::builder()
        .address("https://example.com/")
        .authorization_key(key)
        .did_document(doc)
        .parameters(parameters)
        .also_known_as_web(true)
        .also_known_as_scid(true)
        .build()
        .expect("Failed to build CreateDIDConfig")
}

fn bench_did_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("did_creation");

    group.bench_function("basic", |b| {
        b.iter_batched(
            setup_basic_creation,
            |config| create_did(config).unwrap(),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("with_aliases", |b| {
        b.iter_batched(
            setup_creation_with_aliases,
            |config| create_did(config).unwrap(),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_did_resolution(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("did_resolution");

    group.bench_function("single_entry", |b| {
        b.iter_batched(
            DIDWebVHState::default,
            |mut state| {
                rt.block_on(async move {
                    let _ = state.resolve_file(
                        "did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000",
                        "tests/test_vectors/first_log_entry_verify_full.jsonl",
                        None,
                    ).await.unwrap();
                });
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("large_with_witnesses_120_entries", |b| {
        b.iter_batched(
            DIDWebVHState::default,
            |mut state| {
                rt.block_on(async move {
                    let _ = state.resolve_file(
                        "did:webvh:QmSnw6YkSm2Tu8pASb6VdxuSU2PetvSoLumFfVh5VafiKT:test.affinidi.com",
                        "tests/test_vectors/did-generate_history.jsonl",
                        Some("tests/test_vectors/did-witness-generate_history.json"),
                    ).await.unwrap();
                });
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("validation");

    group.bench_function("single_entry", |b| {
        b.iter_batched(
            || {
                let mut state = DIDWebVHState::default();
                state
                    .load_log_entries_from_file(
                        "tests/test_vectors/first_log_entry_verify_full.jsonl",
                    )
                    .unwrap();
                state
            },
            |mut state| state.validate().unwrap(),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("large_with_witnesses_120_entries", |b| {
        b.iter_batched(
            || {
                let mut state = DIDWebVHState::default();
                state
                    .load_log_entries_from_file(
                        "tests/test_vectors/did-generate_history.jsonl",
                    )
                    .unwrap();
                state.load_witness_proofs_from_file(
                    "tests/test_vectors/did-witness-generate_history.json",
                );
                state
            },
            |mut state| state.validate().unwrap(),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_did_creation, bench_did_resolution, bench_validation);
criterion_main!(benches);
