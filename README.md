# did:webvh implementation

[![Crates.io](https://img.shields.io/crates/v/didwebvh-rs.svg)](https://crates.io/crates/didwebvh-rs)
[![Documentation](https://docs.rs/didwebvh-rs/badge.svg)](https://docs.rs/didwebvh-rs)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/decentralized-identity/didwebvh-rs)

A complete implementation of the [did:webvh](https://identity.foundation/didwebvh/v1.0/)
method in Rust. Supports version 1.0 spec.

A helpful implementation site is the [webvh DID Method Information](https://didwebvh.info/)
site

## [Change log](CHANGELOG.md)

## Features

- [x] Create a did:webvh LogEntry and DID Document
- [x] Resolve a did:webvh method
- [x] Validate webvh LogEntries to v1.0 specification
- [x] Update webvh DID
- [x] Revoke webvh DID
- [x] Witness webvh DID
- [x] Migration of DID (portability)
- [x] Validate witness information
- [x] DID Query Parameters versionId and versionTime implemented
- [x] WebVH DID specification version support (v1.0 and pre-v1.0)
- [x] Export WebVH to a did:web document
- [x] Generate did:scid:vh alsoKnownAs alias from did:webvh DIDs
- [x] WASM friendly for inclusion in other projects
- [x] WebVH DID Create routines to make it easier to create DIDs programmatically

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
didwebvh-rs = "0.2.0"
```

Then:

```rust
use didwebvh_rs::prelude::*;

let mut webvh = DIDWebVHState::default();

// Load LogEntries from a file
webvh.load_log_entries_from_file("did.jsonl")?;
```

The `prelude` module re-exports the most commonly needed types:
`DIDWebVHError`, `DIDWebVHState`, `LogEntryMethods`, `Parameters`,
`CreateDIDConfig`, `create_did`, `Witnesses`, and `WitnessProofCollection`.

## Feature Flags

- **ssi**
  - Enables integration with the [ssi](https://crates.io/crates/ssi) crate
    - This is useful when integrating into universal resolvers

## Everyone likes a wizard

Getting started with webvh at first can be daunting given the complexity of the
specification and supporting infrastructure such as witness and watcher nodes.

To help with getting started, a wizard for webvh has been created to help you.

To run this wizard, you need to have [Rust](https://www.rust-lang.org/)
installed on your machine.

```Bash
cargo run --example wizard -- --help
```

> **_WARNING:_** _This wizard will generate secrets locally on your machine, and
> display the secret on the screen._
>
> **The wizard is meant for demonstration purposes only. Use in a production
> environment is not recommended.**

### Default Wizard Files

`did.jsonl` is the default WebVH LogEntry file that the wizard will create.

`did-witness.json` where Witness Proofs are saved.

`did.jsonl-secrets` is the default file containing key secrets

## Is WebVH performant?

There is a lot going on with the WebVH DID method. A lot of keys, signing and
validations

Depending on how often you are creating LogEntries, number of witnesses etc can
have a big impact on performance.

To help with testing different usage scenario's, there is an example tool that can
help you with testing real-world performance of the WebVH method.

To get options for the `generate_history` performance tool, run:

```Bash
cargo run --release --example generate_history -- --help
```

For example, to generate 200 LogEntries with 10 witnesses each, you can run:

```Bash
cargo run --release --example generate_history -- -c 200 -w 10
```

This tool will save the output to

- did.jsonl (LogEntries)
- did-witness.json (Witness Proofs)

### Criterion Benchmarks (stable Rust)

Run the full benchmark suite using [Criterion](https://crates.io/crates/criterion):

```Bash
cargo bench --bench did_benchmarks
```

Run a specific benchmark group or individual benchmark:

```Bash
cargo bench --bench did_benchmarks -- "did_creation"
cargo bench --bench did_benchmarks -- "did_creation/basic"
```

HTML reports are generated in `target/criterion/`.

### Nightly Benchmarks

If you have the Rust nightly toolchain installed, you can also run the built-in
`#[bench]` benchmarks:

```Bash
cargo +nightly bench --bench did_benchmarks_nightly
```

### Benchmark Groups

| Group | Benchmarks | Description |
|-------|-----------|-------------|
| `did_creation` | `basic`, `with_aliases` | DID creation with minimal config and with alsoKnownAs aliases |
| `did_resolution` | `single_entry`, `large_with_witnesses_120_entries` | File-based DID resolution with 1 and 120+ log entries |
| `validation` | `single_entry`, `large_with_witnesses_120_entries` | Log entry and witness proof validation |

## Creating a DID Programmatically

The `create` module provides a library API for creating a DID without any
interactive prompts. Use `CreateDIDConfig::builder()` to construct the
configuration:

```rust
use didwebvh_rs::prelude::*;
use didwebvh_rs::affinidi_secrets_resolver::secrets::Secret;
use serde_json::json;
use std::sync::Arc;

// Generate or load a signing key
let signing_key = Secret::generate_ed25519(None, None);

// Build parameters with the signing key as an update key
let parameters = Parameters {
    update_keys: Some(Arc::new(vec![
        signing_key.get_public_keymultibase().unwrap(),
    ])),
    portable: Some(true),
    ..Default::default()
};

// Build the DID document
let did_document = json!({
    "id": "did:webvh:{SCID}:example.com",
    "@context": ["https://www.w3.org/ns/did/v1"],
    "verificationMethod": [{
        "id": "did:webvh:{SCID}:example.com#key-0",
        "type": "Multikey",
        "publicKeyMultibase": signing_key.get_public_keymultibase().unwrap(),
        "controller": "did:webvh:{SCID}:example.com"
    }],
    "authentication": ["did:webvh:{SCID}:example.com#key-0"],
    "assertionMethod": ["did:webvh:{SCID}:example.com#key-0"],
});

// Create the DID
let config = CreateDIDConfig::builder()
    .address("https://example.com/")
    .authorization_key(signing_key)
    .did_document(did_document)
    .parameters(parameters)
    .also_known_as_web(true)
    .also_known_as_scid(true)
    .build()
    .unwrap();

let result = create_did(config).unwrap();

// result.did        — the resolved DID identifier (with SCID)
// result.log_entry  — the signed first log entry (serialize to JSON for did.jsonl)
// result.witness_proofs — witness proofs (empty if no witnesses configured)
```

### Witness Support

If your DID uses witnesses, provide the witness secrets via the builder:

```rust
// For each witness, add its DID and secret
let config = CreateDIDConfig::builder()
    .address("https://example.com/")
    .authorization_key(signing_key)
    .did_document(did_document)
    .parameters(parameters)
    .witness_secret("z6Mkw...", witness_key)
    .build()
    .unwrap();
```

The `sign_witness_proofs()` function is also available separately if you need
to sign witness proofs outside of the full DID creation flow.

## License

Licensed under:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
