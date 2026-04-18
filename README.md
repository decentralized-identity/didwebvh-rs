# did:webvh implementation

[![Crates.io](https://img.shields.io/crates/v/didwebvh-rs.svg)](https://crates.io/crates/didwebvh-rs)
[![Documentation](https://docs.rs/didwebvh-rs/badge.svg)](https://docs.rs/didwebvh-rs)
[![Rust](https://img.shields.io/badge/rust-1.94.0%2B-blue.svg?maxAge=3600)](https://github.com/decentralized-identity/didwebvh-rs)

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
- [x] DID Query Parameters versionId, versionTime, and versionNumber implemented
- [x] WebVH DID specification version support (v1.0 and pre-v1.0)
- [x] Export WebVH to a did:web document
- [x] Generate did:scid:vh alsoKnownAs alias from did:webvh DIDs
- [x] URL validation rejects IP addresses per spec (domain names required)
- [x] WASM friendly for inclusion in other projects (resolution only — `cli` feature excluded)
- [x] WebVH DID Create routines to make it easier to create DIDs programmatically
- [x] Embeddable interactive CLI flows for 3rd-party applications (`cli` feature)
- [x] Pluggable signing via the `Signer` trait — use HSMs, KMS, or any external
  signing service without exposing secret key material to the library
- [x] Structured error types for programmatic error handling (e.g. `NetworkError`
  exposes `url`, `status_code`, and `message` fields)
- [x] Convenience API: `update_document()`, `rotate_keys()`, `deactivate()` on `DIDWebVHState`
- [x] `WitnessesBuilder` for ergonomic witness configuration
- [x] Cache serialization: `save_state()` / `load_state()` for offline caching
- [x] `async_trait` re-exported so `Signer` implementors don't need a separate dependency
- [x] Feature flags: `network` (default), `rustls`, `native-tls` for TLS backend selection
- [x] In-memory log verification via `resolve_log()` — verify DID documents without filesystem or network access

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
didwebvh-rs = "0.5.0"
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
`ValidationReport`, `TruncationReason`, `CreateDIDConfig`, `create_did`,
`UpdateDIDConfig`, `update_did`, `Witnesses`, `WitnessProofCollection`,
`Signer`, `KeyType`, `Secret`, `async_trait`, and the `generate_did_key`
helper.

> **Version skew note (0.5.0):** third-party types (`Signer`, `KeyType`,
> `Secret`, `async_trait`) and the whole-crate re-export of
> `affinidi_secrets_resolver` are no longer exposed at the crate root.
> Reach for them via `prelude::*` or depend on the source crates in your
> own Cargo.toml. This shields your build from version skew introduced
> by whatever didwebvh-rs happens to pin.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `network` | **yes** | Enables HTTP(S) resolution via `reqwest`. Disable with `default-features = false` for local-only validation. |
| `ssi` | no | Enables integration with the [ssi](https://crates.io/crates/ssi) crate (implies `network`). |
| `rustls` | no | Use `rustls` TLS backend (implies `network`). |
| `native-tls` | no | Use platform-native TLS backend (implies `network`). |
| `cli` | no | Interactive CLI flows for DID creation and updates. Adds `dialoguer` and `console`. Not included in WASM builds. |
| `experimental-pqc` | no | **Experimental, off-spec.** Unlocks PQC cryptosuites (ML-DSA-{44,65,87}, SLH-DSA-SHA2-128s). Enable only for interop testing with other PQC-aware implementations — didwebvh 1.0 does not yet standardise these suites. See README "Experimental PQC support" below. |

To use the library without network support (e.g. for local file validation only):

```toml
[dependencies]
didwebvh-rs = { version = "0.3.0", default-features = false }
```

## Convenience API

`DIDWebVHState` provides high-level methods for common DID lifecycle operations:

```rust
// Update the DID document
state.update_document(new_doc, &signing_key).await?;

// Rotate update keys
state.rotate_keys(vec![new_key], &signing_key).await?;

// Deactivate the DID
state.deactivate(&signing_key).await?;
```

See the `examples/update_did.rs`, `examples/rotate_keys.rs`, and
`examples/deactivate_did.rs` examples for full usage.

## Updating a DID Programmatically

The `update` module provides [`update_did()`] for programmatic DID updates,
complementing `create_did()`. It handles document changes, key rotation,
parameter updates, domain migration, deactivation, and witness signing:

```rust
use didwebvh_rs::prelude::*;

// Update the DID document
let result = update_did(
    UpdateDIDConfig::builder()
        .state(webvh_state)
        .signing_key(key)
        .document(new_doc)
        .build()?
).await?;

// Rotate authorization keys
let result = update_did(
    UpdateDIDConfig::builder()
        .state(webvh_state)
        .signing_key(current_key)
        .update_keys(vec![new_key_multibase])
        .build()?
).await?;

// Migrate to a new domain (requires portable=true)
let result = update_did(
    UpdateDIDConfig::builder()
        .state(webvh_state)
        .signing_key(key)
        .migrate_to("https://new-domain.example.com/")
        .build()?
).await?;

// Deactivate permanently
let result = update_did(
    UpdateDIDConfig::builder()
        .state(webvh_state)
        .signing_key(key)
        .deactivate(true)
        .build()?
).await?;

// Access results
result.log_entry().save_to_file("did.jsonl")?;
result.state().witness_proofs().save_to_file("did-witness.json")?;
```

Multiple changes can be combined in a single update (e.g. document + TTL + watchers).
For deactivation with active pre-rotation, the function automatically creates an
intermediate log entry to disable pre-rotation first.

## Examples

The `examples/` directory contains runnable demonstrations of the library's API:

| Example | Command | Description |
|---------|---------|-------------|
| `create` | `cargo run --example create` | Create a new DID with `create_did()`, `{DID}` placeholders, and aliases |
| `update_did` | `cargo run --example update_did` | Update a DID document (add a service endpoint) using `update_did()` |
| `rotate_keys` | `cargo run --example rotate_keys` | Rotate authorization keys using `update_did()` |
| `deactivate_did` | `cargo run --example deactivate_did` | Permanently deactivate a DID using `update_did()` |
| `custom_signer` | `cargo run --example custom_signer` | Implement the `Signer` trait for HSM/KMS integration |
| `resolve` | `cargo run --example resolve -- <DID>` | Resolve a did:webvh DID over HTTP(S) and display the document |
| `wizard` | `cargo run --example wizard --features cli` | Interactive CLI wizard for DID creation, updates, and resolution |
| `generate_history` | `cargo run --release --example generate_history -- -c 200` | Generate large DID histories for performance testing |
| `generate_large_did` | `cargo run --release --example generate_large_did` | Generate a 1 MB+ DID file for benchmarking |

## WitnessesBuilder

Build witness configurations ergonomically:

```rust
use didwebvh_rs::prelude::*;

let witnesses = Witnesses::builder()
    .threshold(2)
    .witness(Multibase::new("z6Mk..."))
    .witness(Multibase::new("z6Mk..."))
    .build()?;
```

## Cache Serialization

Save and load `DIDWebVHState` for offline caching:

```rust
// Save state to disk
state.save_state("cache.json")?;

// Load state from disk (re-validate before use)
let state = DIDWebVHState::load_state("cache.json")?;
```

**Important:** Loaded state should be re-validated because computed fields
(`active_update_keys`, `active_witness`) use `#[serde(skip)]` and will be
at their defaults after deserialization.

## Embedding Interactive CLI Flows in Your Application

The `cli` feature provides interactive terminal flows that 3rd-party applications
can embed directly in their own CLIs. These give your users the same guided
DID creation and management experience as the built-in wizard.

```toml
[dependencies]
didwebvh-rs = { version = "0.4.1", features = ["cli"] }
```

### Interactive DID Creation

Run the full interactive DID creation flow, or pre-configure parts of it:

```rust
use didwebvh_rs::prelude::*;
use serde_json::json;

// Fully interactive — prompts for everything
let result = interactive_create_did(InteractiveCreateConfig::default()).await?;

// Or pre-configure services and address, prompt for the rest
let config = InteractiveCreateConfig::builder()
    .address("https://example.com/")
    .service(json!({
        "id": "{DID}#messaging",
        "type": "DIDCommMessaging",
        "serviceEndpoint": "https://example.com/didcomm"
    }))
    .portable(true)
    .also_known_as_web(true)
    .build();
let result = interactive_create_did(config).await?;

// Access results
println!("Created DID: {}", result.did());
result.log_entry().save_to_file("did.jsonl")?;
result.witness_proofs().save_to_file("did-witness.json")?;
```

Use `{DID}` as a placeholder in pre-configured services and verification method IDs —
it is automatically replaced with the actual DID identifier (including SCID) during creation.

### Interactive DID Updates

Update an existing DID with the same guided flow. Supports three operations:
modifying the document/parameters, migrating to a new domain, or revoking the DID.

```rust
use didwebvh_rs::prelude::*;

// Fully interactive — loads state from files, prompts for operation
let result = interactive_update_did(InteractiveUpdateConfig::default()).await?;

// Or pre-load state and choose the operation
let config = InteractiveUpdateConfig::builder()
    .state(webvh_state)
    .secrets(update_secrets)
    .operation(UpdateOperation::Modify)
    .build();
let result = interactive_update_did(config).await?;

// Save updated state
result.log_entry().save_to_file("did.jsonl")?;
result.state().witness_proofs().save_to_file("did-witness.json")?;
```

> **Note:** The `cli` feature is intentionally excluded from WASM builds.
> WASM targets should use the core library API (`create_did`, `resolve`, etc.) directly.

## Everyone likes a wizard

Getting started with webvh at first can be daunting given the complexity of the
specification and supporting infrastructure such as witness and watcher nodes.

To help with getting started, a wizard for webvh has been created to help you.

To run this wizard, you need to have [Rust](https://www.rust-lang.org/)
installed on your machine.

```Bash
cargo run --example wizard --features cli
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

| Group            | Benchmarks                                         | Description                                                   |
| ---------------- | -------------------------------------------------- | ------------------------------------------------------------- |
| `did_creation`   | `basic`, `with_aliases`                            | DID creation with minimal config and with alsoKnownAs aliases |
| `did_resolution` | `single_entry`, `large_with_witnesses_120_entries` | File-based DID resolution with 1 and 120+ log entries         |
| `validation`     | `single_entry`, `large_with_witnesses_120_entries` | Log entry and witness proof validation                        |

## Creating a DID Programmatically

The `create` module provides a library API for creating a DID without any
interactive prompts. Use `CreateDIDConfig::builder()` to construct the
configuration:

```rust
use didwebvh_rs::prelude::*;
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

### Bring Your Own Signer (HSM / KMS)

The library does not require you to hold secret key material in memory. All
signing operations go through the `Signer` trait, so you can delegate to an
HSM, cloud KMS, or any other external signing service. The built-in `Secret`
type implements `Signer` for local Ed25519 keys, but you can replace it with
your own implementation:

```rust
use didwebvh_rs::prelude::*; // async_trait is re-exported here

struct MyKmsSigner { /* your KMS client, key ID, etc. */ }

#[async_trait]
impl Signer for MyKmsSigner {
    fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }

    fn verification_method(&self) -> &str {
        // Must be "did:key:{multibase}#{multibase}" format
        "did:key:z6Mk...#z6Mk..."
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, affinidi_data_integrity::DataIntegrityError> {
        // Call your KMS / HSM here — no private key bytes needed locally
        todo!()
    }
}
```

Then use your custom signer with `CreateDIDConfig::builder_generic()`:

```rust
let kms_signer = MyKmsSigner { /* ... */ };

let config = CreateDIDConfig::builder_generic()
    .address("https://example.com/")
    .authorization_key(kms_signer)
    .did_document(did_document)
    .parameters(parameters)
    .build()
    .unwrap();

let result = create_did(config).await.unwrap();
```

The same applies to witness signing — `sign_witness_proofs()` accepts any
`HashMap<String, W>` where `W: Signer`.

### Witness Support

If your DID uses witnesses, provide the witness signers via the builder:

```rust
// For each witness, add its DID and signer
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

## Experimental PQC support

The `experimental-pqc` Cargo feature unlocks post-quantum cryptosuites
(ML-DSA-{44,65,87}, SLH-DSA-SHA2-128s) for DID log entries and witness
proofs. These suites are **not yet part of the didwebvh 1.0 spec** —
enable only for interop testing with other PQC-aware implementations.

```toml
[dependencies]
didwebvh-rs = { version = "0.5.0", features = ["experimental-pqc"] }
```

Key generation, signing, and verification flow through the same
`generate_did_key` / `DataIntegrityProof::sign` / `proof.verify(...)` API
as the classical suites — just pass a PQC `KeyType`:

```rust
use didwebvh_rs::{did_key::generate_did_key, prelude::KeyType};

// Creates did:key:z6ML... with a 32-byte ML-DSA-44 private-key seed.
let (did, key) = generate_did_key(KeyType::MlDsa44)?;
```

### Try it from the examples

Every example under `examples/` takes a `--key-type` flag that maps onto
the `Suite` enum (defined in `examples/common/suite.rs`). Classical
suites are always available; PQC variants appear only when the feature
is on:

```bash
# Create a DID with an ML-DSA-44 update key
cargo run --features experimental-pqc --example create -- --key-type ml-dsa-44

# Rotate keys across two ML-DSA-44 generations
cargo run --features experimental-pqc --example rotate_keys -- --key-type ml-dsa-44

# Benchmark a 120-entry history signed with ML-DSA-44
cargo run --release --features experimental-pqc --example generate_history -- \
    --key-type ml-dsa-44 -c 120

# SLH-DSA-128s (hash-based, no JWK)
cargo run --features experimental-pqc --example create -- --key-type slh-dsa-128
```

The interactive wizard (`--features cli,experimental-pqc`) adds ML-DSA
and SLH-DSA entries to the key-type menu, clearly labelled
*(experimental)*.

### Runtime opt-in for PQC witness proofs (independent of the feature)

The didwebvh 1.0 spec (§"The Witness Proofs File") says witness
cryptosuite MUST be `eddsa-jcs-2022`. `WitnessVerifyOptions` widens the
accepted set at runtime so a resolver can accept PQC-signed witness
proofs without rebuilding the crate:

```rust
use didwebvh_rs::prelude::*;
use didwebvh_rs::witness::WitnessVerifyOptions;
use affinidi_data_integrity::crypto_suites::CryptoSuite;

let options = WitnessVerifyOptions::new()
    .with_extra_allowed_suite(CryptoSuite::MlDsa44Jcs2024);

state.validate_with(&options)?.assert_complete()?;
```

Accepting non-spec witness suites is deliberate spec-deviation; it's an
escape hatch for testing, not a production recommendation. Strict
`state.validate()?` keeps the `eddsa-jcs-2022`-only default.

## License

Licensed under:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
