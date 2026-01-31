# did:webvh implementation

[![Crates.io](https://img.shields.io/crates/v/didwebvh-rs.svg)](https://crates.io/crates/didwebvh-rs)
[![Documentation](https://docs.rs/didwebvh-rs/badge.svg)](https://docs.rs/didwebvh-rs)
[![Rust](https://img.shields.io/badge/rust-1.88.0%2B-blue.svg?maxAge=3600)](https://github.com/decentralized-identity/didwebvh-rs)

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

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
didwebvh-rs = "0.1.16"
```

Then:

```rust
use didwebvh_rs::DIDWebVHState;

let mut webvh = DIDWebVHState::default();

// Load LogEntries from a file
webvh.load_log_entries_from_file("did.jsonl")?;
```

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
cargo run --release --example generate_histroy -- -c 200 -w 10
```

This tool will save the output to

- did.jsonl (LogEntries)
- did-witness.json (Witness Proofs)

## License

Licensed under:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
