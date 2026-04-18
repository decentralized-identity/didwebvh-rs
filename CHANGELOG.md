# didwebvh-rs Changelog history

## 18th April 2026

### Release 0.5.0 — breaking

#### Fixed

- **Fixed issue #35** — resolution rejected spec-compliant logs that used
  plain key rotation (no pre-rotation). The read path now authorises
  non-pre-committed log entries against the **previous** entry's
  `updateKeys`, matching `didwebvh 1.0` §"Authorized Keys" and the writer's
  pre-existing logic. Logs produced by other spec-compliant resolvers
  (e.g. the TypeScript reference resolver) that use plain rotation now
  resolve correctly.

#### Breaking

- **`DIDWebVHState::validate` returns `ValidationReport`**. Previously the
  function silently truncated the log and returned `Ok(())` on partial
  validation — the failure mode that surfaced #35. The new
  `#[must_use]` `ValidationReport` carries `ok_until: String` and
  `truncated: Option<TruncationReason>`; `ValidationReport::assert_complete()`
  is the one-call path for strict resolution.
- **Third-party types removed from top-level re-exports.**
  `didwebvh_rs::{Signer, KeyType, async_trait}` and
  `didwebvh_rs::affinidi_secrets_resolver::*` are gone; use
  `didwebvh_rs::prelude::*` or depend on the source crates directly. Avoids
  silent version skew via the crate-root convenience re-export.
- **Dropped `affinidi-tdk` as a runtime dep.** The `cli` feature no longer
  pulls in tdk (and its messaging-SDK / meeting-place transitive graph).
  Replaced the single callsite with `didwebvh_rs::did_key::generate_did_key`,
  a ~30-line wrapper over `affinidi-did-common` + `affinidi-secrets-resolver`.
- **Witness proofs now spec-strict by default.** `LogEntry::validate_witness_proof`
  and `WitnessProofCollection::validate_log_entry` take `&WitnessVerifyOptions`.
  The default options reject witness proofs that don't use `eddsa-jcs-2022`
  with `proofPurpose: assertionMethod`, matching `didwebvh 1.0` §"The
  Witness Proofs File". Use `WitnessVerifyOptions::with_extra_allowed_suite`
  for additive runtime opt-in; `DIDWebVHState::validate_with(options)` is the
  companion to `validate()` for callers that need this.
- **Deprecated `affinidi-data-integrity` APIs migrated off.** `sign_jcs_data`,
  `sign_rdfc_data*`, and `verify_data_with_public_key` replaced with the
  unified `DataIntegrityProof::sign(&doc, signer, SignOptions)` and
  `proof.verify_with_public_key(&doc, pk, VerifyOptions)` in 0.5.4.
- **MSRV bumped to 1.94.0** (required by upstream `affinidi-*` 0.5.x / 0.6.x).

#### Added

- **`didwebvh_rs::did_key::generate_did_key`** — creates a fresh
  `did:key` with a `Secret` (id set to `did:key:{mb}#{mb}`).
- **`didwebvh_rs::witness::WitnessVerifyOptions`** (`#[non_exhaustive]`)
  with `extra_allowed_suites: Vec<CryptoSuite>` for runtime cryptosuite
  opt-in.
- **`ValidationReport` + `TruncationReason`** re-exported at the crate root.
- **Regression test** for issue #35 (`tests/plain_rotation_issue_35.rs`),
  with a Node-based fixture generator committed under
  `tests/fixtures/plain-rotation/`.
- **[lints.rust] + [lints.clippy]** section in Cargo.toml with pedantic
  group enabled and a curated allowlist.
- **`experimental-pqc` Cargo feature** — forwards to
  `affinidi-data-integrity/post-quantum` +
  `affinidi-secrets-resolver/post-quantum` to unlock ML-DSA-{44,65,87}
  and SLH-DSA-SHA2-128s cryptosuites. Off-spec for didwebvh 1.0; use for
  interop testing with other PQC-aware implementations. The runtime
  `WitnessVerifyOptions::extra_allowed_suites` escape hatch stays
  available independently of the compile-time feature.

#### Chores

- **Bumped `ssi` requirement from 0.15 to 0.16** (optional feature). The
  old pin carried a transitive `libipld 0.14 → core2 ^0.4` chain whose
  sole `core2 0.4.0` version is yanked from crates.io, breaking
  `cargo update`. 0.16 dropped that chain.

#### Refactored

- `PublicKey::get_public_key_bytes` now delegates to
  `affinidi_data_integrity::did_vm::resolve_did_key`, which supports every
  multicodec registered upstream (Ed25519, secp256k1, P-256/384/521 today;
  ML-DSA / SLH-DSA when the upstream feature is enabled).

#### Known issues

- **`didwebvh-ts` interop test ignored** — the reference TypeScript
  resolver uses the literal `"{SCID}"` placeholder (not the previous
  entry's versionId) when computing entryHashes for non-genesis entries,
  contrary to the `didwebvh 1.0` spec §"Entry Hash Generation and
  Verification". The committed cross-impl fixture is behind
  `#[ignore]` pending upstream resolution.
- **`ssi` optional feature pulls known-advisory transitive crates.** The
  default build (no `ssi` feature) is advisory-clean. Enabling `ssi`
  pulls in a long transitive tree including the `did-*` adapters, which
  indirectly depend on `rsa 0.6.1` (RUSTSEC-2023-0071, Marvin Attack),
  `rustls-webpki 0.101.7` (RUSTSEC-2026-0098 + RUSTSEC-2026-0099, name
  constraint bugs), and four unmaintained crates (`derivative`,
  `proc-macro-error`, `rustls-pemfile`, `serde_cbor`). CI's `cargo audit`
  step explicitly ignores these with a reason comment; resolve by
  upgrading `ssi` when upstream drops the affected dep chains.

#### Migration notes

```rust
// Before (0.4.x)
use didwebvh_rs::{Signer, KeyType};
use didwebvh_rs::affinidi_secrets_resolver::secrets::Secret;
state.validate()?;

// After (0.5.0)
use didwebvh_rs::prelude::*;   // gets Signer, KeyType, Secret, ValidationReport, ...
state.validate()?.assert_complete()?;   // strict mode (recommended for resolvers)
// or
let report = state.validate()?;
if let Some(reason) = report.truncated { /* handle partial validation */ }
```

## 15th April 2026

### Release 0.4.2

#### Removed

- **Removed `multihash` dependency** — The `multihash` crate (and its transitive
  `core2` dependency) has been replaced with an inline SHA-256 multihash encoder.
  The `core2` crate has been yanked from crates.io, making `multihash 0.19`
  uninstallable for new users. The library only used multihash for a simple
  2-byte prefix encoding, so this is now handled directly without any external
  dependency. No public API changes.

#### Security

- **Updated `aws-lc-sys` to 0.39.1** — Fixes RUSTSEC-2026-0044 (X.509 Name
  Constraints Bypass via Wildcard/Unicode CN).
- **Updated `rustls-webpki` to 0.103.12** — Fixes RUSTSEC-2026-0049 (CRLs not
  considered authoritative by Distribution Point due to faulty matching logic).

#### Maintenance

- **Committed `Cargo.lock`** — Pinning resolved dependency versions to prevent
  CI and fresh builds from failing due to the yanked `core2` crate (transitive
  dependency of the `ssi` crate via `ssi-ucan → libipld → multihash 0.16`).

## 1st April 2026

### Release 0.4.1

#### New

- **`cli` feature flag** — Embeddable interactive CLI flows for 3rd-party
  applications. Adds `dialoguer`, `console`, and `affinidi-tdk` as optional
  dependencies. Not included in WASM builds.
- **`interactive_create_did()`** (`cli_create` module) — Interactive DID creation
  flow with the same guided experience as the built-in wizard. Third-party apps
  can embed this in their own CLIs. Supports:
  - Full interactivity (all values prompted) via `InteractiveCreateConfig::default()`
  - Partial pre-configuration via the builder (skip specific prompts)
  - Full pre-configuration (no prompts) for automated use
  - `{DID}` placeholder rewriting in pre-configured services and VM IDs
  - Returns the created DID, signed log entry, witness proofs, and all secrets
- **`interactive_update_did()`** (`cli_update` module) — Interactive DID update
  flow supporting three operations:
  - **Modify**: Edit DID document and/or parameters (auth keys, witnesses,
    watchers, TTL, portability, pre-rotation)
  - **Migrate**: Move DID to a new domain (rewrites identifiers, adds previous
    DID to `alsoKnownAs`)
  - **Deactivate**: Permanently deactivate the DID (handles pre-rotation teardown)
  - Returns the updated state, new log entry, and updated secrets
- **`UpdateSecrets`** — Secret management type with hash-based and public-key-based
  lookups, used for DID update operations. Compatible with the wizard's
  `ConfigInfo` JSON format for loading secrets from existing files.
- **`update_did()`** (`update` module) — Programmatic DID update API,
  complementing `create_did()`. Supports document changes, key rotation,
  parameter updates (witnesses, watchers, TTL, pre-rotation, portability),
  domain migration (with identifier rewriting), and deactivation (with
  automatic pre-rotation teardown). Handles witness proof signing. Uses the
  same builder pattern as `CreateDIDConfig`.
- **Shared CLI utilities** (`cli_common` module, internal) — Common prompt
  helpers, key generation, witness setup, and next-key-hash generation shared
  between create and update flows.

#### Improvements

- **Inline concept explanations** — All interactive prompts now explain key
  DID concepts in context: what witnesses and watchers do, how pre-rotation
  works, what verification relationships mean (authentication, assertionMethod,
  keyAgreement, etc.), what controllers are for, and what portability implies.
- **Key type guidance** — The verification method key selection now describes
  each algorithm (Ed25519 recommended, X25519 for encryption, P-256/P-384 for
  enterprise, secp256k1 for blockchain).
- **TTL and threshold recommendations** — Default TTL of 3600 seconds suggested,
  witness threshold explained with concrete example (e.g. "threshold=2 with 3
  witnesses means any 2 of 3 must sign").
- **Consistent terminology** — Standardized on "deactivate" (not "revoke"),
  "authorization keys" (not "updateKeys"), and consistent prompt phrasing
  throughout all CLI flows.
- **Format hints** — Input prompts now include format examples (e.g. multibase
  encoding `z6Mk...`, DID format `did:key:z6Mk...`, watcher URLs).
- **Wizard example refactored** — The `wizard` example now uses the library's
  `interactive_create_did()` and `interactive_update_did()` flows instead of its
  own standalone implementation. This reduced the wizard from ~1800 lines across
  9 files to ~280 lines across 3 files (`main.rs`, `did_web.rs`, `resolve.rs`).
  The wizard now requires the `cli` feature (`cargo run --example wizard --features cli`).

#### Maintenance

- Version bump: 0.4.0 → 0.4.1

## 27th March 2026

### Release 0.4.0

#### Breaking Changes

- **`resolve()` / `resolve_owned()` signature change** — The `timeout` and
  `eager_witness_download` parameters have been replaced with a single
  `ResolveOptions` struct. Callers should migrate from
  `resolve(did, None, false)` to `resolve(did, ResolveOptions::default())`.
  Custom timeout or eager witness download can be set via struct fields:
  ```rust
  ResolveOptions {
      timeout: Some(Duration::from_secs(5)),
      eager_witness_download: true,
      ..ResolveOptions::default()
  }
  ```

#### New

- **HTTP response size limits** — `download_file()` now enforces a maximum
  response body size to prevent memory exhaustion from malicious or
  misconfigured servers.
  - `Content-Length` header is checked first for early rejection before any
    body data is read.
  - Body is read in chunks via `response.chunk()` with a running byte counter,
    catching oversized responses even when `Content-Length` is absent or
    inaccurate (e.g. chunked transfer encoding).
  - Default limit: 200 KB (`DEFAULT_MAX_RESPONSE_BYTES`), configurable
    per-request via `ResolveOptions::max_response_bytes`.
- **`ResolveOptions` struct** — Bundles network resolution options (`timeout`,
  `eager_witness_download`, `max_response_bytes`) into a single configuration
  type with sensible defaults via `Default` trait. Re-exported from `prelude`
  behind the `network` feature gate.
- **`ResponseTooLarge` error variant** — New `DIDWebVHError::ResponseTooLarge`
  carries the offending URL and the configured byte limit, making it easy for
  consumers to distinguish size-limit rejections from other network errors.
- **`generate_large_did` example** — Generates a valid 1 MB+ `did.jsonl` file
  with backdated timestamps for benchmarking and testing. Accepts a URL via
  `--url` (properly parsed into WebVH DID format via `WebVHURL::parse_url()`),
  configurable target size (`--target-kb`), and includes generation, write, load,
  and validation timing.
- **`resolve` example CLI improvements** — Now uses `clap` for argument parsing
  with a `--max-size-kb` (`-l`) flag to set the response size limit from the
  command line.

## 19th March 2026

### Release 0.3.1

#### New

- **`resolve_log()` / `resolve_log_owned()`** — Accept raw JSONL log data and
  optional witness proofs as strings, enabling client-side cryptographic
  verification without filesystem or network access. Supports architectures
  where a cache server resolves DIDs and forwards the raw log alongside the
  document, allowing clients to independently verify the DID document has not
  been tampered with.
- **Public parsing helpers** — `parse_log_entries()`, `parse_witness_proofs()`,
  and `needs_witness_proofs()` are now public and available without the
  `network` feature, since they operate on in-memory data only.

## 14th March 2026

### Release 0.3.0

#### New

- **Convenience API** — `DIDWebVHState` now provides `update_document()`,
  `rotate_keys()`, and `deactivate()` methods for common DID lifecycle
  operations without manually constructing parameter diffs.
- **Feature flags** — `reqwest` is now optional behind the `network` feature
  (default on). Consumers who only need local file validation can opt out
  with `default-features = false`. TLS backend selection via `rustls` and
  `native-tls` features.
- **`WitnessesBuilder`** — Ergonomic builder for constructing witness
  configurations with threshold validation:
  `Witnesses::builder().threshold(2).witness(key).build()?`
- **`{SCID}` placeholder validation** — `CreateDIDConfigBuilder::build()`
  now validates that the DID document `id` field contains a `{SCID}` or
  `{DID}` placeholder, with a clear error message if missing.
- **Error context helpers** — `DIDWebVHError::validation()`,
  `DIDWebVHError::parameter()`, and `DIDWebVHError::log_entry()` stamp
  version/field context into error messages for easier debugging.
- **`async_trait` re-export** — `async_trait` moved from dev-dependencies to
  dependencies and re-exported from the crate root and `prelude`, so `Signer`
  implementors don't need a separate dependency.
- **Cache serialization** — `DIDWebVHState` now implements `Serialize` and
  `Deserialize`, with `save_state(path)` and `load_state(path)` convenience
  methods for offline caching. `LogEntryState`, `LogEntry`, `Parameters`, and
  `Version` now also derive `Deserialize`.
- **`resolve_owned()` / `resolve_file_owned()`** — Return owned (cloned)
  `(LogEntry, MetaData)` so callers don't need to borrow `DIDWebVHState`.
- **Property-based tests** — `proptest` added for Multibase serde round-trips
  and WitnessesBuilder threshold validation.
- **Lifecycle examples** — `examples/update_did.rs`, `examples/rotate_keys.rs`,
  and `examples/deactivate_did.rs` demonstrate the convenience API.
- **Pluggable signing via `Signer` trait** — all signing operations now go through
  the `Signer` trait from `affinidi-data-integrity`. This means secret key material
  no longer needs to be held in-process; you can delegate signing to an HSM, cloud
  KMS (e.g. AWS KMS, Azure Key Vault, HashiCorp Vault), or any external signing
  service by implementing the `Signer` trait.
  - `CreateDIDConfig<A, W>` is now generic over authorization and witness signer
    types, with defaults of `Secret` for full backward compatibility
  - `create_did()`, `sign_witness_proofs()`, and `DIDWebVHState::create_log_entry()`
    accept any `Signer` implementation
  - `Signer` trait and `KeyType` re-exported from the crate root and `prelude`
  - `CreateDIDConfig::builder_generic()` added for custom signer types;
    `CreateDIDConfig::builder()` continues to work with `Secret` as before
- **Structured `NetworkError`** — `DIDWebVHError::NetworkError` now carries
  typed fields (`url`, `status_code`, `message`) instead of a plain `String`.
  Consumers can programmatically distinguish HTTP errors (404, 500) from
  transport failures (timeouts, connection refused) by inspecting `status_code`.
- **Removed `regex` dependency** — DID string operations in `did_web.rs` now use
  `str::split_once()`, `str::strip_prefix()`, and a custom `replace_webvh_prefix()`
  function, eliminating the `regex` crate from the dependency tree.

#### Maintenance

- Dependencies updated: `affinidi-data-integrity` 0.4→0.5,
  `affinidi-secrets-resolver` 0.5.0→0.5.2
- Internal `ensure_did_key_id()` (which mutated `Secret` IDs) replaced with
  `validate_did_key_vm()` (validation only, no mutation) — signers are now
  required to provide a correctly formatted `did:key:` verification method
- Added `wiremock` dev-dependency for network failure testing
- Consolidated duplicate test helpers into shared `test_utils` module
- Added comprehensive documentation for `resolve()`, `validate()`, implicit
  services, and witness proof semantics
- Added network failure tests (HTTP 404/500, timeout, connection refused,
  malformed/empty responses)
- Added file I/O error tests for log entry and witness proof loading/saving
- Added unit tests for `LogEntryState` accessors
- Test count: 383 tests (370 unit + 12 integration + 1 doc-test)

## 5th March 2026

### Release 0.2.0

#### Spec Compliance Fixes

- IP addresses rejected in DID URLs per spec (`parse_did_url()` and `parse_url()`)
- Resolved DID validated against DID Document `id` (Read/Resolve step 6)
- DID portability enforced: `id` changes require `portable: true` and previous
  DID in `alsoKnownAs`
- `versionTime` ordering uses strict greater-than (equal timestamps rejected)
- Query parameter mutual exclusivity enforced at parse time (`versionId`,
  `versionTime`, `versionNumber`)
- Witness `{}` and watchers `[]` correctly treated as "not configured" instead of
  erroring
- Empty arrays for `watchers`, `nextKeyHashes`, `updateKeys` no longer error in
  diff calculation
- `Parameters1_0.deactivated` changed from `bool` to `Option<bool>` for lossless
  serialization round-trips

#### Improvements

- `resolve()` conditionally downloads `did-witness.json` only when witnesses are
  configured (`eager_witness_download` parameter)
- `prelude` module added for convenient imports (`use didwebvh_rs::prelude::*`)
- `NotFound` and `UnsupportedMethod` error variants now carry context strings
- All `unwrap()` calls in production code replaced with proper error handling
- Deduplicated log entry spec implementations via `impl_log_entry_common!` macro
  (~150 lines removed)
- Deduplicated resolver helpers (`validate_log_entries()`, `resolve_witness_proofs()`)
- Simplified `Parameters::validate()` (removed dead code, consolidated TTL validation)

#### New

- Benchmark harness: `cargo bench --bench did_benchmarks` (Criterion) and nightly
  benchmarks
- `WebVHURL::to_did_base()` helper for DID comparison without query/fragment

#### Maintenance

- Dependencies updated: `affinidi-data-integrity` 0.3→0.4, `criterion` 0.5→0.8,
  `ssi` 0.14→0.15, `rand` 0.9→0.10
- Fixed minimum Rust version badge in README (1.88→1.90)
- `generate_history` example uses deterministic timestamps; fixes `rand` 0.10 import
- Comprehensive test coverage: 353 tests (340 unit + 12 integration + 1 doc-test)
  with shared test utilities

## 5th February 2026

### Release 0.1.17

- **FEATURE:** New `create` module with a library API for programmatic DID creation
  - `create_did()` encapsulates the full DID creation flow (log entry creation,
    validation, witness signing) without any interactive prompts
  - `CreateDIDConfig::builder()` provides a fluent builder for constructing the
    configuration
  - `add_web_also_known_as()` and `add_scid_also_known_as()` are non-interactive
    helpers for adding aliases to the DID document
  - `sign_witness_proofs()` is a standalone function for signing witness proofs
    outside of the full creation flow
- **IMPROVEMENT:** Wizard example updated to delegate core logic to the new
  library API, reducing code duplication between the library and the example
- **MAINTENANCE:** Updated downstream dependencies
  - `SSI` crate updated to 0.14
- **MAINTENANCE:** Tests added for code coverage (@82.67% code coverage)

## 1st February 2026

### Release 0.1.16

- **MAINTENANCE:** Updated downstream dependencies

## 4th December 2025

### Release 0.1.13 --> 0.1.15

- **FIX:** Updated back to `affinid-data-integrity` 0.3.x after fixing cyclic
  dependency issue

### Release 0.1.12

- **FIX:** Downgrading `affinidi-data-integrity` to 0.2.x due to cyclic dependency
  issue

## 3rd December 2025

### Release 0.1.11

- **FEATURE:** Added the wizard the ability to easily add a did:scid:vh alsoKnownAs
  alias
  - This matches with making WebVH as reusable as possible, supporting did:web and
    did:scid in parallel
- **MAINTENANCE:** Updated `affinidi-data-integrity` to 0.3.x release
- **MAINTENANCE:** Updated downstream dependencies

## 3rd November 2025

### Release 0.1.10

- **MAINTENANCE:** Updated `affinidi-secrets-resolver` to 0.4.x release

## 3rd October 2025

### Release 0.1.9

- **MAINTENANCE:** Updated `affinidi-secrets-resolver` to 0.3.x release

## 30th September 2025

### Release 0.1.8

- **MAINTENANCE:** Crate dependencies updated
  - Removes a lot of the SSI crate dependencies from downstream crates simplifying
    the build
- **IMPROVEMENT:** Example `generate_history` now has interactive mode
  - `cargo run --release --example generate_history -- -i`
- **IMPROVEMENT:** `get_did_document()` added to `LogEntryState` and `LogEntry`
  - Use `get_did_document()` to get a full DID Document including implied WebVH
    Services
  - Use `get_state()` if you want to access the raw un-modified DID Document

## 13th September 2025

### Release 0.1.7

- **IMPROVEMENT:** `didwebvh-rs` is now WASM compile friendly.

## 11th September 2025

### Release 0.1.6

- **IMPROVEMENT:** Wizard will now assist with exporting to did:web format
  - The wizard will change DID Document values on your behalf
  - It can also add to the did:webvh Document `alsoKnownAs` records
- **IMPROVEMENT:** Resolver will now auto add implicit service records to the
  resolved DID Document where missing (#files and #whois)
- **IMPROVEMENT:** DID Secrets now stored in the `did-secrets.json` when using the
  Wizard
- **IMPROVEMENT:** Added X25519 key support for Encryption Keys (DID Doc)
- **IMPROVEMENT:** SSI Crate moved to a feature flag (`ssi`) so it becomes optional
- **FIX:** URL parsing would incorrectly handle trailing slashes on URL Path
- **FIX:** Wizard would exit with an error when aborting migrating the DID
- **MAINTENANCE:** Updated crate dependencies
- **MAINTENANCE:** Tests added for code coverage (@74.27% code coverage)

## 4th September 2025

### Release 0.1.5

- **IMPROVEMENT:** Removed Option on return from `create_log_entry`
  - Will now return an `Err` if something wrong internally occurs
  - Simplifies error handling on the client side

## 3rd September 2025

### Release 0.1.4

- **IMPROVEMENT:** Exporting Secrets Resolver via this crate so it is easier for
  developers to manage secrets required to manage DIDs
- **MAINTENANCE:** Bumped crate dependencies to latest versions

## 26th August 2025

### Release 0.1.3

- **IMPROVEMENT:** Added additional notes to the wizard when creating updateKeys
  and NextKeyHashes so it is clear that it is a loop until you decide you have
  enough keys
- **IMPROVEMENT:** Ability to resolve a WebVH DID from the wizard added
  - You can still use the example `resolve` as well
- **IMPROVEMENT:** Resolver Query parameter `versionNumber` implemented
  - Allows you to resolve a specific LogEntry version number instead of the full
    `versionId`
- **FIX:** DID Deactivation metadata is now stored at the DID level and not LogEntry
  - Once a DID has been deactivated, all LogEntries will show the DID as deactivated
- **MAINTENANCE:** Bumped crate dependencies to latest versions
  - `dialoguer` upgraded from 0.11 to 0.12
- **MAINTENANCE:** More tests added for code coverage (@73.15% code coverage)

## 18th August 2025

### Release 0.1.2

- **FIX:** [Issue #5](https://github.com/decentralized-identity/didwebvh-rs/issues/5)
  UpdateKey not propagating to new LogEntry Parameter set when pre-rotation is disabled
  - Secondary issue of changing update-key also results in an error
- **FIX:** Wizard would not reset an existing did.jsonl file for a new DID
- **FIX:** Parameter method was always being placed in each LogEntry, will now
  correctly skip if version is the same
- **MAINTENANCE:** More tests added for code coverage (@66.78% code coverage)

## 14th August 2025

### Release 0.1.1

- **FIX:** [Issue #2](https://github.com/decentralized-identity/didwebvh-rs/issues/2)
  Handle when there is no witness proof file on resolution
- **FIX:** [Issue #3](https://github.com/decentralized-identity/didwebvh-rs/issues/3)
  URL Conversions incorrectly including .well-known path for default location
  - Added unit test to test for inclusion of default paths in URL conversions
- **MAINTENANCE:** Updating crate dependencies to latest versions
- **MAINTENANCE:** Addressing rust-analyzer warnings
  - Chaining `if let` statements where multiple `if` statements were being used

## 1st August 2025

### Release 0.1.0

- **RELEASE:** Initial release of the `didwebvh-rs` library.
