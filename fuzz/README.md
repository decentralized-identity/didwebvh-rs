# didwebvh-rs fuzzing

Structure-aware, coverage-guided fuzzing for the `did:webvh` chain verifier
(issue #44). Built on [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
and the off-by-default `arbitrary` feature of `didwebvh-rs`.

This is a **separate, workspace-detached crate** — it has its own empty
`[workspace]` table, so `cargo build`/`cargo test`/`cargo clippy` at the repo
root never compile it and the nightly-only libfuzzer toolchain stays out of
normal CI.

## Why structure-aware

Raw byte/string mutation almost never produces input that survives
`LogEntry` deserialization, let alone a multi-entry chain whose hashes link —
so a naive fuzzer bounces off the JSON parser and rarely reaches the verifier.
The `arbitrary` feature derives/implements `Arbitrary` on the public log-entry
and parameters types, so these targets generate *structurally-valid-but-
semantically-mutated* chains that actually exercise the transition and
verification logic.

## Setup

```sh
cargo install cargo-fuzz       # one-time
rustup toolchain install nightly
```

## Targets

| Target                 | Surface |
|------------------------|---------|
| `parameters_validate`  | `Parameters::validate` — pure parameter-transition rules (no crypto; highest ROI) |
| `logentry_deserialize` | `LogEntry::deserialize_string` — version detection + serde paths |
| `chain_validate`       | `DIDWebVHState::validate` — full chain walk over an arbitrary `Vec<LogEntry>` |
| `proof_verify`         | `LogEntry::validate_witness_proof` — structural proof path (shape, did:key resolve, cryptosuite gating) |

## Running

From this `fuzz/` directory:

```sh
cargo +nightly fuzz run parameters_validate
cargo +nightly fuzz run chain_validate -- -max_total_time=300
```

List targets: `cargo +nightly fuzz list`.

## Notes

- Arbitrary bytes essentially never form a valid signature, so `proof_verify`
  exercises the *pre-crypto* structural path. To fuzz valid-then-tampered
  proofs, build a harness that signs with controlled keys.
- `state` (the DID document) is generated as a *bounded* JSON value
  (capped depth/width) so the fuzzer explores the verifier rather than
  building giant trees.
