# Test-suite interop vectors

Regression fixtures imported from
[didwebvh-test-suite](https://github.com/decentralized-identity/didwebvh-test-suite)
PR [#4](https://github.com/decentralized-identity/didwebvh-test-suite/pull/4).

Upstream commit: `7be2491f04102e322197774504ff986c18b1f63e`
Upstream path: `vectors/<scenario>/`

## Contents

Each subdirectory is one happy-path scenario. Files per scenario:

- `did.jsonl` — the DID log.
- `resolutionResult.json` — expected resolver output for the latest
  version.
- `resolutionResult.<N>.json` — expected output when resolving with
  `?versionNumber=<N>` (present only for `multi-update`).
- `did-witness.json` — committed witness proofs (present only for
  `witness-threshold` and `witness-update`).

`script.yaml` (the DSL input used to generate each vector) is **not**
imported — it's an upstream generator input, not part of the vector.

## Scenarios

- `basic-create` — single log entry.
- `basic-update` — create + one update, no key change.
- `key-rotation` — update that rotates the updateKey.
- `multi-update` — three entries with intermediate `versionNumber` targets.
- `multiple-update-keys` — log with more than one `updateKeys` entry.
- `deactivate` — terminal entry with `deactivated: true`.
- `services` — service-endpoint expansion for `#files` / `#whois`.
- `witness-update` — witness configuration change.
- `witness-threshold` — witness threshold verification, with proofs.
- `portable` — DID created with `portable: true`.
- `portable-move` — portable DID migrated to a new web location.
- `pre-rotation` — log using `nextKeyHashes` commitments.
- `pre-rotation-consume` — rotation that consumes a pre-rotation commit.

## Refreshing

Upstream hasn't stabilised yet. To refresh:

```sh
SHA=<new-sha>
BASE=https://raw.githubusercontent.com/decentralized-identity/didwebvh-test-suite/$SHA/vectors
# ... curl each file into place, update this README's SHA.
```
