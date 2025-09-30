# didwebvh-rs Changelog history

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
