# didwebvh-rs Changelog history

## 15th August 2025

### Release 0.1.2

* **FIX:** [Issue #5](https://github.com/decentralized-identity/didwebvh-rs/issues/5)
UpdateKey not propagating to new LogEntry Parameter set when pre-rotation is disabled
  * Secondary issue of changing update-key also results in an error
* **FIX:** Wizard would not reset an existing did.jsonl file for a new DID

## 14th August 2025

### Release 0.1.1

* **FIX:** [Issue #2](https://github.com/decentralized-identity/didwebvh-rs/issues/2)
Handle when there is no witness proof file on resolution
* **FIX:** [Issue #3](https://github.com/decentralized-identity/didwebvh-rs/issues/3)
URL Conversions incorrectly including .well-known path for default location
  * Added unit test to test for inclusion of default paths in URL conversions
* **MAINTENANCE:** Updating crate dependencies to latest versions
* **MAINTENANCE:** Addressing rust-analyzer warnings
  * Chaining `if let` statements where multiple `if` statements were being used

## 1st August 2025

### Release 0.1.0

* **RELEASE:** Initial release of the `didwebvh-rs` library.
