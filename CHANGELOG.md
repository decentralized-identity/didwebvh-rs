# didwebvh-rs Changelog history

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
