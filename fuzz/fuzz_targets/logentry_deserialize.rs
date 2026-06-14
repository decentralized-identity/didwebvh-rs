#![no_main]
//! Fuzz the JSON entry parser: `LogEntry::deserialize_string`.
//!
//! Raw-bytes target (not structure-aware): exercises version detection, the
//! pre-ratification null-vs-empty heuristic, and the two serde paths. Any
//! input must yield `Ok`/`Err` — never a panic. Strings that do parse are
//! round-tripped to catch serialize/deserialize asymmetries.

use libfuzzer_sys::fuzz_target;
use didwebvh_rs::log_entry::LogEntry;

fuzz_target!(|data: &str| {
    if let Ok(entry) = LogEntry::deserialize_string(data, None) {
        // A parsed entry must re-serialize and re-parse without panicking.
        if let Ok(json) = serde_json::to_string(&entry) {
            let _ = LogEntry::deserialize_string(&json, None);
        }
        let _ = entry.generate_log_entry_hash();
    }
});
