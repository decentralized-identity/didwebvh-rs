#![no_main]
//! Fuzz the full chain verifier: `DIDWebVHState::validate`.
//!
//! Builds a state from a structure-aware `Vec<LogEntry>` (plausible parameters
//! and entry shapes, deliberately broken linkage) and walks the verifier:
//! entry-hash linkage, SCID derivation, parameter transitions, pre-rotation
//! authorisation, and post-deactivation truncation. The verifier must always
//! terminate with a report or an error — never panic — regardless of how
//! broken the chain is.

use libfuzzer_sys::fuzz_target;
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::LogEntry;

fuzz_target!(|entries: Vec<LogEntry>| {
    let mut state = DIDWebVHState::from_log_entries(entries);
    let _ = state.validate();
});
