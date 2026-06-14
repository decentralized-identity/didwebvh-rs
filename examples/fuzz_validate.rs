//! Structure-aware fuzz harness for the did:webvh chain verifier.
//!
//! With the `arbitrary` feature, the whole log-entry / parameters graph derives
//! [`arbitrary::Arbitrary`], so a fuzzer can turn a raw `&[u8]` into a
//! *structurally-valid-but-mutated* chain and drive
//! [`DIDWebVHState::validate`] directly — far better coverage than byte
//! mutation, which almost never survives JSON parsing.
//!
//! Run it as a normal example over a corpus file (no nightly needed):
//!
//! ```sh
//! cargo run --example fuzz_validate --features arbitrary -- path/to/seed
//! ```
//!
//! To wire it into `cargo-fuzz`, copy [`fuzz_one`] into a libfuzzer target:
//!
//! ```ignore
//! #![no_main]
//! libfuzzer_sys::fuzz_target!(|data: &[u8]| {
//!     didwebvh_rs_fuzz::fuzz_one(data);
//! });
//! ```
//!
//! The contract under fuzz is simple: `validate()` must only ever return
//! `Ok`/`Err` — it must never panic on attacker-controlled input.

use arbitrary::{Arbitrary, Unstructured};
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::LogEntry;
use didwebvh_rs::log_entry_state::{LogEntryState, LogEntryValidationStatus};
use didwebvh_rs::parameters::Parameters;

/// One fuzz iteration: build a chain from `data` and run it through the
/// verifier. Returns early (does nothing) when the bytes can't be coerced
/// into a plausible chain — that's a miss, not a crash.
pub fn fuzz_one(data: &[u8]) {
    let mut u = Unstructured::new(data);

    // Generate a plausible multi-entry chain straight from the bytes.
    let Ok(entries) = Vec::<LogEntry>::arbitrary(&mut u) else {
        return;
    };
    if entries.is_empty() {
        return;
    }

    let mut state = DIDWebVHState::default();
    for entry in entries {
        // versionId must parse to a number for the chain walk; if a mutated
        // entry can't yield one, skip this input rather than fabricate state.
        let Ok((version_number, _)) = entry.get_version_id_fields() else {
            return;
        };
        state.log_entries_mut().push(LogEntryState {
            log_entry: entry,
            version_number,
            validated_parameters: Parameters::default(),
            validation_status: LogEntryValidationStatus::NotValidated,
        });
    }

    // The property under test: never panic. Both outcomes are acceptable.
    let _ = state.validate();
}

fn main() {
    // Read a single corpus file from argv[1], or stdin if omitted.
    let data = if let Some(path) = std::env::args().nth(1) {
        std::fs::read(&path).expect("failed to read corpus file")
    } else {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .expect("failed to read stdin");
        buf
    };

    fuzz_one(&data);
    println!("ok: validate() did not panic on {} bytes", data.len());
}
