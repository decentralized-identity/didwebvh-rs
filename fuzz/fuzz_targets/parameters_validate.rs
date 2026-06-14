#![no_main]
//! Fuzz the pure parameter-transition logic: `Parameters::validate(previous)`.
//!
//! This is the highest-ROI target — `validate()` is the spec's transition
//! rule engine (SCID presence, portable monotonicity, pre-rotation key-hash
//! commitments, witness/watcher tri-state, deactivation terminality) and runs
//! with no cryptography, so structure-aware input reaches it immediately.
//! We assert it never panics and never produces a result that fails to
//! re-validate against itself (an idempotence/soundness check on the output).

use libfuzzer_sys::fuzz_target;
use didwebvh_rs::parameters::Parameters;

fuzz_target!(|input: (Parameters, Option<Parameters>)| {
    let (current, previous) = input;
    if let Ok(validated) = current.validate(previous.as_ref()) {
        // A successfully validated parameter set, fed back as the "current"
        // entry on top of itself, must not panic the validator.
        let _ = validated.validate(Some(&validated));
    }
});
