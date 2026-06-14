#![no_main]
//! Fuzz the proof-verification path: `LogEntry::validate_witness_proof`.
//!
//! The arbitrary `LogEntry` carries arbitrary `DataIntegrityProof`s, so we
//! verify each of the entry's own proofs against it. Arbitrary bytes won't
//! form a valid signature, so this targets the STRUCTURAL pre-crypto path:
//! `enforce_witness_proof_shape` (cryptosuite + proofPurpose gating),
//! `PublicKey::get_public_key_bytes` (did:key resolution + multibase decode),
//! and the cryptosuite allow-list. None of it may panic on hostile input.

use libfuzzer_sys::fuzz_target;
use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};
use didwebvh_rs::witness::WitnessVerifyOptions;

fuzz_target!(|entry: LogEntry| {
    let options = WitnessVerifyOptions::new();
    for proof in entry.get_proofs() {
        let _ = entry.validate_witness_proof(proof, &options);
    }
});
