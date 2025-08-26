use affinidi_data_integrity::verification_proof::verify_data;
use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};

#[cfg(test)]
pub fn load_test_file(file: &str) -> String {
    use std::fs;

    fs::read_to_string(file).unwrap_or_else(|_| panic!("Failed to read test file: {file}",))
}

#[test]
fn test_first_log_entry_good() {
    let first_log_entry = load_test_file("tests/test_vectors/first_log_entry_good.jsonl");

    let first_log_entry: LogEntry = LogEntry::deserialize_string(&first_log_entry, None)
        .expect("Failed to parse first log entry JSON");

    assert!(first_log_entry.get_parameters().validate(None).is_ok());
}

#[test]
fn test_first_log_entry_verify_signature() {
    let first_log_entry = load_test_file("tests/test_vectors/first_log_entry_verify_full.jsonl");

    let mut first_log_entry: LogEntry = LogEntry::deserialize_string(&first_log_entry, None)
        .expect("Failed to parse first log entry JSON");

    let proof = if let Some(proof) = first_log_entry.get_proofs().first() {
        proof.to_owned()
    } else {
        panic!("Proof is missing in the first log entry");
    };

    first_log_entry.clear_proofs();

    assert!(verify_data(&first_log_entry, None, &proof).is_ok());
}

#[test]
fn test_first_log_entry_verify_signature_tampered() {
    let first_log_entry =
        load_test_file("tests/test_vectors/first_log_entry_verify_tampered.jsonl");

    let mut first_log_entry: LogEntry = LogEntry::deserialize_string(&first_log_entry, None)
        .expect("Failed to parse first log entry JSON");

    let proof = if let Some(proof) = first_log_entry.get_proofs().first() {
        proof.to_owned()
    } else {
        panic!("Proof is missing in the first log entry");
    };

    first_log_entry.clear_proofs();

    assert!(verify_data(&first_log_entry, None, &proof).is_err());
}

#[test]
fn test_first_log_entry_verify_full() {
    let first_log_entry = load_test_file("tests/test_vectors/first_log_entry_verify_full.jsonl");

    let first_log_entry: LogEntry = LogEntry::deserialize_string(&first_log_entry, None)
        .expect("Failed to parse first log entry JSON");

    let result = first_log_entry.verify_log_entry(None, None);
    println!("{result:#?}",);
    assert!(result.is_ok());
}

#[test]
fn test_first_log_entry_verify_full_error() {
    let first_log_entry =
        load_test_file("tests/test_vectors/first_log_entry_verify_tampered.jsonl");

    let first_log_entry: LogEntry = LogEntry::deserialize_string(&first_log_entry, None)
        .expect("Failed to parse first log entry JSON");

    assert!(first_log_entry.verify_log_entry(None, None).is_err());
}
