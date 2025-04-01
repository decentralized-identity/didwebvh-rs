//! Module for processing DID log files.
//! 
//! This module provides functions for parsing and validating DID log entries
//! according to the did:webvh specification.

use crate::error::{ResolverError, Result};
use crate::http::HttpClient;
use crate::types::{DIDLogEntry, Parameters, DIDDocumentMetadata};
use crate::url::DIDUrl;
use crate::crypto::{verify_scid, verify_entry_hash, verify_prerotation};
use serde_json::Value;
use std::collections::HashMap;



/// Parsed and validated DID log
#[derive(Debug, Clone)]
pub struct DIDLog {
    /// All entries in the log
    pub entries: Vec<DIDLogEntry>,
    /// Latest active parameters
    pub active_parameters: Parameters,
    /// Mapping of version IDs to entry indices
    pub version_id_map: HashMap<String, usize>,
    /// Original DID string
    pub did: String,
}

impl DIDLog {
    /// Create a new, empty DID log
    pub fn new(did: &str) -> Self {
        Self {
            entries: Vec::new(),
            active_parameters: Parameters::default(),
            version_id_map: HashMap::new(),
            did: did.to_string(),
        }
    }

    /// Get the latest entry in the log
    pub fn latest_entry(&self) -> Option<&DIDLogEntry> {
        self.entries.last()
    }

    /// Get an entry by version ID
    pub fn get_entry_by_version_id(&self, version_id: &str) -> Option<&DIDLogEntry> {
        self.version_id_map.get(version_id).map(|&idx| &self.entries[idx])
    }

    /// Get an entry by version number
    pub fn get_entry_by_version_number(&self, version_number: u64) -> Option<&DIDLogEntry> {
        let version_prefix = format!("{}-", version_number);
        self.entries.iter().find(|entry| entry.version_id.starts_with(&version_prefix))
    }

    /// Get an entry by version time (closest entry at or before the given time)
    pub fn get_entry_by_version_time(&self, version_time: &str) -> Option<&DIDLogEntry> {
        // Basic implementation - we'll improve this later with proper timestamp parsing
        self.entries.iter()
            .filter(|entry| entry.version_time.as_str() <= version_time)
            .max_by(|a, b| a.version_time.cmp(&b.version_time))
    }

    /// Generate DID document metadata from the log
    pub fn generate_metadata(&self, entry: &DIDLogEntry) -> DIDDocumentMetadata {
        let mut metadata = DIDDocumentMetadata::default();
        
        // Set created time from the first entry
        if let Some(first_entry) = self.entries.first() {
            metadata.created = Some(first_entry.version_time.clone());
        }
        
        // Set updated time from the specified entry
        metadata.updated = Some(entry.version_time.clone());
        
        // Set version ID
        metadata.version_id = Some(entry.version_id.clone());
        
        // Set deactivated flag
        metadata.deactivated = entry.parameters.deactivated;
        
        // Set next version ID if this isn't the latest entry
        if let Some(idx) = self.version_id_map.get(&entry.version_id) {
            if *idx < self.entries.len() - 1 {
                metadata.next_version_id = Some(self.entries[*idx + 1].version_id.clone());
            }
        }
        
        // Check for equivalent IDs (e.g., from portable DIDs)
        let equivalent_ids: Vec<String> = self.entries.iter()
            .filter_map(|e| {
                if let Value::Object(obj) = &e.state {
                    if let Some(Value::Array(aka)) = obj.get("alsoKnownAs") {
                        return Some(
                            aka.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect::<Vec<String>>()
                        );
                    }
                }
                None
            })
            .flatten()
            .collect();
        
        if !equivalent_ids.is_empty() {
            metadata.equivalent_id = Some(equivalent_ids);
        }
        
        metadata
    }
}

/// Parse a DID log file from raw bytes
/// 
/// This function takes raw bytes of a JSONL file and parses it into a list of DID log entries.
/// It performs basic validation of the structure of each entry but does not perform
/// cryptographic verification.
pub fn parse_did_log(log_bytes: &[u8], did: &str) -> Result<DIDLog> {
    let log_str = String::from_utf8_lossy(log_bytes);
    let mut did_log = DIDLog::new(did);
    
    for (line_idx, line) in log_str.lines().enumerate() {
        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }
        
        // Parse the line as JSON
        let entry: DIDLogEntry = serde_json::from_str(line)
            .map_err(|e| ResolverError::LogProcessing(
                format!("Failed to parse log entry at line {}: {}", line_idx + 1, e)
            ))?;
        
        // Perform basic structure validation of the entry
        validate_entry_structure(&entry, did_log.entries.len())
            .map_err(|e| ResolverError::LogProcessing(
                format!("Invalid log entry at line {}: {}", line_idx + 1, e)
            ))?;
        
        // Determine if this is the first entry
        let is_first_entry = did_log.entries.is_empty();
        
        // If this is the first entry, verify the SCID
        if is_first_entry {
            verify_scid(&entry)
                .map_err(|e| ResolverError::LogProcessing(
                    format!("SCID verification failed at line {}: {}", line_idx + 1, e)
                ))?;
        }
        
        // Verify the entry hash, providing the previous entry's versionId if not the first entry
        let prev_version_id = if is_first_entry {
            None
        } else {
            Some(did_log.entries.last().unwrap().version_id.as_str())
        };
        
        verify_entry_hash(&entry, prev_version_id)
            .map_err(|e| ResolverError::LogProcessing(
                format!("Entry hash verification failed at line {}: {}", line_idx + 1, e)
            ))?;
        
        // If pre-rotation is active, verify that update keys match previous nextKeyHashes
        if !is_first_entry {
            if let (Some(update_keys), Some(prev_next_key_hashes)) = (
                &entry.parameters.update_keys,
                &did_log.active_parameters.next_key_hashes
            ) {
                verify_prerotation(update_keys, prev_next_key_hashes)
                    .map_err(|e| ResolverError::LogProcessing(
                        format!("Pre-rotation verification failed at line {}: {}", line_idx + 1, e)
                    ))?;
            }
        }
        
        // Update active parameters, passing is_first_entry flag
        update_active_parameters(&mut did_log.active_parameters, &entry.parameters, is_first_entry);
        
        // Add the entry to the log
        did_log.version_id_map.insert(entry.version_id.clone(), did_log.entries.len());
        did_log.entries.push(entry);
    }
    
    // Validate that the log has at least one entry
    if did_log.entries.is_empty() {
        return Err(ResolverError::LogProcessing("DID log is empty".to_string()));
    }
    
    Ok(did_log)
}

/// Validate the structure of a DID log entry
fn validate_entry_structure(entry: &DIDLogEntry, entry_index: usize) -> Result<()> {
    // Check that versionId is present and has the correct format
    let version_id_parts: Vec<&str> = entry.version_id.split('-').collect();
    if version_id_parts.len() != 2 {
        return Err(ResolverError::LogProcessing(
            format!("Invalid versionId format: {}", entry.version_id)
        ));
    }
    
    // Check that version number is valid
    let version_number = version_id_parts[0].parse::<u64>().map_err(|_| {
        ResolverError::LogProcessing(
            format!("Invalid version number in versionId: {}", entry.version_id)
        )
    })?;
    
    // Check that version number matches the expected sequence
    let expected_version = entry_index as u64 + 1;
    if version_number != expected_version {
        return Err(ResolverError::LogProcessing(
            format!("Version number {} does not match expected sequence number {}", 
                   version_number, expected_version)
        ));
    }
    
    // Check that versionTime is present
    if entry.version_time.is_empty() {
        return Err(ResolverError::LogProcessing(
            "Missing versionTime".to_string()
        ));
    }
    
    // Check that state (DID Document) is present
    if !entry.state.is_object() {
        return Err(ResolverError::LogProcessing(
            "Invalid or missing DID Document in state".to_string()
        ));
    }
    
    // Check that there is at least one proof
    if entry.proof.is_empty() {
        return Err(ResolverError::LogProcessing(
            "Missing proof".to_string()
        ));
    }
    
    // First entry specific checks
    if entry_index == 0 {
        // Check that the first entry has an SCID parameter
        if entry.parameters.scid.is_none() {
            return Err(ResolverError::LogProcessing(
                "First entry is missing required SCID parameter".to_string()
            ));
        }
        
        // Check that the first entry has a method parameter
        if entry.parameters.method.is_none() {
            return Err(ResolverError::LogProcessing(
                "First entry is missing required method parameter".to_string()
            ));
        }
        
        // Check that the first entry has update keys and at least one key
        if entry.parameters.update_keys.is_none() || 
           entry.parameters.update_keys.as_ref().unwrap().is_empty() {
            return Err(ResolverError::LogProcessing(
                "First entry is missing required updateKeys parameter or has empty updateKeys".to_string()
            ));
        }
    }
    
    Ok(())
}

/// Update active parameters with new parameter values
fn update_active_parameters(active_params: &mut Parameters, new_params: &Parameters, is_first_entry: bool) {
    // Note on parameter timing effects:
    // Some parameters take effect immediately, others only after publication.
    // We follow these rules based on the did:webvh specification:
    //
    // Parameters that take effect immediately (in all entries):
    // - method, scid, portable, deactivated, ttl
    //
    // Parameters with special timing rules:
    // - update_keys: Takes effect immediately in first entry, but for subsequent entries,
    //   takes effect only after publication (must be signed by previous entry's keys)
    // - witness: Takes effect immediately in first entry, but for subsequent entries,
    //   takes effect only after publication (must be witnessed by previous entry's witnesses)
    // - next_key_hashes: Takes effect immediately (used to verify next entry's update_keys)

    // Update method if present (takes effect immediately)
    if let Some(method) = &new_params.method {
        active_params.method = Some(method.clone());
    }
    
    // Update SCID if present (takes effect immediately)
    if let Some(scid) = &new_params.scid {
        active_params.scid = Some(scid.clone());
    }
    
    // Update update keys if present (timing depends on whether it's the first entry)
    if let Some(update_keys) = &new_params.update_keys {
        active_params.update_keys = Some(update_keys.clone());
        // Note: For non-first entries, these keys will only be used to verify
        // the *next* entry, not the current one
    }
    
    // Update next key hashes if present
    if let Some(next_key_hashes) = &new_params.next_key_hashes {
        active_params.next_key_hashes = Some(next_key_hashes.clone());
    }
    
    // Update portable flag if present (takes effect immediately)
    if let Some(portable) = new_params.portable {
        active_params.portable = Some(portable);
    }
    
    // Update witness configuration if present (timing depends on whether it's the first entry)
    if new_params.witness.is_some() {
        active_params.witness = new_params.witness.clone();
        // Note: For non-first entries, this witness configuration will only be used
        // for the *next* entry, not the current one
    }
    
    // Update deactivated flag if present (takes effect immediately)
    if new_params.deactivated.is_some() {
        active_params.deactivated = new_params.deactivated;
    }
    
    // Update TTL if present (takes effect immediately)
    if new_params.ttl.is_some() {
        active_params.ttl = new_params.ttl;
    }
}

/// Fetch and parse a DID log
pub async fn fetch_and_parse_did_log<C: HttpClient>(
    http_client: &C,
    did_url: &DIDUrl
) -> Result<DIDLog> {
    // Convert DID URL to HTTPS URL for the DID log
    let https_url = did_url.to_https_url()?;
    
    // Fetch the DID log
    let log_bytes = http_client.get(https_url.as_str(), None).await?;
    
    // Parse the DID log
    parse_did_log(&log_bytes, &did_url.did_url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{http::tests::MockHttpClientMock, Proof, Witness, WitnessConfig};
    
    #[test]
    fn test_parse_valid_did_log() {
        // Simple valid DID log with two entries
        let log_str = r#"{"versionId": "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz", "versionTime": "2024-09-26T23:22:26Z", "parameters": {"method": "did:webvh:0.5", "scid": "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ", "updateKeys": ["z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R"], "nextKeyHashes": ["QmXC3vvStVVzCBHRHGUsksGxn6BNmkdETXJGDBXwNSTL33"]}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R#z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R", "created": "2024-09-26T23:22:26Z", "proofPurpose": "assertionMethod", "proofValue": "z2fPF6fMewtV15kji2N432R7RjmmFs8p7MiSHSTM9FoVmJPtc3JUuZ472pZKoWgZDuT75EDwkGmZbK8ZKVF55pXvx"}]}
{"versionId": "2-QmXL6CLK1BMHAd3zQMqkY49VSc9T3zhUcPxu6zEW176PfN", "versionTime": "2024-09-27T10:15:30Z", "parameters": {"updateKeys": ["z6MkvQnUuQn3s52dw4FF3T87sfaTvXRW7owE1QMvFwpag2Bf"], "nextKeyHashes": ["QmdA9fxQSLLwCQo6TkovcoaLgGYWq6Ttqx6A5D1RY13iFG"]}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R#z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R", "created": "2024-09-27T10:15:30Z", "proofPurpose": "assertionMethod", "proofValue": "z2nkLj9rYAMG7TStpvihuo4HTovpC7uvWcDoYiGhoN8cqQuiwW2EnPZdWtid2FZAQDQPoaNkTooKVftGKDTh9p3Fy"}]}"#;
        
        let log = parse_did_log(log_str.as_bytes(), "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:domain.example").unwrap();
        
        // Check that the log has two entries
        assert_eq!(log.entries.len(), 2);
        
        // Check that the version IDs are correctly parsed
        assert_eq!(log.entries[0].version_id, "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz");
        assert_eq!(log.entries[1].version_id, "2-QmXL6CLK1BMHAd3zQMqkY49VSc9T3zhUcPxu6zEW176PfN");
        
        // Check that active parameters are updated correctly
        assert_eq!(log.active_parameters.method, Some("did:webvh:0.5".to_string()));
        assert_eq!(log.active_parameters.scid, Some("QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ".to_string()));
        assert_eq!(log.active_parameters.update_keys, Some(vec!["z6MkvQnUuQn3s52dw4FF3T87sfaTvXRW7owE1QMvFwpag2Bf".to_string()]));
        
        // Check that version_id_map is correctly populated
        assert_eq!(log.version_id_map.len(), 2);
        assert_eq!(log.version_id_map.get("1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz"), Some(&0));
        assert_eq!(log.version_id_map.get("2-QmXL6CLK1BMHAd3zQMqkY49VSc9T3zhUcPxu6zEW176PfN"), Some(&1));
        
        // Test accessor methods
        assert_eq!(log.latest_entry().unwrap().version_id, "2-QmXL6CLK1BMHAd3zQMqkY49VSc9T3zhUcPxu6zEW176PfN");
        assert_eq!(
            log.get_entry_by_version_id("1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz").unwrap().version_id,
            "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz"
        );
        assert_eq!(log.get_entry_by_version_number(1).unwrap().version_id, "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz");
        assert_eq!(
            log.get_entry_by_version_time("2024-09-27T00:00:00Z").unwrap().version_id,
            "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz"
        );
        
        // Test metadata generation
        let metadata = log.generate_metadata(&log.entries[0]);
        assert_eq!(metadata.created, Some("2024-09-26T23:22:26Z".to_string()));
        assert_eq!(metadata.updated, Some("2024-09-26T23:22:26Z".to_string()));
        assert_eq!(metadata.version_id, Some("1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz".to_string()));
        assert_eq!(metadata.next_version_id, Some("2-QmXL6CLK1BMHAd3zQMqkY49VSc9T3zhUcPxu6zEW176PfN".to_string()));
    }
    
    #[test]
    fn test_parse_invalid_did_log() {
        // Test missing required parameters in first entry
        let log_str = r#"{"versionId": "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz", "versionTime": "2024-09-26T23:22:26Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R#z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R", "created": "2024-09-26T23:22:26Z", "proofPurpose": "assertionMethod", "proofValue": "z2fPF6fMewtV15kji2N432R7RjmmFs8p7MiSHSTM9FoVmJPtc3JUuZ472pZKoWgZDuT75EDwkGmZbK8ZKVF55pXvx"}]}"#;
        
        let result = parse_did_log(log_str.as_bytes(), "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:domain.example");
        assert!(result.is_err());
        
        // Test invalid version number sequence
        let log_str = r#"{"versionId": "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz", "versionTime": "2024-09-26T23:22:26Z", "parameters": {"method": "did:webvh:0.5", "scid": "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ", "updateKeys": ["z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R"]}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R#z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R", "created": "2024-09-26T23:22:26Z", "proofPurpose": "assertionMethod", "proofValue": "z2fPF6fMewtV15kji2N432R7RjmmFs8p7MiSHSTM9FoVmJPtc3JUuZ472pZKoWgZDuT75EDwkGmZbK8ZKVF55pXvx"}]}
{"versionId": "3-QmXL6CLK1BMHAd3zQMqkY49VSc9T3zhUcPxu6zEW176PfN", "versionTime": "2024-09-27T10:15:30Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R#z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R", "created": "2024-09-27T10:15:30Z", "proofPurpose": "assertionMethod", "proofValue": "z2nkLj9rYAMG7TStpvihuo4HTovpC7uvWcDoYiGhoN8cqQuiwW2EnPZdWtid2FZAQDQPoaNkTooKVftGKDTh9p3Fy"}]}"#;
        
        let result = parse_did_log(log_str.as_bytes(), "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:domain.example");
        assert!(result.is_err());
        
        // Test missing proof
        let log_str = r#"{"versionId": "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz", "versionTime": "2024-09-26T23:22:26Z", "parameters": {"method": "did:webvh:0.5", "scid": "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ", "updateKeys": ["z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R"]}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:domain.example"}, "proof": []}"#;
        
        let result = parse_did_log(log_str.as_bytes(), "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:domain.example");
        assert!(result.is_err());
    }
    #[test]
    fn test_update_parameters_first_entry() {
        // Create base parameters
        let mut active_params = Parameters::default();
        
        // Create parameters for first entry
        let first_entry_params = Parameters {
            method: Some("did:webvh:0.5".to_string()),
            scid: Some("QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ".to_string()),
            update_keys: Some(vec!["key1".to_string()]),
            witness: Some(WitnessConfig {
                threshold: 1,
                witnesses: vec![Witness { id: "witness1".to_string() }],
            }),
            portable: Some(true),
            next_key_hashes: Some(vec!["hash1".to_string()]),
            deactivated: None,
            ttl: None,
        };
        
        // Update with first entry parameters (is_first_entry = true)
        update_active_parameters(&mut active_params, &first_entry_params, true);
        
        // Check that all parameters are updated correctly
        assert_eq!(active_params.method, Some("did:webvh:0.5".to_string()));
        assert_eq!(active_params.scid, Some("QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ".to_string()));
        assert_eq!(active_params.update_keys, Some(vec!["key1".to_string()]));
        assert_eq!(active_params.witness.as_ref().unwrap().threshold, 1);
        assert_eq!(active_params.portable, Some(true));
        assert_eq!(active_params.next_key_hashes, Some(vec!["hash1".to_string()]));
    }

    #[test]
    fn test_update_parameters_subsequent_entry() {
        // Create base parameters (simulating active state after first entry)
        let mut active_params = Parameters {
            method: Some("did:webvh:0.5".to_string()),
            scid: Some("QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ".to_string()),
            update_keys: Some(vec!["old_key".to_string()]),
            witness: Some(WitnessConfig {
                threshold: 1,
                witnesses: vec![Witness { id: "old_witness".to_string() }],
            }),
            portable: Some(true),
            next_key_hashes: Some(vec!["old_hash".to_string()]),
            deactivated: None,
            ttl: None,
        };
        
        // Create parameters for subsequent entry
        let new_entry_params = Parameters {
            update_keys: Some(vec!["new_key".to_string()]),
            witness: Some(WitnessConfig {
                threshold: 2,
                witnesses: vec![Witness { id: "new_witness".to_string() }],
            }),
            next_key_hashes: Some(vec!["new_hash".to_string()]),
            deactivated: Some(true),
            ttl: Some(3600),
            ..Parameters::default()
        };
        
        // Update with subsequent entry parameters (is_first_entry = false)
        update_active_parameters(&mut active_params, &new_entry_params, false);
        
        // Check that parameters are updated correctly
        // Method and SCID should remain unchanged
        assert_eq!(active_params.method, Some("did:webvh:0.5".to_string()));
        assert_eq!(active_params.scid, Some("QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ".to_string()));
        
        // These parameters should be updated
        assert_eq!(active_params.update_keys, Some(vec!["new_key".to_string()]));
        assert_eq!(active_params.witness.as_ref().unwrap().threshold, 2);
        assert_eq!(active_params.next_key_hashes, Some(vec!["new_hash".to_string()]));
        assert_eq!(active_params.deactivated, Some(true));
        assert_eq!(active_params.ttl, Some(3600));
    }

    #[test]
    fn test_validate_first_entry_missing_update_keys() {
        // Create an entry with missing update_keys
        let entry = DIDLogEntry {
            version_id: "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz".to_string(),
            version_time: "2024-09-26T23:22:26Z".to_string(),
            parameters: Parameters {
                method: Some("did:webvh:0.5".to_string()),
                scid: Some("QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ".to_string()),
                update_keys: None, // Missing update_keys
                ..Parameters::default()
            },
            state: serde_json::json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com"
            }),
            proof: vec![Proof {
                type_: "DataIntegrityProof".to_string(),
                cryptosuite: "eddsa-jcs-2022".to_string(),
                verification_method: "did:key:z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R#z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R".to_string(),
                created: "2024-09-26T23:22:26Z".to_string(),
                proof_purpose: "assertionMethod".to_string(),
                proof_value: "z2fPF6fMewtV15kji2N432R7RjmmFs8p7MiSHSTM9FoVmJPtc3JUuZ472pZKoWgZDuT75EDwkGmZbK8ZKVF55pXvx".to_string(),
            }],
        };
        
        // Validate as the first entry (entry_index = 0)
        let result = validate_entry_structure(&entry, 0);
        
        // Should fail with error about missing updateKeys
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("updateKeys"));
    }

    #[test]
    fn test_validate_first_entry_empty_update_keys() {
        // Create an entry with empty update_keys array
        let entry = DIDLogEntry {
            version_id: "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz".to_string(),
            version_time: "2024-09-26T23:22:26Z".to_string(),
            parameters: Parameters {
                method: Some("did:webvh:0.5".to_string()),
                scid: Some("QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ".to_string()),
                update_keys: Some(vec![]), // Empty update_keys array
                ..Parameters::default()
            },
            state: serde_json::json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com"
            }),
            proof: vec![Proof {
                type_: "DataIntegrityProof".to_string(),
                cryptosuite: "eddsa-jcs-2022".to_string(),
                verification_method: "did:key:z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R#z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R".to_string(),
                created: "2024-09-26T23:22:26Z".to_string(),
                proof_purpose: "assertionMethod".to_string(),
                proof_value: "z2fPF6fMewtV15kji2N432R7RjmmFs8p7MiSHSTM9FoVmJPtc3JUuZ472pZKoWgZDuT75EDwkGmZbK8ZKVF55pXvx".to_string(),
            }],
        };
        
        // Validate as the first entry (entry_index = 0)
        let result = validate_entry_structure(&entry, 0);
        
        // Should fail with error about empty updateKeys
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty updateKeys"));
    }

    #[test]
    fn test_parse_did_log_with_parameter_updates() {
        // Create a DID log with multiple entries that update different parameters
        let log_str = r#"{"versionId": "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz", "versionTime": "2024-09-26T23:22:26Z", "parameters": {"method": "did:webvh:0.5", "scid": "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ", "updateKeys": ["key1"], "portable": true}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R#z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R", "created": "2024-09-26T23:22:26Z", "proofPurpose": "assertionMethod", "proofValue": "z2fPF6fMewtV15kji2N432R7RjmmFs8p7MiSHSTM9FoVmJPtc3JUuZ472pZKoWgZDuT75EDwkGmZbK8ZKVF55pXvx"}]}
    {"versionId": "2-QmXL6CLK1BMHAd3zQMqkY49VSc9T3zhUcPxu6zEW176PfN", "versionTime": "2024-09-27T10:15:30Z", "parameters": {"updateKeys": ["key2"], "ttl": 3600}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R#z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R", "created": "2024-09-27T10:15:30Z", "proofPurpose": "assertionMethod", "proofValue": "z2nkLj9rYAMG7TStpvihuo4HTovpC7uvWcDoYiGhoN8cqQuiwW2EnPZdWtid2FZAQDQPoaNkTooKVftGKDTh9p3Fy"}]}
    {"versionId": "3-QmaSKJRACGefmi19LkS6TFj5FeMEfr98GpBWk7vEmbhT92", "versionTime": "2024-09-28T14:35:12Z", "parameters": {"deactivated": true}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkvQnUuQn3s52dw4FF3T87sfaTvXRW7owE1QMvFwpag2Bf#z6MkvQnUuQn3s52dw4FF3T87sfaTvXRW7owE1QMvFwpag2Bf", "created": "2024-09-28T14:35:12Z", "proofPurpose": "assertionMethod", "proofValue": "z2V72e7bRFpjvphDcWfYeSDTLsbkoVU5SfWAKMwpxYAL74D8GugTuoB2vH93cJqb8XXz8tN4es9AM787CogcbmXKa"}]}"#;
        
        let did_log = parse_did_log(log_str.as_bytes(), "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com").unwrap();
        
        // Check that the final active parameters are correctly accumulated
        assert_eq!(did_log.active_parameters.method, Some("did:webvh:0.5".to_string()));
        assert_eq!(did_log.active_parameters.scid, Some("QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ".to_string()));
        assert_eq!(did_log.active_parameters.update_keys, Some(vec!["key2".to_string()]));
        assert_eq!(did_log.active_parameters.portable, Some(true));
        assert_eq!(did_log.active_parameters.ttl, Some(3600));
        assert_eq!(did_log.active_parameters.deactivated, Some(true));
    }
}
   