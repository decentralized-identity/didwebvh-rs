//! Module for cryptographic operations.
//!
//! This module provides functions for:
//! - SCID generation and verification
//! - Entry hash generation and verification
//! - Handling JSON Canonicalization Scheme (JCS)
//! - Multihash and base58btc encoding

use crate::error::{ResolverError, Result};
use crate::types::{DIDLogEntry, Parameters};
use base58::{self, ToBase58};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use multihash::{Multihash};
use serde_json_canonicalizer::to_string as to_canonical_json;

/// SHA-256 multihash code
pub const SHA2_256: u64 = 0x12;

/// Generate a multihash using SHA-256
fn generate_multihash(data: &[u8]) -> Result<Vec<u8>> {
    // Create a new SHA-256 hasher
    let mut hasher = Sha256::new();
    
    // Update the hasher with the input data
    hasher.update(data);
    
    // Finalize and get the hash
    let hash = hasher.finalize();
    
    // Wrap the hash in a multihash format
    let multihash = Multihash::<64>::wrap(SHA2_256, &hash)
        .map_err(|_| ResolverError::Verification("Failed to create multihash".to_string()))?;
    
    Ok(multihash.to_bytes())
}

/// Convert bytes to base58btc encoding
fn to_base58btc(hash: &[u8]) -> String {
    hash.to_base58()
}

/// Generate a hash string using multihash and base58btc encoding
pub fn hash_to_base58btc(data: &[u8]) -> Result<String> {
    let multihash_bytes = generate_multihash(data)?;
    Ok(to_base58btc(&multihash_bytes))
}

/// Verify the SCID of a DID based on the first log entry
///
/// The SCID is generated as:
/// base58btc(multihash(JCS(preliminary log entry with {SCID} placeholders), <hash algorithm>))
pub fn verify_scid(entry: &DIDLogEntry) -> Result<()> {
    // Extract the SCID from the entry parameters
    let scid = entry.parameters.scid.as_ref().ok_or_else(|| {
        ResolverError::Verification("Missing SCID parameter in first entry".to_string())
    })?;

    // 1. Create a copy of the entry to manipulate
    let mut entry_copy = entry.clone();
    
    // 2. Remove the proof (not part of the SCID calculation)
    entry_copy.proof.clear();
    
    // 3. Replace the versionId with "{SCID}" placeholder
    entry_copy.version_id = "{SCID}".to_string();
    
    // 4. Replace all instances of the actual SCID with the placeholder in the entire entry
    let entry_json = serde_json::to_string(&entry_copy).map_err(|e| {
        ResolverError::Verification(format!("Failed to serialize entry for SCID verification: {}", e))
    })?;
    
    let entry_with_placeholders = entry_json.replace(scid, "{SCID}");
    
    // 5. Parse the modified entry back to a JSON value
    let entry_value: Value = serde_json::from_str(&entry_with_placeholders).map_err(|e| {
        ResolverError::Verification(format!("Failed to parse entry with placeholders: {}", e))
    })?;
    
    // 6. Apply JCS to get a canonical representation
    let canonical = to_canonical_json(&entry_value).map_err(|e| {
        ResolverError::Verification(format!("Failed to canonicalize JSON: {}", e))
    })?;
    
    // 7. Calculate the hash using SHA-256 (as specified for did:webvh 0.5)
    let calculated_scid = hash_to_base58btc(canonical.as_bytes())?;
    
    // 8. Compare with the provided SCID
    if calculated_scid != *scid {
        return Err(ResolverError::Verification(format!(
            "SCID verification failed: calculated {} but found {}",
            calculated_scid, scid
        )));
    }
    
    Ok(())
}

/// Verify the entry hash within a versionId
///
/// The entry hash is generated as:
/// base58btc(multihash(JCS(entry with versionId set to predecessor's versionId), <hash algorithm>))
pub fn verify_entry_hash(
    entry: &DIDLogEntry,
    prev_version_id: Option<&str>
) -> Result<()> {
    // Extract the version number and entry hash from the versionId
    let version_parts: Vec<&str> = entry.version_id.split('-').collect();
    if version_parts.len() != 2 {
        return Err(ResolverError::Verification(format!(
            "Invalid versionId format: {}", entry.version_id
        )));
    }
    
    let entry_hash = version_parts[1];
    
    // Create a copy of the entry to manipulate
    let mut entry_copy = entry.clone();
    
    // Remove the proof (not part of the hash calculation)
    entry_copy.proof.clear();
    
    // Set the versionId to the predecessor's versionId
    // For the first entry, this is the SCID
    // For subsequent entries, this is the previous entry's versionId
    entry_copy.version_id = match prev_version_id {
        Some(id) => id.to_string(),
        None => {
            // If no previous versionId is provided (for the first entry),
            // use the SCID from parameters
            entry_copy.parameters.scid.as_ref().ok_or_else(|| {
                ResolverError::Verification("Missing SCID for first entry hash verification".to_string())
            })?.clone()
        }
    };
    
    // Apply JCS to get a canonical representation
    let entry_json = serde_json::to_value(entry_copy).map_err(|e| {
        ResolverError::Verification(format!("Failed to convert entry to JSON: {}", e))
    })?;
    
    let canonical = to_canonical_json(&entry_json).map_err(|e| {
        ResolverError::Verification(format!("Failed to canonicalize JSON: {}", e))
    })?;
    
    // Calculate the hash using SHA-256 (as specified for did:webvh 0.5)
    let calculated_hash = hash_to_base58btc(canonical.as_bytes())?;
    
    // Compare with the provided hash
    if calculated_hash != entry_hash {
        return Err(ResolverError::Verification(format!(
            "Entry hash verification failed: calculated {} but found {}",
            calculated_hash, entry_hash
        )));
    }
    
    Ok(())
}

/// Verify the SCID and all entry hashes in a DID log
pub fn verify_did_log_integrity(entries: &[DIDLogEntry]) -> Result<()> {
    if entries.is_empty() {
        return Err(ResolverError::Verification("Empty DID log".to_string()));
    }
    
    // Verify the SCID of the first entry
    verify_scid(&entries[0])?;
    
    // Verify the entry hash of each entry
    for (i, entry) in entries.iter().enumerate() {
        let prev_version_id = if i == 0 {
            None // First entry uses SCID
        } else {
            Some(entries[i-1].version_id.as_str())
        };
        
        verify_entry_hash(entry, prev_version_id)?;
    }
    
    Ok(())
}

/// Hash a multikey representation for pre-rotation verification
pub fn hash_multikey(multikey: &str) -> Result<String> {
    // For pre-rotation, we hash the multikey directly
    let hash = hash_to_base58btc(multikey.as_bytes())?;
    Ok(hash)
}

/// Verify pre-rotation key hashes
///
/// Checks that each key in update_keys has its hash in the previous next_key_hashes array
pub fn verify_prerotation(
    update_keys: &[String],
    prev_next_key_hashes: &[String]
) -> Result<()> {
    // For each update key, check if its hash is in the previous next_key_hashes
    for key in update_keys {
        let key_hash = hash_multikey(key)?;
        
        if !prev_next_key_hashes.contains(&key_hash) {
            return Err(ResolverError::Verification(format!(
                "Pre-rotation verification failed: hash of key {} not found in previous nextKeyHashes",
                key
            )));
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Proof;
    
    #[test]
    fn test_hash_to_base58btc() {
        let data = b"test data";
        let hash = hash_to_base58btc(data).unwrap();
        
        // The hash should be a non-empty string
        assert!(!hash.is_empty());
        
        // The same data should always produce the same hash
        let hash2 = hash_to_base58btc(data).unwrap();
        assert_eq!(hash, hash2);
        
        // Different data should produce different hashes
        let data2 = b"different data";
        let hash3 = hash_to_base58btc(data2).unwrap();
        assert_ne!(hash, hash3);
    }
    
    #[test]
    fn test_verify_entry_hash_with_simple_data() {
        // Create a simple entry with a known hash
        let mut entry = DIDLogEntry {
            version_id: "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz".to_string(),
            version_time: "2024-09-26T23:22:26Z".to_string(),
            parameters: Parameters {
                method: Some("did:webvh:0.5".to_string()),
                scid: Some("QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ".to_string()),
                update_keys: Some(vec!["z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R".to_string()]),
                ..Parameters::default()
            },
            state: json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:domain.example"
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
        
        // Calculate the hash for this entry manually to test
        let mut entry_copy = entry.clone();
        entry_copy.proof.clear();
        entry_copy.version_id = "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ".to_string();
        
        let entry_json = serde_json::to_value(entry_copy).unwrap();
        let canonical = to_canonical_json(&entry_json).unwrap();
        let calculated_hash = hash_to_base58btc(canonical.as_bytes()).unwrap();
        
        // Update the entry to use our calculated hash
        entry.version_id = format!("1-{}", calculated_hash);
        
        // Now verify it - this should pass
        let result = verify_entry_hash(&entry, None);
        assert!(result.is_ok(), "Entry hash verification failed: {:?}", result);
    }
    
    // Additional tests would be added for:
    // - SCID verification
    // - Multi-entry log integrity verification
    // - Pre-rotation verification
    // - Edge cases and error handling
}