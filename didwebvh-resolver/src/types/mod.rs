//! Core data types for the didwebvh-resolver crate.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// A DID Log Entry representing one version of a DID Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDLogEntry {
    /// Format: "<version-number>-<entry-hash>"
    #[serde(rename = "versionId")]
    pub version_id: String,
    
    /// ISO8601 timestamp
    #[serde(rename = "versionTime")]
    pub version_time: String,
    
    /// DID method parameters
    pub parameters: Parameters,
    
    /// The DID Document as a JSON value
    pub state: Value,
    
    /// Data Integrity proofs
    pub proof: Vec<Proof>,
}

/// Parameters that control DID processing
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Parameters {
    /// Specification version (e.g., "did:webvh:0.5")
    pub method: Option<String>,
    
    /// Self-certifying identifier
    pub scid: Option<String>,
    
    /// Keys authorized for updates
    #[serde(rename = "updateKeys")]
    pub update_keys: Option<Vec<String>>,
    
    /// Pre-rotation key hashes
    #[serde(rename = "nextKeyHashes")]
    pub next_key_hashes: Option<Vec<String>>,
    
    /// DID portability flag
    pub portable: Option<bool>,
    
    /// Witness configuration
    pub witness: Option<WitnessConfig>,
    
    /// Deactivation status
    pub deactivated: Option<bool>,
    
    /// Cache TTL in seconds
    pub ttl: Option<u64>,
}

/// Witness configuration for collaborative verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessConfig {
    /// Number of witnesses required
    pub threshold: u64,
    
    /// List of witnesses
    pub witnesses: Vec<Witness>,
}

/// A witness entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    /// DID of the witness
    pub id: String,
}

/// Proof using Data Integrity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Type of proof (e.g., "DataIntegrityProof")
    #[serde(rename = "type")]
    pub type_: String,
    
    /// Cryptosuite used (e.g., "eddsa-jcs-2022")
    pub cryptosuite: String,
    
    /// The key used
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    
    /// Creation timestamp
    pub created: String,
    
    /// Purpose (e.g., "assertionMethod")
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    
    /// The actual proof value
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

/// Witness proof file structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessProofs {
    /// List of witness proof entries
    pub entries: Vec<WitnessProofEntry>,
}

/// A witness proof entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessProofEntry {
    /// Version ID the proofs apply to
    #[serde(rename = "versionId")]
    pub version_id: String,
    
    /// List of witness proofs
    pub proof: Vec<Proof>,
}

/// DID Resolution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDResolutionResult {
    /// The resolved DID Document
    #[serde(rename = "didDocument")]
    pub did_document: Value,
    
    /// Metadata about the DID Document
    #[serde(rename = "didDocumentMetadata")]
    pub did_document_metadata: DIDDocumentMetadata,
    
    /// Metadata about the resolution process
    #[serde(rename = "didResolutionMetadata")]
    pub did_resolution_metadata: DIDResolutionMetadata,
}

/// Metadata about the DID Document
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DIDDocumentMetadata {
    /// When the DID Document was created
    pub created: Option<String>,
    
    /// When the DID Document was last updated
    pub updated: Option<String>,
    
    /// Whether the DID is deactivated
    pub deactivated: Option<bool>,
    
    /// The version ID of the DID Document
    #[serde(rename = "versionId")]
    pub version_id: Option<String>,
    
    /// The version ID of the next DID Document
    #[serde(rename = "nextVersionId")]
    pub next_version_id: Option<String>,
    
    /// Other identifiers that refer to the same subject
    #[serde(rename = "equivalentId")]
    pub equivalent_id: Option<Vec<String>>,
    
    /// The canonical ID for the DID
    #[serde(rename = "canonicalId")]
    pub canonical_id: Option<String>,
}

/// Metadata about the resolution process
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DIDResolutionMetadata {
    /// The content type of the resolved DID Document
    #[serde(rename = "contentType")]
    pub content_type: String,
    
    /// Error encountered during resolution, if any
    pub error: Option<String>,
    
    /// Any additional properties
    #[serde(flatten)]
    pub additional_properties: HashMap<String, Value>,
}

/// Options for DID resolution
#[derive(Debug, Clone, Default)]
pub struct ResolutionOptions {
    /// Specific version ID to resolve
    pub version_id: Option<String>,
    
    /// Specific version time to resolve
    pub version_time: Option<String>,
    
    /// Specific version number to resolve
    pub version_number: Option<u64>,
    
    /// Accept header to use for HTTP requests
    pub accept: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_did_log_entry_serialization() {
        let entry = DIDLogEntry {
            version_id: "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz".to_string(),
            version_time: "2024-09-26T23:22:26Z".to_string(),
            parameters: Parameters {
                method: Some("did:webvh:0.5".to_string()),
                scid: Some("QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ".to_string()),
                update_keys: Some(vec!["z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R".to_string()]),
                next_key_hashes: Some(vec!["QmXC3vvStVVzCBHRHGUsksGxn6BNmkdETXJGDBXwNSTL33".to_string()]),
                portable: Some(false),
                witness: None,
                deactivated: Some(false),
                ttl: None,
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

        // Serialize to JSON
        let json_str = serde_json::to_string(&entry).expect("Failed to serialize DIDLogEntry");
        
        // Deserialize back to a DIDLogEntry
        let deserialized: DIDLogEntry = serde_json::from_str(&json_str).expect("Failed to deserialize DIDLogEntry");
        
        // Check that the deserialized entry matches the original
        assert_eq!(entry.version_id, deserialized.version_id);
        assert_eq!(entry.version_time, deserialized.version_time);
        assert_eq!(entry.parameters.method, deserialized.parameters.method);
        assert_eq!(entry.parameters.scid, deserialized.parameters.scid);
        assert_eq!(entry.parameters.update_keys, deserialized.parameters.update_keys);
        assert_eq!(entry.parameters.next_key_hashes, deserialized.parameters.next_key_hashes);
        
        // Just check that we have the same number of proofs
        assert_eq!(entry.proof.len(), deserialized.proof.len());
        
        // More detailed checks could be added
    }

    #[test]
    fn test_did_log_entry_deserialization_from_json_lines() {
        // This is a typical JSON Lines format DID log entry
        let json_str = r#"{"versionId": "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz", "versionTime": "2024-09-26T23:22:26Z", "parameters": {"prerotation": true, "updateKeys": ["z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R"], "nextKeyHashes": ["QmXC3vvStVVzCBHRHGUsksGxn6BNmkdETXJGDBXwNSTL33"], "method": "did:webvh:0.5", "scid": "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R#z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R", "created": "2024-09-26T23:22:26Z", "proofPurpose": "assertionMethod", "proofValue": "z2fPF6fMewtV15kji2N432R7RjmmFs8p7MiSHSTM9FoVmJPtc3JUuZ472pZKoWgZDuT75EDwkGmZbK8ZKVF55pXvx"}]}"#;
        
        // Deserialize the JSON string into a DIDLogEntry
        let entry: DIDLogEntry = serde_json::from_str(json_str).expect("Failed to deserialize DIDLogEntry");
        
        // Check some of the deserialized values
        assert_eq!(entry.version_id, "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz");
        assert_eq!(entry.version_time, "2024-09-26T23:22:26Z");
        assert_eq!(entry.parameters.method, Some("did:webvh:0.5".to_string()));
        assert_eq!(entry.parameters.scid, Some("QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ".to_string()));
        
        // Check that the proof was deserialized correctly
        assert_eq!(entry.proof.len(), 1);
        assert_eq!(entry.proof[0].type_, "DataIntegrityProof");
        assert_eq!(entry.proof[0].cryptosuite, "eddsa-jcs-2022");
        assert_eq!(entry.proof[0].proof_purpose, "assertionMethod");
    }
}