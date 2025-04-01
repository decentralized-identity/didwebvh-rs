//! Module for resolving did:webvh DIDs.
//! 
//! This module provides the main resolver implementation and related functionality.

use crate::error::{ResolverError, ResolutionError, Result, ResolutionResult};
use crate::http::HttpClient;
use crate::log::{DIDLog, fetch_and_parse_did_log};
use crate::types::{DIDResolutionResult, DIDResolutionMetadata, DIDDocumentMetadata, ResolutionOptions};
use crate::url::DIDUrl;
use serde_json::Value;
use std::sync::Arc;

/// Implementation of the did:webvh resolver
pub struct WebVHResolver<C: HttpClient> {
    http_client: Arc<C>,
}

impl<C: HttpClient> WebVHResolver<C> {
    /// Create a new WebVHResolver with the provided HTTP client
    pub fn new(http_client: C) -> Self {
        Self {
            http_client: Arc::new(http_client),
        }
    }
    
    /// Resolve a did:webvh DID
    pub async fn resolve(&self, did: &str, options: &ResolutionOptions) -> ResolutionResult<DIDResolutionResult> {
        // Parse the DID URL
        let did_url = DIDUrl::parse(did).map_err(|e| {
            ResolutionError::InvalidDID(format!("Invalid DID URL: {}", e))
        })?;
        
        // Fetch and parse the DID log
        let did_log = fetch_and_parse_did_log(Arc::clone(&self.http_client).as_ref(), &did_url).await
            .map_err(|e| match e {
                ResolverError::Http(msg) if msg.contains("not found") => {
                    ResolutionError::NotFound
                },
                _ => ResolutionError::InternalError(format!("Error fetching DID log: {}", e)),
            })?;
        
        // Find the requested entry based on resolution options
        let entry = if let Some(version_id) = &options.version_id {
            // Resolve by version ID
            did_log.get_entry_by_version_id(version_id)
                .ok_or_else(|| ResolutionError::NotFound)?
        } else if let Some(version_time) = &options.version_time {
            // Resolve by version time
            did_log.get_entry_by_version_time(version_time)
                .ok_or_else(|| ResolutionError::NotFound)?
        } else if let Some(version_number) = options.version_number {
            // Resolve by version number
            did_log.get_entry_by_version_number(version_number)
                .ok_or_else(|| ResolutionError::NotFound)?
        } else {
            // Default to latest entry
            did_log.latest_entry()
                .ok_or_else(|| ResolutionError::InternalError("DID log is empty".to_string()))?
        };
        
        // Extract the DID document from the entry
        let did_document = entry.state.clone();
        
        // Generate DID document metadata
        let did_document_metadata = did_log.generate_metadata(entry);
        
        // Create resolution metadata
        let mut did_resolution_metadata = DIDResolutionMetadata::default();
        did_resolution_metadata.content_type = "application/did+json".to_string();
        
        // Ensure the DID document has an ID that matches the resolved DID
        if let Some(id) = extract_did_id(&did_document) {
            if !is_did_match(&id, did) {
                // For portable DIDs, check if the resolved DID is in alsoKnownAs
                if did_log.active_parameters.portable.unwrap_or(false) {
                    if !is_did_in_also_known_as(&did_document, did) {
                        return Err(ResolutionError::InvalidDIDDocument(
                            format!("DID document ID {} does not match resolved DID {} and is not in alsoKnownAs", id, did)
                        ));
                    }
                } else {
                    return Err(ResolutionError::InvalidDIDDocument(
                        format!("DID document ID {} does not match resolved DID {}", id, did)
                    ));
                }
            }
        } else {
            return Err(ResolutionError::InvalidDIDDocument(
                "DID document is missing id property".to_string()
            ));
        }
        
        // Return the resolution result
        Ok(DIDResolutionResult {
            did_document,
            did_document_metadata,
            did_resolution_metadata,
        })
    }
}

/// Extract the DID ID from a DID document
fn extract_did_id(did_document: &Value) -> Option<String> {
    did_document.get("id")?.as_str().map(|s| s.to_string())
}

/// Check if a DID is in the alsoKnownAs array of a DID document
fn is_did_in_also_known_as(did_document: &Value, did: &str) -> bool {
    if let Some(Value::Array(aka)) = did_document.get("alsoKnownAs") {
        aka.iter().any(|v| {
            v.as_str().map_or(false, |s| s == did)
        })
    } else {
        false
    }
}

/// Check if two DIDs match (ignoring query and fragment)
fn is_did_match(did1: &str, did2: &str) -> bool {
    // Remove query and fragment for comparison
    let did1_base = did1.split(&['?', '#'][..]).next().unwrap_or(did1);
    let did2_base = did2.split(&['?', '#'][..]).next().unwrap_or(did2);
    
    did1_base == did2_base
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::tests::MockHttpClientMock;
    use mockall::predicate::{self, *};
    
    #[test]
    fn test_extract_did_id() {
        let did_document = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com"
        });
        
        let id = extract_did_id(&did_document).unwrap();
        assert_eq!(id, "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com");
        
        let empty_doc = serde_json::json!({});
        assert!(extract_did_id(&empty_doc).is_none());
    }
    
    #[test]
    fn test_is_did_in_also_known_as() {
        let did_document = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com",
            "alsoKnownAs": [
                "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:old-domain.com",
                "did:web:example.com"
            ]
        });
        
        assert!(is_did_in_also_known_as(&did_document, "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:old-domain.com"));
        assert!(is_did_in_also_known_as(&did_document, "did:web:example.com"));
        assert!(!is_did_in_also_known_as(&did_document, "did:web:other.com"));
        
        let no_aka_doc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com"
        });
        
        assert!(!is_did_in_also_known_as(&no_aka_doc, "did:web:example.com"));
    }
    
    #[test]
    fn test_is_did_match() {
        // Basic matching
        assert!(is_did_match(
            "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com",
            "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com"
        ));
        
        // Different DIDs
        assert!(!is_did_match(
            "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com",
            "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:other.com"
        ));
        
        // Matching with query/fragment ignored
        assert!(is_did_match(
            "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com?versionId=1",
            "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com#key-1"
        ));
    }
    
    #[tokio::test]
    async fn test_resolver_basic_resolution() {
        let mut mock_client = MockHttpClientMock::new();
        
        // Set up the mock to return a valid DID log
        let log_str = r#"{"versionId": "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz", "versionTime": "2024-09-26T23:22:26Z", "parameters": {"method": "did:webvh:0.5", "scid": "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ", "updateKeys": ["z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R"]}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R#z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R", "created": "2024-09-26T23:22:26Z", "proofPurpose": "assertionMethod", "proofValue": "z2fPF6fMewtV15kji2N432R7RjmmFs8p7MiSHSTM9FoVmJPtc3JUuZ472pZKoWgZDuT75EDwkGmZbK8ZKVF55pXvx"}]}"#;
        
        // Set up the mock expectation for any URL with did.jsonl
        mock_client
            .expect_get()
            .with(predicate::function(|url: &str| url.contains("did.jsonl")), eq(None))
            .times(1)
            .returning(move |_, _| Ok(log_str.as_bytes().to_vec()));
        
        // Create the resolver
        let resolver = WebVHResolver::new(mock_client);
        
        // Resolve the DID
        let result = resolver.resolve(
            "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com", 
            &ResolutionOptions::default()
        ).await;
        
        assert!(result.is_ok());
        
        let resolution_result = result.unwrap();
        assert_eq!(
            resolution_result.did_document.get("id").unwrap().as_str().unwrap(),
            "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com"
        );
        assert_eq!(
            resolution_result.did_document_metadata.version_id,
            Some("1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz".to_string())
        );
        assert_eq!(
            resolution_result.did_resolution_metadata.content_type,
            "application/did+json"
        );
    }
}