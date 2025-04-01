//! Module for handling DID URL parsing and transformations.
//! 
//! This module implements the DID-to-HTTPS transformations as defined in the did:webvh specification,
//! which builds upon the did:web transformation with the addition of the SCID.

use crate::error::{ResolverError, Result};
use std::fmt;
use url::Url;

/// Type of DID URL path resolution
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DIDUrlType {
    /// Regular DID resolution (no path)
    DIDResolution,
    /// Whois endpoint (/whois)
    Whois,
    /// Path-based resolution
    Path(String),
}

/// A parsed did:webvh URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DIDUrl {
    /// The full DID URL
    pub did_url: String,
    /// The SCID part of the DID
    pub scid: String,
    /// The domain part of the DID
    pub domain: String,
    /// Optional port number
    pub port: Option<u16>,
    /// Optional path segments in the DID
    pub path_segments: Vec<String>,
    /// Optional query parameters
    pub query: Option<String>,
    /// Optional fragment
    pub fragment: Option<String>,
    /// The type of DID URL resolution needed
    pub url_type: DIDUrlType,
}

impl fmt::Display for DIDUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut result = format!("did:webvh:{}:{}", self.scid, self.domain);
        
        // Add port if present
        if let Some(port) = self.port {
            result.push_str(&format!("%3A{}", port));
        }
        
        // Add path segments if present
        for segment in &self.path_segments {
            result.push_str(&format!(":{}", segment));
        }
        
        // Add query if present
        if let Some(query) = &self.query {
            result.push_str(&format!("?{}", query));
        }
        
        // Add fragment if present
        if let Some(fragment) = &self.fragment {
            result.push_str(&format!("#{}", fragment));
        }
        
        write!(f, "{}", result)
    }
}

impl DIDUrl {
    /// Parse a did:webvh URL string into a DIDUrl struct.
    pub fn parse(did_url: &str) -> Result<Self> {
        // Basic validation first
        if !did_url.starts_with("did:webvh:") {
            return Err(ResolverError::DIDParsing(
                "DID URL must start with 'did:webvh:'".to_string(),
            ));
        }
        
        // Extract method-specific identifier (everything after did:webvh:)
        let method_specific_id = &did_url[10..];
        
        // Split on # to separate fragment
        let (before_fragment, fragment) = match method_specific_id.split_once('#') {
            Some((before, fragment)) => (before, Some(fragment.to_string())),
            None => (method_specific_id, None),
        };
        
        // Split on ? to separate query
        let (before_query, query) = match before_fragment.split_once('?') {
            Some((before, query)) => (before, Some(query.to_string())),
            None => (before_fragment, None),
        };
        
        // Now process the method-specific identifier
        let segments: Vec<&str> = before_query.split(':').collect();
        
        if segments.len() < 2 {
            return Err(ResolverError::DIDParsing(
                "DID URL must contain at least SCID and domain segments".to_string(),
            ));
        }
        
        let scid = segments[0].to_string();
        let domain_with_port = segments[1];
        
        // Process domain and port
        let (domain, port) = if domain_with_port.contains("%3A") {
            let parts: Vec<&str> = domain_with_port.split("%3A").collect();
            if parts.len() != 2 {
                return Err(ResolverError::DIDParsing(
                    "Invalid port specification".to_string(),
                ));
            }
            let port = match parts[1].parse::<u16>() {
                Ok(p) => p,
                Err(_) => {
                    return Err(ResolverError::DIDParsing(
                        "Invalid port number".to_string(),
                    ))
                }
            };
            (parts[0].to_string(), Some(port))
        } else {
            (domain_with_port.to_string(), None)
        };
        
        // Process path segments (if any)
        let path_segments = if segments.len() > 2 {
            segments[2..].iter().map(|s| s.to_string()).collect()
        } else {
            Vec::new()
        };
        
        // Determine URL type based on path segments and query
        let url_type = if let Some(query_str) = &query {
            // Handle service and relativeRef query parameters
            if query_str.contains("service=files") && query_str.contains("relativeRef=") {
                // Extract the relative ref from the query
                if let Some(relative_ref) = query_str
                    .split('&')
                    .find(|s| s.starts_with("relativeRef="))
                {
                    let path = relative_ref
                        .strip_prefix("relativeRef=")
                        .unwrap_or("")
                        .to_string();
                    DIDUrlType::Path(path)
                } else {
                    DIDUrlType::DIDResolution
                }
            } else {
                DIDUrlType::DIDResolution
            }
        } else if !path_segments.is_empty() && path_segments.last().unwrap() == "whois" {
            // Check if the last path segment is "whois"
            DIDUrlType::Whois
        } else {
            DIDUrlType::DIDResolution
        };
        
        Ok(DIDUrl {
            did_url: did_url.to_string(),
            scid,
            domain,
            port,
            path_segments,
            query,
            fragment,
            url_type,
        })
    }
    
    /// Transform the DID URL to an HTTPS URL according to the did:webvh specification.
    ///
    /// # Note
    /// This implementation does not yet handle internationalized domain names (IDNs)
    /// according to IDNA 2008 (RFC5895). When dealing with IDNs, additional
    /// processing will be required, including Unicode normalization and Punycode encoding.
    /// The did:webvh spec explicitly references this requirement in section 5.1.5.
    pub fn to_https_url(&self) -> Result<Url> {
        // Step 1: Start building the base URL
        let mut base_url = format!("https://{}", self.domain);
        
        // Step 2: Add port if present
        if let Some(port) = self.port {
            base_url.push_str(&format!(":{}", port));
        }
        
        // Step 3: Determine path based on URL type
        let path = match &self.url_type {
            DIDUrlType::DIDResolution => {
                if self.path_segments.is_empty() {
                    // If no path segments, use /.well-known/did.jsonl
                    "/.well-known/did.jsonl".to_string()
                } else {
                    // Otherwise, use /path/to/did.jsonl
                    format!("/{}/did.jsonl", self.path_segments.join("/"))
                }
            }
            DIDUrlType::Whois => {
                if self.path_segments.is_empty() {
                    // If no path segments, use /whois.vp
                    "/whois.vp".to_string()
                } else {
                    // Remove the last "whois" segment and use that path for whois.vp
                    let base_path = if self.path_segments.len() > 1 {
                        self.path_segments[..self.path_segments.len() - 1].join("/")
                    } else {
                        // If only "whois" is present, use empty base path
                        "".to_string()
                    };
                    
                    if base_path.is_empty() {
                        "/whois.vp".to_string()
                    } else {
                        format!("/{}/whois.vp", base_path)
                    }
                }
            }
            DIDUrlType::Path(ref path) => {
                // Remove any leading slash
                let clean_path = path.trim_start_matches('/');
                
                if self.path_segments.is_empty() {
                    format!("/{}", clean_path)
                } else {
                    format!("/{}/{}", self.path_segments.join("/"), clean_path)
                }
            }
        };
        
        // Combine base URL and path
        let url_str = format!("{}{}", base_url, path);
        
        // Parse into a URL
        let mut url = match Url::parse(&url_str) {
            Ok(url) => url,
            Err(e) => return Err(ResolverError::Url(e)),
        };
        
        // Add query parameters if present and not already processed as part of the URL type
        if let Some(query) = &self.query {
            if !matches!(self.url_type, DIDUrlType::Path(_)) {
                url.set_query(Some(query));
            }
        }
        
        // Add fragment if present
        if let Some(fragment) = &self.fragment {
            url.set_fragment(Some(fragment));
        }
        
        Ok(url)
    }
    
    /// Generate the URL for fetching witness proofs.
    pub fn to_witness_url(&self) -> Result<Url> {
        // First, get the base URL for DID resolution
        let did_url = self.to_https_url()?;
        
        // Replace did.jsonl with did-witness.json
        let witness_url_str = did_url
            .as_str()
            .replace("did.jsonl", "did-witness.json");
        
        // Parse into a URL
        match Url::parse(&witness_url_str) {
            Ok(url) => Ok(url),
            Err(e) => Err(ResolverError::Url(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_did_url() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com";
        let parsed = DIDUrl::parse(did_url).unwrap();
        
        assert_eq!(parsed.scid, "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.port, None);
        assert!(parsed.path_segments.is_empty());
        assert_eq!(parsed.query, None);
        assert_eq!(parsed.fragment, None);
        assert_eq!(parsed.url_type, DIDUrlType::DIDResolution);
    }

    #[test]
    fn test_parse_did_url_with_port() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com%3A3000";
        let parsed = DIDUrl::parse(did_url).unwrap();
        
        assert_eq!(parsed.scid, "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.port, Some(3000));
        assert!(parsed.path_segments.is_empty());
        assert_eq!(parsed.query, None);
        assert_eq!(parsed.fragment, None);
        assert_eq!(parsed.url_type, DIDUrlType::DIDResolution);
    }

    #[test]
    fn test_parse_did_url_with_path() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com:dids:issuer";
        let parsed = DIDUrl::parse(did_url).unwrap();
        
        assert_eq!(parsed.scid, "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.port, None);
        assert_eq!(parsed.path_segments, vec!["dids", "issuer"]);
        assert_eq!(parsed.query, None);
        assert_eq!(parsed.fragment, None);
        assert_eq!(parsed.url_type, DIDUrlType::DIDResolution);
    }

    #[test]
    fn test_parse_did_url_with_whois() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com:whois";
        let parsed = DIDUrl::parse(did_url).unwrap();
        
        assert_eq!(parsed.scid, "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.port, None);
        assert_eq!(parsed.path_segments, vec!["whois"]);
        assert_eq!(parsed.query, None);
        assert_eq!(parsed.fragment, None);
        assert_eq!(parsed.url_type, DIDUrlType::Whois);
    }

    #[test]
    fn test_parse_did_url_with_fragment() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com#key-1";
        let parsed = DIDUrl::parse(did_url).unwrap();
        
        assert_eq!(parsed.scid, "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.port, None);
        assert!(parsed.path_segments.is_empty());
        assert_eq!(parsed.query, None);
        assert_eq!(parsed.fragment, Some("key-1".to_string()));
        assert_eq!(parsed.url_type, DIDUrlType::DIDResolution);
    }

    #[test]
    fn test_parse_did_url_with_query() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com?versionId=1-abc123";
        let parsed = DIDUrl::parse(did_url).unwrap();
        
        assert_eq!(parsed.scid, "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.port, None);
        assert!(parsed.path_segments.is_empty());
        assert_eq!(parsed.query, Some("versionId=1-abc123".to_string()));
        assert_eq!(parsed.fragment, None);
        assert_eq!(parsed.url_type, DIDUrlType::DIDResolution);
    }

    #[test]
    fn test_parse_did_url_with_relative_ref() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com?service=files&relativeRef=/path/to/resource";
        let parsed = DIDUrl::parse(did_url).unwrap();
        
        assert_eq!(parsed.scid, "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.port, None);
        assert!(parsed.path_segments.is_empty());
        assert_eq!(parsed.query, Some("service=files&relativeRef=/path/to/resource".to_string()));
        assert_eq!(parsed.fragment, None);
        
        // Check that the URL type is correctly identified as Path
        if let DIDUrlType::Path(path) = &parsed.url_type {
            assert_eq!(path, "/path/to/resource");
        } else {
            panic!("Expected DIDUrlType::Path but got {:?}", parsed.url_type);
        }
    }

    #[test]
    fn test_basic_https_url_transformation() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com";
        let parsed = DIDUrl::parse(did_url).unwrap();
        let https_url = parsed.to_https_url().unwrap();
        
        assert_eq!(https_url.as_str(), "https://example.com/.well-known/did.jsonl");
    }

    #[test]
    fn test_https_url_transformation_with_port() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com%3A3000";
        let parsed = DIDUrl::parse(did_url).unwrap();
        let https_url = parsed.to_https_url().unwrap();
        
        assert_eq!(https_url.as_str(), "https://example.com:3000/.well-known/did.jsonl");
    }

    #[test]
    fn test_https_url_transformation_with_path() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com:dids:issuer";
        let parsed = DIDUrl::parse(did_url).unwrap();
        let https_url = parsed.to_https_url().unwrap();
        
        assert_eq!(https_url.as_str(), "https://example.com/dids/issuer/did.jsonl");
    }

    #[test]
    fn test_https_url_transformation_with_whois() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com:whois";
        let parsed = DIDUrl::parse(did_url).unwrap();
        let https_url = parsed.to_https_url().unwrap();
        
        assert_eq!(https_url.as_str(), "https://example.com/whois.vp");
    }

    #[test]
    fn test_https_url_transformation_with_query() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com?versionId=1-abc123";
        let parsed = DIDUrl::parse(did_url).unwrap();
        let https_url = parsed.to_https_url().unwrap();
        
        assert_eq!(https_url.as_str(), "https://example.com/.well-known/did.jsonl?versionId=1-abc123");
    }

    #[test]
    fn test_witness_url_transformation() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com";
        let parsed = DIDUrl::parse(did_url).unwrap();
        let witness_url = parsed.to_witness_url().unwrap();
        
        assert_eq!(witness_url.as_str(), "https://example.com/.well-known/did-witness.json");
    }

    #[test]
    fn test_parse_did_url_with_multiple_path_segments_including_whois() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com:path1:path2:whois";
        let parsed = DIDUrl::parse(did_url).unwrap();
        
        assert_eq!(parsed.scid, "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.port, None);
        assert_eq!(parsed.path_segments, vec!["path1", "path2", "whois"]);
        assert_eq!(parsed.query, None);
        assert_eq!(parsed.fragment, None);
        
        // The last segment is "whois", so it should be identified as Whois
        assert_eq!(parsed.url_type, DIDUrlType::Whois);
        
        // Verify URL transformation
        let https_url = parsed.to_https_url().unwrap();
        assert_eq!(https_url.as_str(), "https://example.com/path1/path2/whois.vp");
    }

    #[test]
    fn test_parse_did_url_with_whois_not_as_last_segment() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com:whois:path1";
        let parsed = DIDUrl::parse(did_url).unwrap();
        
        assert_eq!(parsed.scid, "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.port, None);
        assert_eq!(parsed.path_segments, vec!["whois", "path1"]);
        assert_eq!(parsed.query, None);
        assert_eq!(parsed.fragment, None);
        
        // When "whois" is not the last segment, it should be treated as a regular path segment
        assert_eq!(parsed.url_type, DIDUrlType::DIDResolution);
        
        // Verify URL transformation (should be treated as a regular DID resolution)
        let https_url = parsed.to_https_url().unwrap();
        assert_eq!(https_url.as_str(), "https://example.com/whois/path1/did.jsonl");
    }

    #[test]
    fn test_parse_did_url_with_query_parameters_and_path_resolution() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com:path1:path2?service=files&relativeRef=resource.json";
        let parsed = DIDUrl::parse(did_url).unwrap();
        
        assert_eq!(parsed.scid, "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.port, None);
        assert_eq!(parsed.path_segments, vec!["path1", "path2"]);
        assert_eq!(parsed.query, Some("service=files&relativeRef=resource.json".to_string()));
        assert_eq!(parsed.fragment, None);
        
        // Check URL type is correctly identified as Path
        if let DIDUrlType::Path(path) = &parsed.url_type {
            assert_eq!(path, "resource.json");
        } else {
            panic!("Expected DIDUrlType::Path but got {:?}", parsed.url_type);
        }
        
        // Verify URL transformation for path-based resolution
        let https_url = parsed.to_https_url().unwrap();
        assert_eq!(https_url.as_str(), "https://example.com/path1/path2/resource.json");
    }

    #[test]
    fn test_parse_did_url_with_query_parameters_and_fragment() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com?versionId=1-abc123#key-1";
        let parsed = DIDUrl::parse(did_url).unwrap();
        
        assert_eq!(parsed.scid, "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.port, None);
        assert!(parsed.path_segments.is_empty());
        assert_eq!(parsed.query, Some("versionId=1-abc123".to_string()));
        assert_eq!(parsed.fragment, Some("key-1".to_string()));
        
        // Verify URL transformation with both query parameters and fragment
        let https_url = parsed.to_https_url().unwrap();
        assert_eq!(https_url.as_str(), "https://example.com/.well-known/did.jsonl?versionId=1-abc123#key-1");
    }

    #[test]
    fn test_parse_path_resolution_with_encoded_characters() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com?service=files&relativeRef=path%20with%20spaces.json";
        let parsed = DIDUrl::parse(did_url).unwrap();
        
        // Check URL type is correctly identified as Path with encoded characters
        if let DIDUrlType::Path(path) = &parsed.url_type {
            assert_eq!(path, "path%20with%20spaces.json");
        } else {
            panic!("Expected DIDUrlType::Path but got {:?}", parsed.url_type);
        }
        
        // Verify URL transformation preserves encoded characters
        let https_url = parsed.to_https_url().unwrap();
        assert_eq!(https_url.as_str(), "https://example.com/path%20with%20spaces.json");
    }

    #[test]
    fn test_parse_did_url_with_complex_path_and_witness_url() {
        let did_url = "did:webvh:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:example.com:org:dept:users";
        let parsed = DIDUrl::parse(did_url).unwrap();
        
        assert_eq!(parsed.scid, "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ");
        assert_eq!(parsed.path_segments, vec!["org", "dept", "users"]);
        
        // Verify DID resolution URL
        let https_url = parsed.to_https_url().unwrap();
        assert_eq!(https_url.as_str(), "https://example.com/org/dept/users/did.jsonl");
        
        // Verify witness URL transformation
        let witness_url = parsed.to_witness_url().unwrap();
        assert_eq!(witness_url.as_str(), "https://example.com/org/dept/users/did-witness.json");
    }
}