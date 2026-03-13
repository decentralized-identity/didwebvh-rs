//! Implicit service injection for WebVH DID Documents.
//!
//! The WebVH specification requires two implicit services on every resolved
//! DID Document:
//! - **`#files`** — a `relativeRef` service pointing to the DID's base HTTP URL
//! - **`#whois`** — a `LinkedVerifiablePresentation` service pointing to `whois.vp`
//!
//! This module checks a resolved DID Document and appends any missing implicit
//! services. Existing services with matching `#files` or `#whois` fragment IDs
//! are preserved (not duplicated).

use crate::{DIDWebVHError, ensure_object_mut, url::WebVHURL};
use serde_json::{Value, json};

// Checks and adds implicit services if not present (#files and #whois)
pub(crate) fn update_implicit_services(
    services: Option<&Value>,
    new_state: &mut Value,
    did_id: &str,
) -> Result<(), DIDWebVHError> {
    let url = WebVHURL::parse_did_url(did_id)?;

    let Some(services) = services else {
        // There are no services, add the implicit services
        ensure_object_mut(new_state)?.insert(
            "service".to_string(),
            Value::Array(vec![
                get_service_whois(did_id, &url)?,
                get_service_files(did_id, &url)?,
            ]),
        );
        return Ok(());
    };

    if let Some(services) = services.as_array() {
        let mut has_whois = false;
        let mut has_files = false;

        for service in services {
            if let Some(id) = service.get("id").and_then(|v| v.as_str()) {
                if id.ends_with("#whois") {
                    has_whois = true;
                } else if id.ends_with("#files") {
                    has_files = true;
                }
            }
        }

        let mut new_services = services.clone();

        if !has_whois {
            new_services.push(get_service_whois(did_id, &url)?);
        }
        if !has_files {
            new_services.push(get_service_files(did_id, &url)?);
        }

        ensure_object_mut(new_state)?.insert("service".to_string(), Value::Array(new_services));
    } else {
        return Err(DIDWebVHError::DIDError(
            "services is not an array".to_string(),
        ));
    }

    Ok(())
}

/// id: did:web ID
/// url: did:webvh URL
fn get_service_whois(id: &str, url: &WebVHURL) -> Result<Value, DIDWebVHError> {
    Ok(json!({
        "@context": "https://identity.foundation/linked-vp/contexts/v1",
        "id": ([id, "#whois"].concat()),
        "type": "LinkedVerifiablePresentation",
        "serviceEndpoint": url.get_http_whois_url()?
    }))
}

/// id: did:web ID
/// url: did:webvh URL
fn get_service_files(id: &str, url: &WebVHURL) -> Result<Value, DIDWebVHError> {
    Ok(json!({
        "id": ([id,"#files"].concat()),
        "type": "relativeRef",
        "serviceEndpoint": url.get_http_files_url()?
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Tests that when a DID Document has no services defined, both implicit
    /// services (#whois and #files) are automatically added.
    /// Expected: The resulting document should contain exactly 2 services.
    /// This matters because the WebVH spec requires these implicit services
    /// for DID discoverability (whois) and file access (files).
    #[test]
    fn test_no_services_adds_both() {
        let mut state = json!({"id": "did:webvh:scid123:example.com"});
        update_implicit_services(None, &mut state, "did:webvh:scid123:example.com").unwrap();
        let services = state["service"].as_array().unwrap();
        assert_eq!(services.len(), 2);
        // Check one ends with #whois and one with #files
        let ids: Vec<&str> = services.iter().map(|s| s["id"].as_str().unwrap()).collect();
        assert!(ids.iter().any(|id| id.ends_with("#whois")));
        assert!(ids.iter().any(|id| id.ends_with("#files")));
    }

    /// Tests that when a DID Document has existing custom services but is missing
    /// both implicit services, #whois and #files are appended alongside the custom service.
    /// Expected: The resulting document should contain 3 services (1 custom + 2 implicit).
    /// This matters because implicit services must coexist with user-defined services
    /// without overwriting them during DID resolution.
    #[test]
    fn test_existing_services_adds_missing() {
        let existing = json!([{"id": "did:webvh:scid123:example.com#custom", "type": "Custom", "serviceEndpoint": "https://example.com"}]);
        let mut state = json!({"id": "did:webvh:scid123:example.com", "service": existing});
        let services_ref = state.get("service").cloned();
        update_implicit_services(
            services_ref.as_ref(),
            &mut state,
            "did:webvh:scid123:example.com",
        )
        .unwrap();
        let services = state["service"].as_array().unwrap();
        assert_eq!(services.len(), 3); // original + whois + files
    }

    /// Tests that when a DID Document already has both #whois and #files services,
    /// no duplicate services are added.
    /// Expected: The service array remains at exactly 2 entries.
    /// This matters because duplicate implicit services would produce an invalid
    /// DID Document and could confuse resolvers or verifiers.
    #[test]
    fn test_both_services_exist_no_change() {
        let existing = json!([
            {"id": "did:webvh:scid123:example.com#whois", "type": "LinkedVerifiablePresentation", "serviceEndpoint": "https://example.com/whois.vp"},
            {"id": "did:webvh:scid123:example.com#files", "type": "relativeRef", "serviceEndpoint": "https://example.com/"}
        ]);
        let mut state = json!({"id": "did:webvh:scid123:example.com", "service": existing});
        let services_ref = state.get("service").cloned();
        update_implicit_services(
            services_ref.as_ref(),
            &mut state,
            "did:webvh:scid123:example.com",
        )
        .unwrap();
        let services = state["service"].as_array().unwrap();
        assert_eq!(services.len(), 2); // no additions
    }

    /// Tests that passing a non-array value as the services field produces an error.
    /// Expected: The function returns an Err result.
    /// This matters because the DID Document spec requires services to be an array,
    /// and graceful error handling prevents panics during resolution of malformed documents.
    #[test]
    fn test_services_not_array_error() {
        let services = json!("not-an-array");
        let mut state = json!({"id": "did:webvh:scid123:example.com"});
        let result =
            update_implicit_services(Some(&services), &mut state, "did:webvh:scid123:example.com");
        assert!(result.is_err());
    }

    /// Tests that when a DID Document has only the #whois service, the missing
    /// #files service is added while preserving the existing #whois service.
    /// Expected: The resulting document has 2 services, including one ending with #files.
    /// This matters because partial implicit service coverage must be detected and
    /// completed to ensure full spec compliance during resolution.
    #[test]
    fn test_only_whois_adds_files() {
        let existing = json!([
            {"id": "did:webvh:scid123:example.com#whois", "type": "LinkedVerifiablePresentation", "serviceEndpoint": "https://example.com/whois.vp"}
        ]);
        let mut state = json!({"id": "did:webvh:scid123:example.com", "service": existing});
        let services_ref = state.get("service").cloned();
        update_implicit_services(
            services_ref.as_ref(),
            &mut state,
            "did:webvh:scid123:example.com",
        )
        .unwrap();
        let services = state["service"].as_array().unwrap();
        assert_eq!(services.len(), 2);
        let ids: Vec<&str> = services.iter().map(|s| s["id"].as_str().unwrap()).collect();
        assert!(ids.iter().any(|id| id.ends_with("#files")));
    }

    /// Tests that when a DID Document has only the #files service, the missing
    /// #whois service is added while preserving the existing #files service.
    /// Expected: The resulting document has 2 services, including one ending with #whois.
    /// This matters because the #whois service is required for linked verifiable
    /// presentation discovery, and its absence must be corrected during resolution.
    #[test]
    fn test_only_files_adds_whois() {
        let existing = json!([
            {"id": "did:webvh:scid123:example.com#files", "type": "relativeRef", "serviceEndpoint": "https://example.com/"}
        ]);
        let mut state = json!({"id": "did:webvh:scid123:example.com", "service": existing});
        let services_ref = state.get("service").cloned();
        update_implicit_services(
            services_ref.as_ref(),
            &mut state,
            "did:webvh:scid123:example.com",
        )
        .unwrap();
        let services = state["service"].as_array().unwrap();
        assert_eq!(services.len(), 2);
        let ids: Vec<&str> = services.iter().map(|s| s["id"].as_str().unwrap()).collect();
        assert!(ids.iter().any(|id| id.ends_with("#whois")));
    }
}
