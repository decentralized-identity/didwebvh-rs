//! Implicit service injection for WebVH DID Documents.
//!
//! The WebVH specification requires two implicit services on every resolved
//! DID Document:
//! - **`#files`** — a `relativeRef` service pointing to the DID's base HTTP URL
//! - **`#whois`** — a `LinkedVerifiablePresentation` service pointing to `whois.vp`
//!
//! This module checks a resolved DID Document and appends any missing implicit
//! services. Existing services that already supply a `#files`/`#whois` fragment
//! (either as the relative form `"#whois"` or the absolute form
//! `"<did>#whois"`) are preserved and not duplicated.
//!
//! ## Format
//!
//! Both implicit services are emitted with **relative-fragment IDs** (`"#files"`
//! / `"#whois"`) and in **`#files` then `#whois` order**, matching the
//! didwebvh-test-suite reference output (and the didwebvh-ts reference
//! implementation). The `#files` `serviceEndpoint` is the DID's HTTP base URL
//! with any trailing `/` removed.
//!
//! ## Hash safety
//!
//! These services are **never** folded back into the LogEntry's stored `state`.
//! [`update_implicit_services`] mutates the *caller's* `new_state` `Value`,
//! which is constructed fresh by [`get_did_document`]/[`to_web_did`] from a
//! clone of `state`. The signed/hashed bytes are taken from `state` directly,
//! so implicit injection cannot affect the entry hash, the SCID, or any
//! `eddsa-jcs-2022` proof.
//!
//! [`get_did_document`]: crate::log_entry::LogEntryMethods::get_did_document
//! [`to_web_did`]: crate::DIDWebVHState::to_web_did

use crate::{DIDWebVHError, ensure_object_mut, url::WebVHURL};
use serde_json::{Value, json};

/// Checks and adds implicit services if not present (`#files` and `#whois`).
///
/// `services` is the existing `service` array from the source DID Document (or
/// `None` if absent). `new_state` is the *destination* document — typically a
/// clone of the source state — into which the merged service array is written.
///
/// Implicit services are appended in spec order (`#files` first, then
/// `#whois`) **after** any user-supplied services, preserving the user's
/// service ordering. Because JCS does not reorder JSON arrays (RFC 8785
/// §3.2.4), array order is part of the canonical form — but this function only
/// runs on the resolution-time `Value`, never on the LogEntry's `state`, so
/// the entry hash and proof bytes are unaffected.
pub(crate) fn update_implicit_services(
    services: Option<&Value>,
    new_state: &mut Value,
    did_id: &str,
) -> Result<(), DIDWebVHError> {
    let url = WebVHURL::parse_did_url(did_id)?;

    let Some(services) = services else {
        // There are no services, add the implicit services in spec order
        ensure_object_mut(new_state)?.insert(
            "service".to_string(),
            Value::Array(vec![get_service_files(&url)?, get_service_whois(&url)?]),
        );
        return Ok(());
    };

    if let Some(services) = services.as_array() {
        let absolute_whois = format!("{did_id}#whois");
        let absolute_files = format!("{did_id}#files");

        let mut has_whois = false;
        let mut has_files = false;

        for service in services {
            if let Some(id) = service.get("id").and_then(|v| v.as_str()) {
                // Strict match: only the relative form `#whois`/`#files` or the
                // absolute form `<did>#whois`/`<did>#files` count as the
                // implicit service. Any other ID that happens to end in
                // `#whois`/`#files` (e.g. a foreign DID or an unrelated URL)
                // is treated as a user-defined service so we still inject the
                // implicit one for *this* DID.
                if id == "#whois" || id == absolute_whois {
                    has_whois = true;
                } else if id == "#files" || id == absolute_files {
                    has_files = true;
                }
            }
        }

        let mut new_services = services.clone();

        if !has_files {
            new_services.push(get_service_files(&url)?);
        }
        if !has_whois {
            new_services.push(get_service_whois(&url)?);
        }

        ensure_object_mut(new_state)?.insert("service".to_string(), Value::Array(new_services));
    } else {
        return Err(DIDWebVHError::DIDError(
            "services is not an array".to_string(),
        ));
    }

    Ok(())
}

/// `#whois` — `LinkedVerifiablePresentation` service pointing at the DID's
/// `whois.vp`. ID is emitted as a relative fragment to match the
/// didwebvh-test-suite reference output.
fn get_service_whois(url: &WebVHURL) -> Result<Value, DIDWebVHError> {
    Ok(json!({
        "@context": "https://identity.foundation/linked-vp/contexts/v1",
        "id": "#whois",
        "type": "LinkedVerifiablePresentation",
        "serviceEndpoint": url.get_http_whois_url()?
    }))
}

/// `#files` — `relativeRef` service pointing at the DID's HTTP base URL.
///
/// The base URL is emitted **without** a trailing `/`. `Url::to_string()`
/// always appends `/` to a host-only URL, but the test-suite reference (and
/// didwebvh-ts) emit `https://example.com`, not `https://example.com/`.
fn get_service_files(url: &WebVHURL) -> Result<Value, DIDWebVHError> {
    let endpoint = url.get_http_files_url()?.to_string();
    let endpoint = endpoint.strip_suffix('/').unwrap_or(&endpoint);
    Ok(json!({
        "id": "#files",
        "type": "relativeRef",
        "serviceEndpoint": endpoint
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Tests that when a DID Document has no services defined, both implicit
    /// services are automatically added in spec order: `#files` first, then
    /// `#whois`. IDs are emitted as relative fragments.
    #[test]
    fn test_no_services_adds_both() {
        let mut state = json!({"id": "did:webvh:scid123:example.com"});
        update_implicit_services(None, &mut state, "did:webvh:scid123:example.com").unwrap();
        let services = state["service"].as_array().unwrap();
        assert_eq!(services.len(), 2);
        // Order matters for JCS: #files MUST come before #whois.
        assert_eq!(services[0]["id"].as_str(), Some("#files"));
        assert_eq!(services[1]["id"].as_str(), Some("#whois"));
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

    /// When only `#whois` exists (absolute form), the missing `#files` is
    /// appended. The existing service is preserved unchanged.
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
        assert!(ids.contains(&"#files"));
    }

    /// When only `#files` exists (absolute form), the missing `#whois` is
    /// appended. The existing service is preserved unchanged.
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
        assert!(ids.contains(&"#whois"));
    }

    /// Both relative-form (`"#whois"`) and absolute-form
    /// (`"<did>#whois"`) IDs satisfy the "already present" check, so
    /// implicit injection is skipped for either.
    #[test]
    fn test_relative_and_absolute_forms_both_recognised() {
        for whois_id in ["#whois", "did:webvh:scid123:example.com#whois"] {
            for files_id in ["#files", "did:webvh:scid123:example.com#files"] {
                let existing = json!([
                    {"id": whois_id, "type": "LinkedVerifiablePresentation", "serviceEndpoint": "x"},
                    {"id": files_id, "type": "relativeRef", "serviceEndpoint": "y"}
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
                assert_eq!(
                    services.len(),
                    2,
                    "no injection expected for ({whois_id}, {files_id})"
                );
            }
        }
    }

    /// Strict matching: a service with an `id` that merely *ends with*
    /// `#whois` (e.g. a foreign DID's whois, or an unrelated URL fragment) is
    /// **not** treated as this DID's implicit service. The implicit service is
    /// still injected. This guards against the previous `ends_with` check
    /// silently suppressing implicit injection.
    #[test]
    fn test_unrelated_whois_suffix_does_not_suppress_injection() {
        let existing = json!([
            {"id": "did:webvh:OTHER:example.com#whois", "type": "LinkedVerifiablePresentation", "serviceEndpoint": "x"},
            {"id": "https://elsewhere.example/#files", "type": "relativeRef", "serviceEndpoint": "y"}
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
        // 2 user services + 2 implicit services = 4
        assert_eq!(services.len(), 4);
        // Implicits are appended at the end in #files, #whois order.
        assert_eq!(services[2]["id"].as_str(), Some("#files"));
        assert_eq!(services[3]["id"].as_str(), Some("#whois"));
    }

    /// `#files` `serviceEndpoint` must NOT have a trailing slash for a
    /// host-only DID — matches the didwebvh-test-suite reference output.
    #[test]
    fn test_files_endpoint_has_no_trailing_slash() {
        let mut state = json!({"id": "did:webvh:scid123:example.com"});
        update_implicit_services(None, &mut state, "did:webvh:scid123:example.com").unwrap();
        let files = &state["service"][0];
        assert_eq!(files["id"].as_str(), Some("#files"));
        assert_eq!(
            files["serviceEndpoint"].as_str(),
            Some("https://example.com")
        );
    }

    /// Path-bearing DID: the `#files` `serviceEndpoint` MUST be the host plus
    /// the colon-delimited path joined with `/`, with no trailing slash. The
    /// `#whois` endpoint MUST be `<#files>/whois.vp`. Pinned against the
    /// didwebvh-ts reference output (`getBaseUrl`) so the two implementations
    /// emit byte-identical resolved documents for path-bearing DIDs.
    #[test]
    fn test_path_bearing_did_files_and_whois_endpoints() {
        let did = "did:webvh:scid123:example.com:foo:bar";
        let mut state = json!({"id": did});
        update_implicit_services(None, &mut state, did).unwrap();
        let services = state["service"].as_array().unwrap();
        assert_eq!(services[0]["id"].as_str(), Some("#files"));
        assert_eq!(
            services[0]["serviceEndpoint"].as_str(),
            Some("https://example.com/foo/bar")
        );
        assert_eq!(services[1]["id"].as_str(), Some("#whois"));
        assert_eq!(
            services[1]["serviceEndpoint"].as_str(),
            Some("https://example.com/foo/bar/whois.vp")
        );
    }

    /// Port-only DID (no path): `%3A` between host and port decodes to `:`.
    /// `#files` is `https://host:port` (no trailing slash); `#whois` appends
    /// `/whois.vp`. Matches didwebvh-ts `getBaseUrl`.
    #[test]
    fn test_port_only_did_files_and_whois_endpoints() {
        let did = "did:webvh:scid123:example.com%3A8080";
        let mut state = json!({"id": did});
        update_implicit_services(None, &mut state, did).unwrap();
        let services = state["service"].as_array().unwrap();
        assert_eq!(
            services[0]["serviceEndpoint"].as_str(),
            Some("https://example.com:8080")
        );
        assert_eq!(
            services[1]["serviceEndpoint"].as_str(),
            Some("https://example.com:8080/whois.vp")
        );
    }

    /// Port-and-path DID: combines the previous two cases. Matches
    /// didwebvh-ts `getBaseUrl`. Most likely surface for a future divergence,
    /// so worth pinning explicitly.
    #[test]
    fn test_port_and_path_did_files_and_whois_endpoints() {
        let did = "did:webvh:scid123:example.com%3A8080:foo:bar";
        let mut state = json!({"id": did});
        update_implicit_services(None, &mut state, did).unwrap();
        let services = state["service"].as_array().unwrap();
        assert_eq!(
            services[0]["serviceEndpoint"].as_str(),
            Some("https://example.com:8080/foo/bar")
        );
        assert_eq!(
            services[1]["serviceEndpoint"].as_str(),
            Some("https://example.com:8080/foo/bar/whois.vp")
        );
    }

    /// User-supplied services keep their original order; implicits are
    /// appended after them. Order is part of the JCS canonical form, so this
    /// test pins down the expected layout.
    #[test]
    fn test_user_services_preserved_implicits_appended() {
        let existing = json!([
            {"id": "#linked-domain", "type": "LinkedDomains", "serviceEndpoint": "https://example.com"},
            {"id": "#messaging", "type": "DIDCommMessaging", "serviceEndpoint": "https://example.com/dc"}
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
        assert_eq!(services.len(), 4);
        assert_eq!(services[0]["id"].as_str(), Some("#linked-domain"));
        assert_eq!(services[1]["id"].as_str(), Some("#messaging"));
        assert_eq!(services[2]["id"].as_str(), Some("#files"));
        assert_eq!(services[3]["id"].as_str(), Some("#whois"));
    }
}
