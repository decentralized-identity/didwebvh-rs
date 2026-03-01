use crate::{DIDWebVHError, ensure_object_mut, url::WebVHURL};
/// The WebVH DID Specification implies specific services for DID Documents
/// This checks a resolved DID Document and adds implied services as needed
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

        ensure_object_mut(new_state)?
            .insert("service".to_string(), Value::Array(new_services));
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
