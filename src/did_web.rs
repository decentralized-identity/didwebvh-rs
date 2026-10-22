/*!
*   Handles converting a WebVH DID to a Web DID Document
*/

use crate::{
    DIDWebVHError, DIDWebVHState, ensure_object_mut, log_entry_state::LogEntryState,
    resolve::implicit::update_implicit_services,
};
use serde_json::Value;

impl DIDWebVHState {
    /// Converts the last LogEntry to a DID Web Document
    /// Will change the DID ID's as required
    /// NOTE: You may still want to check the resulting DID Document for validity
    pub fn to_web_did(&self) -> Result<Value, DIDWebVHError> {
        if let Some(log_entry) = self.log_entries.last() {
            log_entry.to_web_did()
        } else {
            // There is no Log Entry
            Err(DIDWebVHError::NotFound(
                "No log entries available for did:web conversion".to_string(),
            ))
        }
    }

    /// Takes a did:webvh ID and converts it to a did:web ID
    pub fn convert_webvh_id_to_web_id(id: &str) -> String {
        // input: did:webvh:<SCID>:<path>
        // `id` is taken from the DID document's `state["id"]`, i.e. attacker-
        // controlled, so a malformed value with fewer than three ':' segments
        // must degrade to a useless-but-safe result rather than panic.
        let parts: Vec<&str> = id.split(':').collect();
        let mut new_did = String::new();
        new_did.push_str("did:web");
        for p in parts.get(3..).unwrap_or_default() {
            new_did.push(':');
            new_did.push_str(p);
        }
        new_did
    }

    /// Takes a did:webvh ID and converts it to a did:scid:vh ID
    pub fn convert_webvh_id_to_scid_id(id: &str) -> String {
        // input: did:webvh:<SCID>:<path>
        // Extract SCID and path after "did:webvh:"
        let mut new_did = String::from("did:scid:vh:1:");
        if let Some(rest) = id.strip_prefix("did:webvh:")
            && let Some((scid, path)) = rest.split_once(':')
        {
            new_did.push_str(scid);
            new_did.push_str("?src=");
            new_did.push_str(&path.replace(':', "/"));
        }
        new_did
    }

    /// Takes a `did:scid:vh:1` ID or DID URL and converts it to its did:webvh form.
    ///
    /// The inverse of [`convert_webvh_id_to_scid_id`](Self::convert_webvh_id_to_scid_id):
    /// `did:scid:vh:1:<SCID>?src=example.com/path` becomes
    /// `did:webvh:<SCID>:example.com:path`, and a `#fragment` is carried across
    /// so key and service references map too. `src` may also carry an
    /// `https://` or `http://` scheme, a trailing `/`, or a literal `:` before a
    /// port, which is encoded as `%3A`.
    ///
    /// Returns `None` for anything that is not the `vh:1` format with a `src`:
    /// another method, another did:scid format or version, peer mode (no
    /// `src`), an empty SCID, an extra query parameter, or a malformed `src`.
    /// The input is caller-supplied, so a `None` must be treated as "not a
    /// did:scid:vh alias", never as a match.
    pub fn convert_scid_id_to_webvh_id(id: &str) -> Option<String> {
        let rest = id.strip_prefix("did:scid:vh:1:")?;
        let (rest, fragment) = match rest.split_once('#') {
            Some((r, f)) => (r, Some(f)),
            None => (rest, None),
        };
        let (scid, src) = rest.split_once("?src=")?;
        if scid.is_empty() || scid.contains([':', '/', '?']) || src.contains(['&', '?']) {
            return None;
        }

        let src = src
            .strip_prefix("https://")
            .or_else(|| src.strip_prefix("http://"))
            .unwrap_or(src)
            .trim_end_matches('/');
        let (host, path) = match src.split_once('/') {
            Some((h, p)) => (h, Some(p.trim_end_matches('/'))),
            None => (src, None),
        };
        let host = match host.split_once(':') {
            Some((h, port)) => {
                port.parse::<u16>().ok()?;
                format!("{h}%3A{port}")
            }
            None => host.to_string(),
        };
        if host.is_empty() || host.starts_with('%') {
            return None;
        }

        let mut new_did = format!("did:webvh:{scid}:{host}");
        if let Some(path) = path.filter(|p| !p.is_empty()) {
            if path.split('/').any(str::is_empty) {
                return None;
            }
            new_did.push(':');
            new_did.push_str(&path.replace('/', ":"));
        }
        if let Some(fragment) = fragment {
            new_did.push('#');
            new_did.push_str(fragment);
        }
        Some(new_did)
    }
}

impl DIDWebVHState {
    /// Converts the last LogEntry to a `did:scid:vh:1` DID Document.
    ///
    /// See [`to_scid_did_document`] for what changes.
    pub fn to_scid_did(&self) -> Result<Value, DIDWebVHError> {
        if let Some(log_entry) = self.log_entries.last() {
            to_scid_did_document(log_entry.get_state())
        } else {
            Err(DIDWebVHError::NotFound(
                "No log entries available for did:scid conversion".to_string(),
            ))
        }
    }
}

/// Expresses a did:webvh DID document as the document of its `did:scid:vh:1` DID.
///
/// A `did:scid:vh:1` DID is verified by the did:webvh log it is derived from,
/// but it is a DID in its own right: `did:scid:vh:1:<SCID>`, with
/// `?src=<host>/<path>` only a locator for the log. The document a resolver
/// returns for it must carry that DID as its `id` (DID Core §5.1.1), and its
/// own key and service references must be under it, or a party verifying
/// against the did:scid finds no keys.
///
/// - `id` becomes `did:scid:vh:1:<SCID>`, with no `src`.
/// - Every string that is exactly the did:webvh DID, or that DID followed by
///   `#`, is rewritten under the did:scid DID: verification method ids and
///   controllers, relationship references, service ids, and `controller`.
///   Other DIDs and URLs, relative references (`#key-1`) and DID URLs with a
///   path are left as they are.
/// - `alsoKnownAs` keeps the controller's entries, drops the bare did:scid DID
///   itself, and gains the `did:scid:vh:1:<SCID>?src=…` DID URL of the log's
///   current location and the did:webvh DID, where absent.
pub fn to_scid_did_document(state: &Value) -> Result<Value, DIDWebVHError> {
    let webvh_did = state
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| id.starts_with("did:webvh:"))
        .ok_or_else(|| {
            DIDWebVHError::DIDError("Couldn't find a did:webvh id attribute".to_string())
        })?
        .to_string();
    let scid_url = DIDWebVHState::convert_webvh_id_to_scid_id(&webvh_did);
    let Some((scid_did, _)) = scid_url.split_once("?src=") else {
        return Err(DIDWebVHError::DIDError(format!(
            "{webvh_did} has no SCID and host to convert"
        )));
    };
    let scid_did = scid_did.to_string();

    let mut new_state = state.clone();
    rewrite_self_references(&mut new_state, &webvh_did, &scid_did);

    let mut aliases: Vec<Value> = match state.get("alsoKnownAs") {
        None => vec![],
        Some(Value::Array(aliases)) => aliases
            .iter()
            .filter(|alias| alias.as_str() != Some(scid_did.as_str()))
            .cloned()
            .collect(),
        Some(_) => {
            return Err(DIDWebVHError::DIDError(
                "alsoKnownAs is not an array".to_string(),
            ));
        }
    };
    for alias in [scid_url.as_str(), webvh_did.as_str()] {
        if !aliases.iter().any(|a| a.as_str() == Some(alias)) {
            aliases.push(Value::String(alias.to_string()));
        }
    }
    ensure_object_mut(&mut new_state)?.insert("alsoKnownAs".to_string(), Value::Array(aliases));

    Ok(new_state)
}

fn rewrite_self_references(value: &mut Value, webvh_did: &str, scid_did: &str) {
    match value {
        Value::String(s) => {
            if s == webvh_did {
                *s = scid_did.to_string();
            } else if let Some(fragment) = s
                .strip_prefix(webvh_did)
                .and_then(|rest| rest.strip_prefix('#'))
            {
                *s = format!("{scid_did}#{fragment}");
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| rewrite_self_references(item, webvh_did, scid_did)),
        Value::Object(map) => map
            .values_mut()
            .for_each(|item| rewrite_self_references(item, webvh_did, scid_did)),
        _ => {}
    }
}

impl LogEntryState {
    /// Converts this LogEntry State to a `did:scid:vh:1` DID Document.
    ///
    /// See [`to_scid_did_document`] for what changes.
    pub fn to_scid_did(&self) -> Result<Value, DIDWebVHError> {
        to_scid_did_document(self.get_state())
    }

    /// Converts this LogEntry State to a DID Web Document
    /// Converts the DID references automatically
    /// NOTE: You may still want to check the resulting DID Document for validity
    pub fn to_web_did(&self) -> Result<Value, DIDWebVHError> {
        let state = self.get_state();
        if !state.is_object() {
            return Err(DIDWebVHError::DIDError(
                "State is not a valid JSON Object".to_string(),
            ));
        }

        to_web_did(state)
    }
}

/// Replaces all occurrences of `did:webvh:<SCID>` with `did:web` in a string.
/// The SCID is the segment between `did:webvh:` and the next `:` (or end of the
/// `did:webvh:...` token).
fn replace_webvh_prefix(input: &str) -> String {
    const PREFIX: &str = "did:webvh:";
    let mut result = String::with_capacity(input.len());
    let mut remaining = input;
    while let Some(start) = remaining.find(PREFIX) {
        result.push_str(&remaining[..start]);
        result.push_str("did:web");
        let after_prefix = &remaining[start + PREFIX.len()..];
        // Skip the SCID (everything up to the next ':' or non-DID character)
        let scid_end = after_prefix
            .find(|c: char| c == ':' || c == '"' || c.is_whitespace())
            .unwrap_or(after_prefix.len());
        remaining = &after_prefix[scid_end..];
    }
    result.push_str(remaining);
    result
}

fn to_web_did(old_state: &Value) -> Result<Value, DIDWebVHError> {
    // What is the new DID?
    let (webvh_did, web_did) = if let Some(id) = old_state.get("id")
        && let Some(id_str) = id.as_str()
    {
        (
            id_str.to_string(),
            DIDWebVHState::convert_webvh_id_to_web_id(id_str),
        )
    } else {
        return Err(DIDWebVHError::DIDError(
            "Couldn't find DID (id) attribute".to_string(),
        ));
    };

    let service = old_state.get("service");
    let mut old_state = old_state.clone();
    // Add implicit WebVH Services if not present
    update_implicit_services(service, &mut old_state, &webvh_did)?;

    let did_doc = serde_json::to_string(&old_state)
        .map_err(|e| DIDWebVHError::DIDError(format!("Couldn't serialize state: {}", e)))?;

    // Replace the existing did:webvh:<SCID> prefix with did:web throughout the document.
    // The SCID is always the segment between "did:webvh:" and the next ":"
    let new_did_doc = replace_webvh_prefix(&did_doc);

    let mut new_state: Value = serde_json::from_str(&new_did_doc)
        .map_err(|e| DIDWebVHError::DIDError(format!("Couldn't parse new state: {}", e)))?;

    // Set the DID id
    ensure_object_mut(&mut new_state)?.insert("id".to_string(), Value::String(web_did.clone()));

    // Reset the controller to be the webvh original ID
    ensure_object_mut(&mut new_state)?
        .insert("controller".to_string(), Value::String(webvh_did.clone()));

    // Update alsoKnownAs
    update_also_known_as(
        old_state.get("alsoKnownAs"),
        &mut new_state,
        &webvh_did,
        &web_did,
    )?;

    Ok(new_state)
}

// Manages the updates to the alsoKnownAs DID attribute
// Checks each entry, removes itself if it exists already
// Adds the WebVH entry if it doesn't exist
fn update_also_known_as(
    also_known_as: Option<&Value>,
    new_state: &mut Value,
    old_did: &str,
    new_did: &str,
) -> Result<(), DIDWebVHError> {
    let Some(also_known_as) = also_known_as else {
        // There is no alsoKnownAs, add the old_did
        ensure_object_mut(new_state)?.insert(
            "alsoKnownAs".to_string(),
            Value::Array(vec![Value::String(old_did.to_string())]),
        );
        return Ok(());
    };

    let mut did_webvh_exists = false;
    let mut new_aliases = vec![];

    if let Some(aliases) = also_known_as.as_array() {
        for alias in aliases {
            if let Some(alias_str) = alias.as_str() {
                if alias_str == new_did {
                    // did:web already exists, skip it
                } else if alias_str == old_did {
                    // did:webvh already exists, add it
                    did_webvh_exists = true;
                    new_aliases.push(alias.clone());
                } else {
                    new_aliases.push(alias.clone());
                }
            }
        }
    } else {
        return Err(DIDWebVHError::DIDError(
            "alsoKnownAs is not an array".to_string(),
        ));
    }

    if !did_webvh_exists {
        // webvh DID isn't an alias, add it
        new_aliases.push(Value::String(old_did.to_string()));
    }

    ensure_object_mut(new_state)?.insert("alsoKnownAs".to_string(), Value::Array(new_aliases));

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{DIDWebVHState, did_web::to_web_did};
    use serde::Deserialize;
    use serde_json::{Value, json};

    // Dummy struct to help with testing DID Services
    #[derive(Debug, Deserialize, PartialEq)]
    struct Service {
        pub id: String,
        #[serde(rename = "serviceEndpoint")]
        pub service_endpoint: String,
    }

    #[test]
    fn test_no_log_entry() {
        let state = DIDWebVHState::default();

        assert!(state.to_web_did().is_err());
    }

    #[test]
    fn test_id_conversion() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com:path"});

        let new_state = to_web_did(&old_state).expect("Couldn't convert to did:web");
        assert_eq!(
            new_state
                .get("id")
                .expect("Couldn't find (id)")
                .as_str()
                .expect("Expected a string for (id)"),
            "did:web:affinidi.com:path"
        );

        assert_eq!(
            new_state
                .get("controller")
                .expect("Couldn't find (controller)")
                .as_str()
                .expect("Expected a string for (controller)"),
            "did:webvh:acme1234:affinidi.com:path"
        );
    }

    #[test]
    fn test_missing_id() {
        let old_state = json!({"not_id": "did:webvh:acme1234:affinidi.com:path"});

        assert!(to_web_did(&old_state).is_err());
    }

    #[test]
    fn test_not_object() {
        let old_state = Value::String("Not an object".to_string());

        assert!(to_web_did(&old_state).is_err());
    }

    #[test]
    fn test_also_known_as_empty() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com"});

        let did_web = to_web_did(&old_state).expect("Couldn't convert to did:web");

        let also_known_as: Vec<String> = serde_json::from_value(
            did_web
                .get("alsoKnownAs")
                .expect("alsoKnownAs in did:web doesn't exist")
                .to_owned(),
        )
        .expect("Couldn't process alsoKnownAs attribute");

        assert_eq!(also_known_as.len(), 1);
        assert!(also_known_as.contains(&"did:webvh:acme1234:affinidi.com".to_string()));
    }

    #[test]
    fn test_also_known_as_existing_webvh() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com", "alsoKnownAs": ["did:webvh:acme1234:affinidi.com"]});

        let did_web = to_web_did(&old_state).expect("Couldn't convert to did:web");

        let also_known_as: Vec<String> = serde_json::from_value(
            did_web
                .get("alsoKnownAs")
                .expect("alsoKnownAs in did:web doesn't exist")
                .to_owned(),
        )
        .expect("Couldn't process alsoKnownAs attribute");

        assert_eq!(also_known_as.len(), 1);
        assert!(also_known_as.contains(&"did:webvh:acme1234:affinidi.com".to_string()));
    }

    #[test]
    fn test_also_known_as_existing_web() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com", "alsoKnownAs": ["did:web:affinidi.com"]});

        let did_web = to_web_did(&old_state).expect("Couldn't convert to did:web");

        let also_known_as: Vec<String> = serde_json::from_value(
            did_web
                .get("alsoKnownAs")
                .expect("alsoKnownAs in did:web doesn't exist")
                .to_owned(),
        )
        .expect("Couldn't process alsoKnownAs attribute");

        assert_eq!(also_known_as.len(), 1);
        assert!(!also_known_as.contains(&"did:web:affinidi.com".to_string()));
        assert!(also_known_as.contains(&"did:webvh:acme1234:affinidi.com".to_string()));
    }

    #[test]
    fn test_also_known_as_existing_many() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com", "alsoKnownAs": ["did:web:affinidi.com", "did:webvh:acme1234:affinidi.com", "did:web:unknown.com", "did:web:another.alias"]});

        let did_web = to_web_did(&old_state).expect("Couldn't convert to did:web");

        let also_known_as: Vec<String> = serde_json::from_value(
            did_web
                .get("alsoKnownAs")
                .expect("alsoKnownAs in did:web doesn't exist")
                .to_owned(),
        )
        .expect("Couldn't process alsoKnownAs attribute");

        assert_eq!(also_known_as.len(), 3);
        assert!(!also_known_as.contains(&"did:web:affinidi.com".to_string()));
        assert!(also_known_as.contains(&"did:web:unknown.com".to_string()));
        assert!(also_known_as.contains(&"did:webvh:acme1234:affinidi.com".to_string()));
    }

    /// Implicit services use absolute IDs (`<did>#files`, `<did>#whois`) so
    /// the resolved did:web document satisfies DID Core 1.0 §5.4. The
    /// `did:webvh:<scid>:` prefix is rewritten to `did:web:` by
    /// `to_web_did`, so the IDs land as `did:web:<host>#…`. The `#files`
    /// `serviceEndpoint` has no trailing slash.
    #[test]
    fn test_services_none() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com"});

        let did_web = to_web_did(&old_state).expect("Couldn't convert to did:web");

        let services: Vec<Service> = serde_json::from_value(
            did_web
                .get("service")
                .expect("service in did:web doesn't exist")
                .to_owned(),
        )
        .expect("Couldn't process service attribute");

        assert_eq!(services.len(), 2);
        // Order matters: #files MUST come before #whois.
        assert_eq!(
            services[0],
            Service {
                id: "did:web:affinidi.com#files".to_string(),
                service_endpoint: "https://affinidi.com".to_string(),
            }
        );
        assert_eq!(
            services[1],
            Service {
                id: "did:web:affinidi.com#whois".to_string(),
                service_endpoint: "https://affinidi.com/whois.vp".to_string(),
            }
        );
    }

    #[test]
    fn test_convert_webvh_to_web_malformed_no_panic() {
        // state["id"] is attacker-controlled; fewer than three ':' segments
        // used to panic on `parts[3..]`. It must now return a (useless but
        // harmless) bare "did:web" instead of crashing the resolver.
        assert_eq!(DIDWebVHState::convert_webvh_id_to_web_id(""), "did:web");
        assert_eq!(DIDWebVHState::convert_webvh_id_to_web_id("x"), "did:web");
        assert_eq!(DIDWebVHState::convert_webvh_id_to_web_id("a:b"), "did:web");
        assert_eq!(
            DIDWebVHState::convert_webvh_id_to_web_id("did:webvh:scid"),
            "did:web"
        );
    }

    #[test]
    fn test_convert_webvh_to_scid() {
        let scid =
            DIDWebVHState::convert_webvh_id_to_scid_id("did:webvh:acme1234:affinidi.com:path");
        assert_eq!(scid, "did:scid:vh:1:acme1234?src=affinidi.com/path");
    }

    #[test]
    fn test_convert_webvh_to_scid_no_path() {
        let scid = DIDWebVHState::convert_webvh_id_to_scid_id("did:webvh:acme1234:affinidi.com");
        assert_eq!(scid, "did:scid:vh:1:acme1234?src=affinidi.com");
    }

    #[test]
    fn test_convert_scid_to_webvh() {
        assert_eq!(
            DIDWebVHState::convert_scid_id_to_webvh_id(
                "did:scid:vh:1:acme1234?src=affinidi.com/path"
            )
            .as_deref(),
            Some("did:webvh:acme1234:affinidi.com:path")
        );
        assert_eq!(
            DIDWebVHState::convert_scid_id_to_webvh_id("did:scid:vh:1:acme1234?src=affinidi.com")
                .as_deref(),
            Some("did:webvh:acme1234:affinidi.com")
        );
    }

    #[test]
    fn test_scid_webvh_round_trip() {
        for webvh in [
            "did:webvh:acme1234:affinidi.com",
            "did:webvh:acme1234:affinidi.com:a:b",
            "did:webvh:acme1234:localhost%3A8000:path",
        ] {
            let scid = DIDWebVHState::convert_webvh_id_to_scid_id(webvh);
            assert_eq!(
                DIDWebVHState::convert_scid_id_to_webvh_id(&scid).as_deref(),
                Some(webvh)
            );
        }
    }

    #[test]
    fn test_convert_scid_to_webvh_lenient_src() {
        for src in [
            "https://localhost:8000/path/",
            "localhost:8000/path",
            "localhost%3A8000/path",
            "http://localhost%3A8000/path",
        ] {
            assert_eq!(
                DIDWebVHState::convert_scid_id_to_webvh_id(&format!("did:scid:vh:1:abc?src={src}"))
                    .as_deref(),
                Some("did:webvh:abc:localhost%3A8000:path"),
                "src={src}"
            );
        }
    }

    #[test]
    fn test_convert_scid_to_webvh_keeps_fragment() {
        assert_eq!(
            DIDWebVHState::convert_scid_id_to_webvh_id("did:scid:vh:1:abc?src=example.com#key-1")
                .as_deref(),
            Some("did:webvh:abc:example.com#key-1")
        );
    }

    #[test]
    fn test_convert_scid_to_webvh_rejects() {
        for id in [
            "did:webvh:abc:example.com",
            "did:scid:vh:1:abc",
            "did:scid:vh:2:abc?src=example.com",
            "did:scid:ke:1:abc?src=example.com",
            "did:scid:vh:1:?src=example.com",
            "did:scid:vh:1:abc?src=",
            "did:scid:vh:1:abc?src=https:///",
            "did:scid:vh:1:abc?src=example.com&x=1",
            "did:scid:vh:1:abc?src=example.com:notaport",
            "did:scid:vh:1:abc?src=:8000",
            "did:scid:vh:1:abc?src=example.com//path",
            "did:scid:vh:1:a:b?src=example.com",
        ] {
            assert_eq!(DIDWebVHState::convert_scid_id_to_webvh_id(id), None, "{id}");
        }
    }

    #[test]
    fn test_to_scid_did_document() {
        let webvh = "did:webvh:Qm123:example.com:alice";
        let scid = "did:scid:vh:1:Qm123";
        let scid_url = "did:scid:vh:1:Qm123?src=example.com/alice";
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": webvh,
            "controller": webvh,
            "alsoKnownAs": [scid_url, "did:web:example.com:alice"],
            "verificationMethod": [
                { "id": format!("{webvh}#key-1"), "controller": webvh, "type": "Multikey", "publicKeyMultibase": "z6Mk" },
                { "id": "#key-2", "controller": webvh, "type": "Multikey", "publicKeyMultibase": "z6LS" }
            ],
            "authentication": [format!("{webvh}#key-1")],
            "keyAgreement": ["#key-2"],
            "service": [
                { "id": format!("{webvh}#didcomm"), "type": "DIDCommMessaging", "serviceEndpoint": "did:webvh:QmOther:mediator.example.com" },
                { "id": format!("{webvh}/whois"), "type": "LinkedVerifiablePresentation", "serviceEndpoint": "https://example.com/alice/whois.vp" }
            ]
        });

        let out = super::to_scid_did_document(&doc).unwrap();
        assert_eq!(out["id"], scid);
        assert_eq!(out["controller"], scid);
        assert_eq!(out["verificationMethod"][0]["id"], format!("{scid}#key-1"));
        assert_eq!(out["verificationMethod"][0]["controller"], scid);
        assert_eq!(out["verificationMethod"][1]["id"], "#key-2");
        assert_eq!(out["authentication"][0], format!("{scid}#key-1"));
        assert_eq!(out["keyAgreement"][0], "#key-2");
        assert_eq!(out["service"][0]["id"], format!("{scid}#didcomm"));
        // Another DID is not this one.
        assert_eq!(
            out["service"][0]["serviceEndpoint"],
            "did:webvh:QmOther:mediator.example.com"
        );
        // A DID URL with a path has no did:scid spelling and is left alone.
        assert_eq!(out["service"][1]["id"], format!("{webvh}/whois"));
        assert_eq!(
            out["alsoKnownAs"],
            json!([scid_url, "did:web:example.com:alice", webvh])
        );
    }

    #[test]
    fn test_to_scid_did_document_without_alias() {
        // A log that never listed its did:scid still has one; the locator of
        // its current location is added.
        let doc = json!({
            "id": "did:webvh:Qm123:example.com",
            "controller": "did:webvh:Qm123:example.com:alice"
        });
        let out = super::to_scid_did_document(&doc).unwrap();
        assert_eq!(out["id"], "did:scid:vh:1:Qm123");
        // did:webvh:Qm123:example.com is a prefix of this, but not this.
        assert_eq!(out["controller"], "did:webvh:Qm123:example.com:alice");
        assert_eq!(
            out["alsoKnownAs"],
            json!([
                "did:scid:vh:1:Qm123?src=example.com",
                "did:webvh:Qm123:example.com"
            ])
        );
    }

    #[test]
    fn test_to_scid_did_document_refuses_non_webvh() {
        assert!(super::to_scid_did_document(&json!({ "id": "did:web:example.com" })).is_err());
        assert!(super::to_scid_did_document(&json!({ "id": "did:webvh:Qm123" })).is_err());
        assert!(super::to_scid_did_document(&json!({})).is_err());
    }

    #[test]
    fn test_replace_webvh_prefix_multiple() {
        use super::replace_webvh_prefix;
        let input = r#""did:webvh:scid1:a.com" and "did:webvh:scid2:b.com""#;
        let output = replace_webvh_prefix(input);
        assert_eq!(output, r#""did:web:a.com" and "did:web:b.com""#);
    }

    #[test]
    fn test_replace_webvh_prefix_no_match() {
        use super::replace_webvh_prefix;
        let input = "did:web:example.com";
        assert_eq!(replace_webvh_prefix(input), input);
    }

    /// Path-bearing DID: implicit services use absolute IDs that, after the
    /// webvh→web prefix rewrite, become `did:web:<host>:<path>#…`. The
    /// `#files` endpoint drops its trailing slash to match the test-suite
    /// convention.
    #[test]
    fn test_services_none_custom_path() {
        let old_state = json!({"id": "did:webvh:acme1234:affinidi.com:custom:path"});

        let did_web = to_web_did(&old_state).expect("Couldn't convert to did:web");

        let services: Vec<Service> = serde_json::from_value(
            did_web
                .get("service")
                .expect("service in did:web doesn't exist")
                .to_owned(),
        )
        .expect("Couldn't process service attribute");

        assert_eq!(services.len(), 2);
        assert_eq!(
            services[0],
            Service {
                id: "did:web:affinidi.com:custom:path#files".to_string(),
                service_endpoint: "https://affinidi.com/custom/path".to_string(),
            }
        );
        assert_eq!(
            services[1],
            Service {
                id: "did:web:affinidi.com:custom:path#whois".to_string(),
                service_endpoint: "https://affinidi.com/custom/path/whois.vp".to_string(),
            }
        );
    }
}
