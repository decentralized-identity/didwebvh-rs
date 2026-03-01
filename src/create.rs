/*!
*   Library API for creating a new webvh DID programmatically.
*   Encapsulates the DID creation flow (log entry creation, validation, witness signing)
*   without any interactive prompts.
*/

use crate::{
    DIDWebVHError, DIDWebVHState, ensure_object_mut,
    log_entry::{LogEntry, LogEntryMethods},
    log_entry_state::LogEntryState,
    parameters::Parameters,
    url::WebVHURL,
    witness::{Witnesses, proofs::WitnessProofCollection},
};
use affinidi_data_integrity::DataIntegrityProof;
use affinidi_secrets_resolver::secrets::Secret;
use ahash::HashMap;
use serde_json::{Value, json};
use std::sync::Arc;
use url::Url;

/// Configuration for creating a new DID
pub struct CreateDIDConfig {
    /// Address: URL (e.g. "https://example.com/") or DID (e.g. "did:webvh:{SCID}:example.com")
    pub address: String,
    /// At least one Secret for signing the log entry
    pub authorization_keys: Vec<Secret>,
    /// The DID Document (JSON Value). Must contain `id` matching the DID.
    pub did_document: Value,
    /// Parameters (update_keys, portable, witnesses, watchers, ttl, etc.)
    pub parameters: Parameters,
    /// Witness secrets keyed by witness DID — required if witnesses configured
    pub witness_secrets: HashMap<String, Secret>,
    /// Add did:web to alsoKnownAs
    pub also_known_as_web: bool,
    /// Add did:scid:vh to alsoKnownAs
    pub also_known_as_scid: bool,
}

/// Builder for constructing a [`CreateDIDConfig`].
///
/// Only `address`, `authorization_keys`, `did_document`, and `parameters` are required.
/// All other fields have sensible defaults.
///
/// # Example
/// ```ignore
/// let config = CreateDIDConfig::builder()
///     .address("https://example.com/")
///     .authorization_key(signing_key)
///     .did_document(doc)
///     .parameters(params)
///     .also_known_as_web(true)
///     .build()?;
/// ```
pub struct CreateDIDConfigBuilder {
    address: Option<String>,
    authorization_keys: Vec<Secret>,
    did_document: Option<Value>,
    parameters: Option<Parameters>,
    witness_secrets: HashMap<String, Secret>,
    also_known_as_web: bool,
    also_known_as_scid: bool,
}

impl CreateDIDConfigBuilder {
    fn new() -> Self {
        Self {
            address: None,
            authorization_keys: Vec::new(),
            did_document: None,
            parameters: None,
            witness_secrets: HashMap::default(),
            also_known_as_web: false,
            also_known_as_scid: false,
        }
    }

    /// Set the address (URL or DID format). Required.
    pub fn address(mut self, address: impl Into<String>) -> Self {
        self.address = Some(address.into());
        self
    }

    /// Add a single authorization key. At least one is required.
    pub fn authorization_key(mut self, key: Secret) -> Self {
        self.authorization_keys.push(key);
        self
    }

    /// Set all authorization keys at once, replacing any previously added.
    pub fn authorization_keys(mut self, keys: Vec<Secret>) -> Self {
        self.authorization_keys = keys;
        self
    }

    /// Set the DID Document. Required.
    pub fn did_document(mut self, doc: Value) -> Self {
        self.did_document = Some(doc);
        self
    }

    /// Set the Parameters. Required.
    pub fn parameters(mut self, params: Parameters) -> Self {
        self.parameters = Some(params);
        self
    }

    /// Add a single witness secret keyed by witness DID.
    pub fn witness_secret(mut self, did: impl Into<String>, secret: Secret) -> Self {
        self.witness_secrets.insert(did.into(), secret);
        self
    }

    /// Set all witness secrets at once, replacing any previously added.
    pub fn witness_secrets(mut self, secrets: HashMap<String, Secret>) -> Self {
        self.witness_secrets = secrets;
        self
    }

    /// Whether to add `did:web` to `alsoKnownAs`. Defaults to `false`.
    pub fn also_known_as_web(mut self, enabled: bool) -> Self {
        self.also_known_as_web = enabled;
        self
    }

    /// Whether to add `did:scid:vh` to `alsoKnownAs`. Defaults to `false`.
    pub fn also_known_as_scid(mut self, enabled: bool) -> Self {
        self.also_known_as_scid = enabled;
        self
    }

    /// Build the [`CreateDIDConfig`], returning an error if required fields are missing.
    pub fn build(self) -> Result<CreateDIDConfig, DIDWebVHError> {
        let address = self.address.ok_or_else(|| {
            DIDWebVHError::DIDError("address is required".to_string())
        })?;
        if self.authorization_keys.is_empty() {
            return Err(DIDWebVHError::LogEntryError(
                "At least one authorization key is required".to_string(),
            ));
        }
        let did_document = self.did_document.ok_or_else(|| {
            DIDWebVHError::DIDError("did_document is required".to_string())
        })?;
        let parameters = self.parameters.ok_or_else(|| {
            DIDWebVHError::ParametersError("parameters is required".to_string())
        })?;

        Ok(CreateDIDConfig {
            address,
            authorization_keys: self.authorization_keys,
            did_document,
            parameters,
            witness_secrets: self.witness_secrets,
            also_known_as_web: self.also_known_as_web,
            also_known_as_scid: self.also_known_as_scid,
        })
    }
}

impl CreateDIDConfig {
    /// Create a new builder for `CreateDIDConfig`.
    pub fn builder() -> CreateDIDConfigBuilder {
        CreateDIDConfigBuilder::new()
    }
}

/// Result of creating a new DID
pub struct CreateDIDResult {
    /// The resolved DID identifier (with SCID)
    pub did: String,
    /// The signed first log entry (serialize to JSON for did.jsonl)
    pub log_entry: LogEntry,
    /// Witness proofs (serialize to JSON for witness.json). Empty if no witnesses.
    pub witness_proofs: WitnessProofCollection,
}

/// Ensure a Secret has a proper `did:key:` ID for use in Data Integrity Proofs.
/// If the id doesn't start with `did:key:`, it's replaced with the
/// `did:key:{multibase}#{multibase}` format expected by verification.
fn ensure_did_key_id(secret: &mut Secret) -> Result<(), DIDWebVHError> {
    if !secret.id.starts_with("did:key:") {
        let pub_mb = secret.get_public_keymultibase().map_err(|e| {
            DIDWebVHError::LogEntryError(format!("Invalid key: {e}"))
        })?;
        secret.id = format!("did:key:{pub_mb}#{pub_mb}");
    }
    Ok(())
}

/// Create a new DID using the provided configuration.
///
/// This is the main library entry point for DID creation. It:
/// 1. Parses the address (URL or DID format)
/// 2. Optionally adds `did:web` and `did:scid:vh` to `alsoKnownAs`
/// 3. Creates and signs the first log entry
/// 4. Validates the log entry
/// 5. Signs witness proofs using provided witness secrets
///
/// Returns the resolved DID, signed LogEntry, and WitnessProofCollection.
pub fn create_did(mut config: CreateDIDConfig) -> Result<CreateDIDResult, DIDWebVHError> {
    // Parse the address
    let did_url = if config.address.starts_with("did:") {
        WebVHURL::parse_did_url(&config.address)?
    } else {
        let url = Url::parse(&config.address).map_err(|e| {
            DIDWebVHError::DIDError(format!("Invalid URL ({}): {e}", config.address))
        })?;
        WebVHURL::parse_url(&url)?
    };

    let webvh_did = did_url.to_string();

    // Optionally add did:web to alsoKnownAs
    if config.also_known_as_web {
        add_web_also_known_as(&mut config.did_document, &webvh_did)?;
    }

    // Optionally add did:scid:vh to alsoKnownAs
    if config.also_known_as_scid {
        add_scid_also_known_as(&mut config.did_document, &webvh_did)?;
    }

    replace_did_placeholder(&mut config.did_document, &webvh_did);

    // Ensure authorization keys have proper did:key IDs for Data Integrity Proofs
    for key in &mut config.authorization_keys {
        ensure_did_key_id(key)?;
    }

    // Create the log entry
    let mut didwebvh = DIDWebVHState::default();
    let signing_key = config.authorization_keys.first().ok_or_else(|| {
        DIDWebVHError::LogEntryError("At least one authorization key is required".to_string())
    })?;

    let log_entry_state = didwebvh.create_log_entry(
        None, // No version time, defaults to now
        &config.did_document,
        &config.parameters,
        signing_key,
    )?;

    // Validate the log entry
    log_entry_state.log_entry.verify_log_entry(None, None)?;

    // Get the resolved DID (with SCID)
    let resolved_did = if let Some(Value::String(id)) = log_entry_state.log_entry.get_state().get("id") {
        id.clone()
    } else {
        webvh_did
    };

    // Clone the log entry since we borrow from didwebvh
    let log_entry = log_entry_state.log_entry.clone();
    let active_witnesses = log_entry_state.get_active_witnesses();

    // Sign witness proofs
    let mut witness_proofs = WitnessProofCollection::default();
    sign_witness_proofs(
        &mut witness_proofs,
        log_entry_state,
        &active_witnesses,
        &config.witness_secrets,
    )?;

    Ok(CreateDIDResult {
        did: resolved_did,
        log_entry,
        witness_proofs,
    })
}

/// Recursively replaces all occurrences of the string "{DID}" in leaf string values of a JSON document.
///
/// Traverses the provided `did_document` (serde_json::Value), and for every string value found,
/// replaces all instances of "{DID}" with the provided `did` value. This is useful for templating
/// DID documents where placeholders need to be replaced with the actual DID.
///
/// # Arguments
/// * `did_document` - A mutable reference to a serde_json::Value representing the DID document.
/// * `did` - The DID string to substitute for the "{DID}" placeholder.
fn replace_did_placeholder(did_document: &mut Value, did: &String) {
    match did_document {
        Value::Object(map) => {
            for value in map.values_mut() {
                replace_did_placeholder(value, did);
            }
        }
        Value::Array(arr) => {
            for value in arr.iter_mut() {
                replace_did_placeholder(value, did);
            }
        }
        Value::String(s) => {
            if s.contains("{DID}") {
                *s = s.replace("{DID}", did);
            }
        }
        _ => {}
    }
}

/// Add a `did:web` alias to `alsoKnownAs` in the DID document (non-interactive).
///
/// Converts the `did:webvh` identifier to `did:web` format and inserts it into
/// the `alsoKnownAs` array. If the alias already exists, it is not duplicated.
pub fn add_web_also_known_as(did_document: &mut Value, did: &str) -> Result<(), DIDWebVHError> {
    let did_web_id = DIDWebVHState::convert_webvh_id_to_web_id(did);

    let also_known_as = did_document.get_mut("alsoKnownAs");

    let Some(also_known_as) = also_known_as else {
        // There is no alsoKnownAs, add the did:web
        ensure_object_mut(did_document)?.insert(
            "alsoKnownAs".to_string(),
            Value::Array(vec![Value::String(did_web_id.to_string())]),
        );
        return Ok(());
    };

    let new_aliases = build_alias_list(also_known_as, &did_web_id)?;

    ensure_object_mut(did_document)?
        .insert("alsoKnownAs".to_string(), Value::Array(new_aliases));

    Ok(())
}

/// Add a `did:scid:vh` alias to `alsoKnownAs` in the DID document (non-interactive).
///
/// Converts the `did:webvh` identifier to `did:scid:vh` format and inserts it into
/// the `alsoKnownAs` array. If the alias already exists, it is not duplicated.
pub fn add_scid_also_known_as(did_document: &mut Value, did: &str) -> Result<(), DIDWebVHError> {
    let did_scid_id = DIDWebVHState::convert_webvh_id_to_scid_id(did);

    let also_known_as = did_document.get_mut("alsoKnownAs");

    let Some(also_known_as) = also_known_as else {
        // There is no alsoKnownAs, add the did:scid
        ensure_object_mut(did_document)?.insert(
            "alsoKnownAs".to_string(),
            Value::Array(vec![Value::String(did_scid_id.to_string())]),
        );
        return Ok(());
    };

    let new_aliases = build_alias_list(also_known_as, &did_scid_id)?;

    ensure_object_mut(did_document)?
        .insert("alsoKnownAs".to_string(), Value::Array(new_aliases));

    Ok(())
}

/// Shared helper: collects existing aliases, appending `new_alias` if not already present.
fn build_alias_list(
    also_known_as: &Value,
    new_alias: &str,
) -> Result<Vec<Value>, DIDWebVHError> {
    let mut new_aliases = vec![];
    let mut already_exists = false;

    if let Some(aliases) = also_known_as.as_array() {
        for alias in aliases {
            if let Some(alias_str) = alias.as_str() {
                if alias_str == new_alias {
                    already_exists = true;
                }
                new_aliases.push(alias.clone());
            }
        }
    } else {
        return Err(DIDWebVHError::DIDError(
            "alsoKnownAs is not an array".to_string(),
        ));
    }

    if !already_exists {
        new_aliases.push(Value::String(new_alias.to_string()));
    }

    Ok(new_aliases)
}

/// Sign witness proofs for a log entry using provided witness secrets (non-interactive).
///
/// For each witness node in the active witnesses configuration, looks up the corresponding
/// secret in `witness_secrets` (keyed by witness DID) and signs a proof.
///
/// Returns `Ok(true)` if witness proofs were signed, `Ok(false)` if no witnesses configured.
pub fn sign_witness_proofs(
    witness_proofs: &mut WitnessProofCollection,
    log_entry: &LogEntryState,
    witnesses: &Option<Arc<Witnesses>>,
    witness_secrets: &HashMap<String, Secret>,
) -> Result<bool, DIDWebVHError> {
    let Some(witnesses) = witnesses else {
        return Ok(false);
    };

    let (_, witness_nodes) = match &**witnesses {
        Witnesses::Value {
            threshold,
            witnesses,
        } => (threshold, witnesses),
        _ => {
            return Err(DIDWebVHError::WitnessProofError(
                "No valid witness parameter config found".to_string(),
            ));
        }
    };

    for witness in witness_nodes {
        // Get secret for Witness
        let Some(secret) = witness_secrets.get(&witness.id) else {
            return Err(DIDWebVHError::WitnessProofError(format!(
                "Couldn't find secret for witness ({})",
                witness.id
            )));
        };

        // Ensure the witness secret has a proper did:key ID
        let mut secret = secret.clone();
        ensure_did_key_id(&mut secret)?;

        // Generate Signature
        let proof = DataIntegrityProof::sign_jcs_data(
            &json!({"versionId": &log_entry.get_version_id()}),
            None,
            &secret,
            None,
        )
        .map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate Data Integrity Proof for LogEntry. Reason: {e}",
            ))
        })?;

        // Save proof to collection
        witness_proofs
            .add_proof(&log_entry.get_version_id(), &proof, false)
            .map_err(|e| DIDWebVHError::WitnessProofError(format!("Error adding proof: {e}")))?;
    }

    // Strip out any duplicate records where we can
    witness_proofs.write_optimise_records()?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DIDWebVHState,
        witness::Witness,
    };
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;
    use std::sync::Arc;

    /// Helper: generate a signing key and matching parameters with update_keys set.
    fn key_and_params() -> (Secret, Parameters) {
        let key = Secret::generate_ed25519(None, None);
        let params = Parameters {
            update_keys: Some(Arc::new(vec![key.get_public_keymultibase().unwrap()])),
            ..Default::default()
        };
        (key, params)
    }

    /// Helper: build a minimal DID document for the given DID string.
    /// Uses the provided key's public key in the verification method so that
    /// log entry signature validation succeeds.
    fn did_doc_with_key(did: &str, key: &Secret) -> Value {
        let pk = key.get_public_keymultibase().unwrap();
        json!({
            "id": did,
            "@context": ["https://www.w3.org/ns/did/v1"],
            "verificationMethod": [{
                "id": format!("{did}#key-0"),
                "type": "Multikey",
                "publicKeyMultibase": pk,
                "controller": did
            }],
            "authentication": [format!("{did}#key-0")],
            "assertionMethod": [format!("{did}#key-0")],
        })
    }

    /// Helper: create a first log entry and its LogEntryState (for witness tests).
    fn create_log_entry_state(key: &Secret, params: &Parameters) -> (DIDWebVHState, String) {
        let mut state = DIDWebVHState::default();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", key);
        state
            .create_log_entry(None, &doc, params, key)
            .expect("Failed to create log entry");
        let version_id = state.log_entries.last().unwrap().get_version_id();
        (state, version_id)
    }

    // -----------------------------------------------------------------------
    // Builder tests
    // -----------------------------------------------------------------------

    #[test]
    fn builder_missing_address() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let result = CreateDIDConfig::builder()
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn builder_missing_authorization_keys() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let result = CreateDIDConfig::builder()
            .address("https://example.com/")
            .did_document(doc)
            .parameters(params)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn builder_missing_did_document() {
        let (key, params) = key_and_params();
        let result = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .parameters(params)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn builder_missing_parameters() {
        let (key, _) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let result = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn builder_all_required_fields() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let result = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn builder_authorization_keys_replaces() {
        let key1 = Secret::generate_ed25519(None, None);
        let key2 = Secret::generate_ed25519(None, None);
        let (_, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key2);

        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key1)
            .authorization_keys(vec![key2])
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        assert_eq!(config.authorization_keys.len(), 1);
    }

    #[test]
    fn builder_witness_secrets() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let witness_key = Secret::generate_ed25519(None, None);

        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .witness_secret("did:key:z6Mk1", witness_key)
            .build()
            .unwrap();

        assert_eq!(config.witness_secrets.len(), 1);
        assert!(config.witness_secrets.contains_key("did:key:z6Mk1"));
    }

    #[test]
    fn builder_defaults() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        assert!(!config.also_known_as_web);
        assert!(!config.also_known_as_scid);
        assert!(config.witness_secrets.is_empty());
    }

    // -----------------------------------------------------------------------
    // create_did tests
    // -----------------------------------------------------------------------

    #[test]
    fn create_did_with_url_address() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        let result = create_did(config);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.did.starts_with("did:webvh:"));
        assert!(result.did.contains("example.com"));
        assert!(!result.did.contains("{SCID}"));
    }

    #[test]
    fn create_did_with_did_address() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig::builder()
            .address("did:webvh:{SCID}:example.com")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        let result = create_did(config);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.did.starts_with("did:webvh:"));
        assert!(!result.did.contains("{SCID}"));
    }

    #[test]
    fn create_did_invalid_address() {
        let (key, _params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig {
            address: "not a valid url or did".to_string(),
            authorization_keys: vec![key],
            did_document: doc,
            parameters: _params,
            witness_secrets: HashMap::default(),
            also_known_as_web: false,
            also_known_as_scid: false,
        };

        assert!(create_did(config).is_err());
    }

    #[test]
    fn create_did_no_update_keys() {
        let key = Secret::generate_ed25519(None, None);
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let params = Parameters::default(); // no update_keys

        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        assert!(create_did(config).is_err());
    }

    #[test]
    fn create_did_with_also_known_as_web() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .also_known_as_web(true)
            .build()
            .unwrap();

        let result = create_did(config).unwrap();
        let state = result.log_entry.get_state();
        let also_known_as = state.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert!(also_known_as.iter().any(|v| {
            v.as_str().map_or(false, |s| s.starts_with("did:web:"))
        }));
    }

    #[test]
    fn create_did_with_also_known_as_scid() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .also_known_as_scid(true)
            .build()
            .unwrap();

        let result = create_did(config).unwrap();
        let state = result.log_entry.get_state();
        let also_known_as = state.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert!(also_known_as.iter().any(|v| {
            v.as_str().map_or(false, |s| s.starts_with("did:scid:vh:"))
        }));
    }

    #[test]
    fn create_did_with_both_aliases() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .also_known_as_web(true)
            .also_known_as_scid(true)
            .build()
            .unwrap();

        let result = create_did(config).unwrap();
        let state = result.log_entry.get_state();
        let also_known_as = state.get("alsoKnownAs").unwrap().as_array().unwrap();
        let has_web = also_known_as.iter().any(|v| {
            v.as_str().map_or(false, |s| s.starts_with("did:web:"))
        });
        let has_scid = also_known_as.iter().any(|v| {
            v.as_str().map_or(false, |s| s.starts_with("did:scid:vh:"))
        });
        assert!(has_web);
        assert!(has_scid);
    }

    #[test]
    fn create_did_no_witnesses_returns_empty_proofs() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        let result = create_did(config).unwrap();
        assert_eq!(result.witness_proofs.get_total_count(), 0);
    }

    #[test]
    fn create_did_with_witnesses() {
        let (key, _) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let witness1 = Secret::generate_ed25519(None, None);
        let witness2 = Secret::generate_ed25519(None, None);
        let w1_id = witness1.get_public_keymultibase().unwrap();
        let w2_id = witness2.get_public_keymultibase().unwrap();

        let params = Parameters {
            update_keys: Some(Arc::new(vec![key.get_public_keymultibase().unwrap()])),
            witness: Some(Arc::new(Witnesses::Value {
                threshold: 1,
                witnesses: vec![
                    Witness { id: w1_id.clone() },
                    Witness { id: w2_id.clone() },
                ],
            })),
            ..Default::default()
        };

        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .witness_secret(w1_id, witness1)
            .witness_secret(w2_id, witness2)
            .build()
            .unwrap();

        let result = create_did(config).unwrap();
        assert_eq!(result.witness_proofs.get_total_count(), 2);
    }

    #[test]
    fn create_did_witnesses_missing_secret() {
        let (key, _) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let witness1 = Secret::generate_ed25519(None, None);
        let w1_id = witness1.get_public_keymultibase().unwrap();

        let params = Parameters {
            update_keys: Some(Arc::new(vec![key.get_public_keymultibase().unwrap()])),
            witness: Some(Arc::new(Witnesses::Value {
                threshold: 1,
                witnesses: vec![Witness { id: w1_id }],
            })),
            ..Default::default()
        };

        // Don't provide the witness secret
        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        assert!(create_did(config).is_err());
    }

    #[test]
    fn create_did_portable() {
        let (key, _) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let params = Parameters {
            update_keys: Some(Arc::new(vec![key.get_public_keymultibase().unwrap()])),
            portable: Some(true),
            ..Default::default()
        };

        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        let result = create_did(config).unwrap();
        assert!(result.did.starts_with("did:webvh:"));
    }

    #[test]
    fn create_did_log_entry_serializable() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        let result = create_did(config).unwrap();
        let json = serde_json::to_string(&result.log_entry);
        assert!(json.is_ok());
        assert!(!json.unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // add_web_also_known_as tests
    // -----------------------------------------------------------------------

    #[test]
    fn add_web_also_known_as_no_existing() {
        let mut doc = json!({"id": "did:webvh:abc123:example.com"});
        add_web_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();

        let aliases = doc.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].as_str().unwrap(), "did:web:example.com");
    }

    #[test]
    fn add_web_also_known_as_with_existing() {
        let mut doc = json!({
            "id": "did:webvh:abc123:example.com",
            "alsoKnownAs": ["did:example:other"]
        });
        add_web_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();

        let aliases = doc.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert_eq!(aliases.len(), 2);
        assert!(aliases.iter().any(|v| v.as_str() == Some("did:example:other")));
        assert!(aliases.iter().any(|v| v.as_str() == Some("did:web:example.com")));
    }

    #[test]
    fn add_web_also_known_as_already_present() {
        let mut doc = json!({
            "id": "did:webvh:abc123:example.com",
            "alsoKnownAs": ["did:web:example.com"]
        });
        add_web_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();

        let aliases = doc.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].as_str().unwrap(), "did:web:example.com");
    }

    #[test]
    fn add_web_also_known_as_not_array() {
        let mut doc = json!({
            "id": "did:webvh:abc123:example.com",
            "alsoKnownAs": "not an array"
        });
        assert!(add_web_also_known_as(&mut doc, "did:webvh:abc123:example.com").is_err());
    }

    // -----------------------------------------------------------------------
    // add_scid_also_known_as tests
    // -----------------------------------------------------------------------

    #[test]
    fn add_scid_also_known_as_no_existing() {
        let mut doc = json!({"id": "did:webvh:abc123:example.com"});
        add_scid_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();

        let aliases = doc.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert_eq!(aliases.len(), 1);
        assert!(aliases[0].as_str().unwrap().starts_with("did:scid:vh:1:"));
    }

    #[test]
    fn add_scid_also_known_as_with_existing() {
        let mut doc = json!({
            "id": "did:webvh:abc123:example.com",
            "alsoKnownAs": ["did:example:other"]
        });
        add_scid_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();

        let aliases = doc.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert_eq!(aliases.len(), 2);
        assert!(aliases.iter().any(|v| v.as_str() == Some("did:example:other")));
        assert!(aliases.iter().any(|v| {
            v.as_str().map_or(false, |s| s.starts_with("did:scid:vh:1:"))
        }));
    }

    #[test]
    fn add_scid_also_known_as_already_present() {
        let scid_id = DIDWebVHState::convert_webvh_id_to_scid_id("did:webvh:abc123:example.com");
        let mut doc = json!({
            "id": "did:webvh:abc123:example.com",
            "alsoKnownAs": [scid_id]
        });
        add_scid_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();

        let aliases = doc.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert_eq!(aliases.len(), 1);
    }

    #[test]
    fn add_scid_also_known_as_not_array() {
        let mut doc = json!({
            "id": "did:webvh:abc123:example.com",
            "alsoKnownAs": 42
        });
        assert!(add_scid_also_known_as(&mut doc, "did:webvh:abc123:example.com").is_err());
    }

    // -----------------------------------------------------------------------
    // sign_witness_proofs tests
    // -----------------------------------------------------------------------

    #[test]
    fn sign_witness_proofs_no_witnesses() {
        let (key, params) = key_and_params();
        let (state, _) = create_log_entry_state(&key, &params);
        let log_entry = state.log_entries.last().unwrap();

        let mut proofs = WitnessProofCollection::default();
        let result = sign_witness_proofs(&mut proofs, log_entry, &None, &HashMap::default());
        assert!(result.is_ok());
        assert!(!result.unwrap()); // false = no witnesses
        assert_eq!(proofs.get_total_count(), 0);
    }

    #[test]
    fn sign_witness_proofs_with_witnesses() {
        let (key, _) = key_and_params();
        let witness1 = Secret::generate_ed25519(None, None);
        let witness2 = Secret::generate_ed25519(None, None);
        let w1_id = witness1.get_public_keymultibase().unwrap();
        let w2_id = witness2.get_public_keymultibase().unwrap();

        let params = Parameters {
            update_keys: Some(Arc::new(vec![key.get_public_keymultibase().unwrap()])),
            witness: Some(Arc::new(Witnesses::Value {
                threshold: 1,
                witnesses: vec![
                    Witness { id: w1_id.clone() },
                    Witness { id: w2_id.clone() },
                ],
            })),
            ..Default::default()
        };

        let (state, version_id) = create_log_entry_state(&key, &params);
        let log_entry = state.log_entries.last().unwrap();

        let mut secrets = HashMap::default();
        secrets.insert(w1_id, witness1);
        secrets.insert(w2_id, witness2);

        let witnesses = log_entry.get_active_witnesses();
        let mut proofs = WitnessProofCollection::default();
        let result = sign_witness_proofs(&mut proofs, log_entry, &witnesses, &secrets);
        assert!(result.is_ok());
        assert!(result.unwrap()); // true = witnesses signed
        assert_eq!(proofs.get_proof_count(&version_id), 2);
    }

    #[test]
    fn sign_witness_proofs_missing_secret() {
        let (key, _) = key_and_params();
        let witness1 = Secret::generate_ed25519(None, None);
        let w1_id = witness1.get_public_keymultibase().unwrap();

        let params = Parameters {
            update_keys: Some(Arc::new(vec![key.get_public_keymultibase().unwrap()])),
            witness: Some(Arc::new(Witnesses::Value {
                threshold: 1,
                witnesses: vec![Witness { id: w1_id }],
            })),
            ..Default::default()
        };

        let (state, _) = create_log_entry_state(&key, &params);
        let log_entry = state.log_entries.last().unwrap();

        let witnesses = log_entry.get_active_witnesses();
        let mut proofs = WitnessProofCollection::default();
        // Empty secrets map — secret for witness not provided
        let result = sign_witness_proofs(&mut proofs, log_entry, &witnesses, &HashMap::default());
        assert!(result.is_err());
    }

    #[test]
    fn sign_witness_proofs_empty_witnesses_config() {
        let (key, params) = key_and_params();
        let (state, _) = create_log_entry_state(&key, &params);
        let log_entry = state.log_entries.last().unwrap();

        let witnesses = Some(Arc::new(Witnesses::Empty {}));
        let mut proofs = WitnessProofCollection::default();
        let result = sign_witness_proofs(&mut proofs, log_entry, &witnesses, &HashMap::default());
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // ensure_did_key_id tests
    // -----------------------------------------------------------------------

    #[test]
    fn ensure_did_key_id_normalizes_random_id() {
        let mut key = Secret::generate_ed25519(None, None);
        let pub_mb = key.get_public_keymultibase().unwrap();
        // Default id is a random base64url value, not a did:key
        assert!(!key.id.starts_with("did:key:"));

        ensure_did_key_id(&mut key).unwrap();

        assert_eq!(key.id, format!("did:key:{pub_mb}#{pub_mb}"));
    }

    #[test]
    fn ensure_did_key_id_preserves_existing() {
        let mut key = Secret::generate_ed25519(None, None);
        let pub_mb = key.get_public_keymultibase().unwrap();
        let did_key_id = format!("did:key:{pub_mb}#{pub_mb}");
        key.id = did_key_id.clone();

        ensure_did_key_id(&mut key).unwrap();

        // Should be unchanged
        assert_eq!(key.id, did_key_id);
    }

    #[test]
    fn ensure_did_key_id_explicit_kid() {
        // Key created with an explicit kid that is already a did:key
        let pub_mb_source = Secret::generate_ed25519(None, None);
        let pub_mb = pub_mb_source.get_public_keymultibase().unwrap();
        let kid = format!("did:key:{pub_mb}#{pub_mb}");
        let mut key = Secret::generate_ed25519(Some(&kid), None);

        assert_eq!(key.id, kid);
        ensure_did_key_id(&mut key).unwrap();
        // Still unchanged
        assert_eq!(key.id, kid);
    }

    // -----------------------------------------------------------------------
    // Additional builder tests
    // -----------------------------------------------------------------------

    #[test]
    fn builder_also_known_as_flags() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .also_known_as_web(true)
            .also_known_as_scid(true)
            .build()
            .unwrap();

        assert!(config.also_known_as_web);
        assert!(config.also_known_as_scid);
    }

    #[test]
    fn builder_multiple_authorization_keys_accumulate() {
        let key1 = Secret::generate_ed25519(None, None);
        let key2 = Secret::generate_ed25519(None, None);
        let (_, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key1);

        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key1)
            .authorization_key(key2)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        assert_eq!(config.authorization_keys.len(), 2);
    }

    #[test]
    fn builder_witness_secrets_bulk_replaces() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let w1 = Secret::generate_ed25519(None, None);
        let w2 = Secret::generate_ed25519(None, None);

        let mut bulk = HashMap::default();
        bulk.insert("did:key:z6MkBulk".to_string(), w2);

        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .witness_secret("did:key:z6MkSingle", w1)
            .witness_secrets(bulk)
            .build()
            .unwrap();

        // Bulk setter replaces the individual one
        assert_eq!(config.witness_secrets.len(), 1);
        assert!(config.witness_secrets.contains_key("did:key:z6MkBulk"));
        assert!(!config.witness_secrets.contains_key("did:key:z6MkSingle"));
    }

    // -----------------------------------------------------------------------
    // Additional create_did tests
    // -----------------------------------------------------------------------

    #[test]
    fn create_did_key_with_existing_did_key_id() {
        let mut key = Secret::generate_ed25519(None, None);
        let pub_mb = key.get_public_keymultibase().unwrap();
        key.id = format!("did:key:{pub_mb}#{pub_mb}");

        let params = Parameters {
            update_keys: Some(Arc::new(vec![pub_mb])),
            ..Default::default()
        };
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);

        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        let result = create_did(config);
        assert!(result.is_ok());
    }

    #[test]
    fn create_did_state_has_no_scid_placeholder() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        let result = create_did(config).unwrap();

        // Verify SCID placeholder is replaced everywhere
        let state_str = serde_json::to_string(result.log_entry.get_state()).unwrap();
        assert!(!state_str.contains("{SCID}"));
        assert!(!result.did.contains("{SCID}"));
    }

    #[test]
    fn create_did_log_entry_has_proof() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        let result = create_did(config).unwrap();
        assert!(!result.log_entry.get_proofs().is_empty());
    }

    #[test]
    fn create_did_version_id_starts_with_one() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        let result = create_did(config).unwrap();
        let version_id = result.log_entry.get_version_id();
        assert!(version_id.starts_with("1-"));
    }

    #[test]
    fn create_did_with_url_path() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com:dids:alice", &key);
        let config = CreateDIDConfig::builder()
            .address("https://example.com/dids/alice/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        let result = create_did(config).unwrap();
        assert!(result.did.starts_with("did:webvh:"));
        assert!(result.did.contains("example.com"));
    }

    #[test]
    fn create_did_result_did_matches_state_id() {
        let (key, params) = key_and_params();
        let doc = did_doc_with_key("did:webvh:{SCID}:example.com", &key);
        let config = CreateDIDConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .did_document(doc)
            .parameters(params)
            .build()
            .unwrap();

        let result = create_did(config).unwrap();
        let state_id = result.log_entry.get_state()
            .get("id").unwrap()
            .as_str().unwrap();
        assert_eq!(result.did, state_id);
    }

    // -----------------------------------------------------------------------
    // Additional add_web_also_known_as tests
    // -----------------------------------------------------------------------

    #[test]
    fn add_web_also_known_as_empty_array() {
        let mut doc = json!({
            "id": "did:webvh:abc123:example.com",
            "alsoKnownAs": []
        });
        add_web_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();

        let aliases = doc.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].as_str().unwrap(), "did:web:example.com");
    }

    #[test]
    fn add_web_also_known_as_idempotent() {
        let mut doc = json!({"id": "did:webvh:abc123:example.com"});
        add_web_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();
        add_web_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();

        let aliases = doc.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].as_str().unwrap(), "did:web:example.com");
    }

    #[test]
    fn add_web_also_known_as_preserves_all_existing() {
        let mut doc = json!({
            "id": "did:webvh:abc123:example.com",
            "alsoKnownAs": ["did:example:a", "did:example:b", "did:web:example.com"]
        });
        add_web_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();

        let aliases = doc.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert_eq!(aliases.len(), 3);
        assert!(aliases.iter().any(|v| v.as_str() == Some("did:example:a")));
        assert!(aliases.iter().any(|v| v.as_str() == Some("did:example:b")));
        assert!(aliases.iter().any(|v| v.as_str() == Some("did:web:example.com")));
    }

    // -----------------------------------------------------------------------
    // Additional add_scid_also_known_as tests
    // -----------------------------------------------------------------------

    #[test]
    fn add_scid_also_known_as_empty_array() {
        let mut doc = json!({
            "id": "did:webvh:abc123:example.com",
            "alsoKnownAs": []
        });
        add_scid_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();

        let aliases = doc.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert_eq!(aliases.len(), 1);
        assert!(aliases[0].as_str().unwrap().starts_with("did:scid:vh:1:"));
    }

    #[test]
    fn add_scid_also_known_as_idempotent() {
        let mut doc = json!({"id": "did:webvh:abc123:example.com"});
        add_scid_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();
        add_scid_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();

        let aliases = doc.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert_eq!(aliases.len(), 1);
    }

    #[test]
    fn add_scid_also_known_as_preserves_all_existing() {
        let scid_id = DIDWebVHState::convert_webvh_id_to_scid_id("did:webvh:abc123:example.com");
        let mut doc = json!({
            "id": "did:webvh:abc123:example.com",
            "alsoKnownAs": ["did:example:a", "did:example:b", scid_id]
        });
        add_scid_also_known_as(&mut doc, "did:webvh:abc123:example.com").unwrap();

        let aliases = doc.get("alsoKnownAs").unwrap().as_array().unwrap();
        assert_eq!(aliases.len(), 3);
        assert!(aliases.iter().any(|v| v.as_str() == Some("did:example:a")));
        assert!(aliases.iter().any(|v| v.as_str() == Some("did:example:b")));
    }

    // -----------------------------------------------------------------------
    // Additional sign_witness_proofs tests
    // -----------------------------------------------------------------------

    #[test]
    fn sign_witness_proofs_are_verifiable() {
        let (key, _) = key_and_params();
        let witness1 = Secret::generate_ed25519(None, None);
        let w1_id = witness1.get_public_keymultibase().unwrap();

        let params = Parameters {
            update_keys: Some(Arc::new(vec![key.get_public_keymultibase().unwrap()])),
            witness: Some(Arc::new(Witnesses::Value {
                threshold: 1,
                witnesses: vec![Witness { id: w1_id.clone() }],
            })),
            ..Default::default()
        };

        let (state, version_id) = create_log_entry_state(&key, &params);
        let log_entry_state = state.log_entries.last().unwrap();

        let mut secrets = HashMap::default();
        secrets.insert(w1_id, witness1);

        let witnesses = log_entry_state.get_active_witnesses();
        let mut proofs = WitnessProofCollection::default();
        sign_witness_proofs(&mut proofs, log_entry_state, &witnesses, &secrets).unwrap();

        // Verify the proof can be validated by the log entry
        let witness_proof = proofs.get_proofs(&version_id).unwrap();
        let validation = log_entry_state.log_entry.validate_witness_proof(
            witness_proof.proof.first().unwrap(),
        );
        assert!(validation.is_ok());
    }

    #[test]
    fn sign_witness_proofs_returns_true_with_witnesses() {
        let (key, _) = key_and_params();
        let witness1 = Secret::generate_ed25519(None, None);
        let w1_id = witness1.get_public_keymultibase().unwrap();

        let params = Parameters {
            update_keys: Some(Arc::new(vec![key.get_public_keymultibase().unwrap()])),
            witness: Some(Arc::new(Witnesses::Value {
                threshold: 1,
                witnesses: vec![Witness { id: w1_id.clone() }],
            })),
            ..Default::default()
        };

        let (state, _) = create_log_entry_state(&key, &params);
        let log_entry_state = state.log_entries.last().unwrap();

        let mut secrets = HashMap::default();
        secrets.insert(w1_id, witness1);

        let witnesses = log_entry_state.get_active_witnesses();
        let mut proofs = WitnessProofCollection::default();
        let signed = sign_witness_proofs(&mut proofs, log_entry_state, &witnesses, &secrets).unwrap();
        assert!(signed);
    }

    #[test]
    fn sign_witness_proofs_returns_false_no_witnesses() {
        let (key, params) = key_and_params();
        let (state, _) = create_log_entry_state(&key, &params);
        let log_entry = state.log_entries.last().unwrap();

        let mut proofs = WitnessProofCollection::default();
        let signed = sign_witness_proofs(&mut proofs, log_entry, &None, &HashMap::default()).unwrap();
        assert!(!signed);
    }

    #[test]
    fn replace_did_placeholder_replaces_all_occurrences() {
        let did = "did:webvh:abc:example.com".to_string();

        let mut did_document = json!({
            "id": "{DID}",
            "@context": ["https://www.w3.org/ns/did/v1"],
            "verificationMethod": [{
                "id": "{DID}#key-0",
                "type": "Multikey",
                "publicKeyMultibase": "abcd",
                "controller": "{DID}"
            }],
            "authentication": ["{DID}#key-0"],
            "assertionMethod": ["{DID}#key-0"],
        });

        let expected_document = json!({
            "id": "did:webvh:abc:example.com",
            "@context": ["https://www.w3.org/ns/did/v1"],
            "verificationMethod": [{
                "id": "did:webvh:abc:example.com#key-0",
                "type": "Multikey",
                "publicKeyMultibase": "abcd",
                "controller": did
            }],
            "authentication": ["did:webvh:abc:example.com#key-0"],
            "assertionMethod": ["did:webvh:abc:example.com#key-0"],
        });

        replace_did_placeholder(&mut did_document, &did);

        assert_eq!(did_document, expected_document);
    }

    #[test]
    fn replace_did_placeholder_no_op() {
        let did = "did:webvh:abc:example.com".to_string();

        let mut did_document = json!({
            "a": 1,
            "b": {
                "c": null
            }
        });

        let expected_document = json!({
            "a": 1,
            "b": {
                "c": null
            }
        });

        replace_did_placeholder(&mut did_document, &did);

        assert_eq!(did_document, expected_document);
    }
}
