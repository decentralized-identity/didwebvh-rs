/*!
 * Library API for updating an existing webvh DID programmatically.
 *
 * Provides [`update_did()`] as the high-level entry point for DID updates,
 * complementing [`crate::create::create_did()`] for DID creation.
 *
 * Handles document changes, key rotation, parameter updates, domain migration,
 * deactivation (with automatic pre-rotation teardown), and witness proof signing.
 *
 * # Example
 *
 * ```ignore
 * use didwebvh_rs::prelude::*;
 * use didwebvh_rs::update::{UpdateDIDConfig, update_did};
 *
 * // Rotate keys
 * let config = UpdateDIDConfig::builder()
 *     .state(webvh_state)
 *     .signing_key(current_key)
 *     .update_keys(vec![new_key_multibase])
 *     .build()?;
 * let result = update_did(config).await?;
 * ```
 */

use crate::{
    DIDWebVHError, DIDWebVHState, Multibase, Signer, create::sign_witness_proofs,
    ensure_object_mut, log_entry::LogEntry, parameters::Parameters, url::WebVHURL,
    witness::Witnesses,
};
use affinidi_secrets_resolver::secrets::Secret;
use ahash::HashMap;
use serde_json::Value;
use std::sync::Arc;
use url::Url;

/// Configuration for updating an existing DID.
///
/// Generic over `A` (signing key) and `W` (witness signer), both defaulting to [`Secret`].
///
/// Use [`UpdateDIDConfig::builder()`] to construct. At minimum, `state` and `signing_key`
/// are required. All other fields are optional — only the fields you set will be changed.
///
/// # Examples
///
/// Update the DID document:
///
/// ```ignore
/// let config = UpdateDIDConfig::builder()
///     .state(webvh_state)
///     .signing_key(key)
///     .document(new_doc)
///     .build()?;
/// let result = update_did(config).await?;
/// ```
///
/// Rotate authorization keys:
///
/// ```ignore
/// let config = UpdateDIDConfig::builder()
///     .state(webvh_state)
///     .signing_key(current_key)
///     .update_keys(vec![new_key_multibase])
///     .build()?;
/// ```
///
/// Deactivate a DID:
///
/// ```ignore
/// let config = UpdateDIDConfig::builder()
///     .state(webvh_state)
///     .signing_key(key)
///     .deactivate(true)
///     .build()?;
/// ```
///
/// Migrate to a new domain:
///
/// ```ignore
/// let config = UpdateDIDConfig::builder()
///     .state(webvh_state)
///     .signing_key(key)
///     .migrate_to("https://new-domain.example.com/")
///     .build()?;
/// ```
pub struct UpdateDIDConfig<A: Signer = Secret, W: Signer = Secret> {
    /// The DID WebVH state to update (must have at least one log entry).
    pub state: DIDWebVHState,
    /// The signer for this update (must be an active authorization key or pre-rotation key).
    pub signing_key: A,
    /// New DID document. `None` = keep current document.
    pub document: Option<Value>,
    /// New authorization keys. `None` = keep current.
    pub update_keys: Option<Vec<Multibase>>,
    /// New pre-rotation key hashes. `None` = keep current. `Some(vec![])` = disable pre-rotation.
    pub next_key_hashes: Option<Vec<Multibase>>,
    /// New witness configuration. `None` = keep current. `Some(Witnesses::Empty{})` = disable.
    pub witness: Option<Witnesses>,
    /// New watcher URLs. `None` = keep current. `Some(vec![])` = disable.
    pub watchers: Option<Vec<String>>,
    /// New TTL in seconds. `None` = keep current.
    pub ttl: Option<u32>,
    /// Disable portability. Only applicable if currently portable. `None` = keep current.
    pub portable: Option<bool>,
    /// Deactivate the DID permanently. Creates a final log entry with empty update_keys.
    /// If pre-rotation is active, an intermediate entry is created to disable it first.
    pub deactivated: bool,
    /// Migrate the DID to a new URL. Rewrites all DID references in the document and
    /// adds the previous DID to `alsoKnownAs`. Requires `portable = true` on the DID.
    pub migrate_to: Option<String>,
    /// Witness signing secrets keyed by witness DID.
    pub witness_secrets: HashMap<String, W>,
}

/// Builder for constructing an [`UpdateDIDConfig`].
///
/// Only `state` and `signing_key` are required.
/// All parameter fields default to `None` (no change).
pub struct UpdateDIDConfigBuilder<A: Signer = Secret, W: Signer = Secret> {
    state: Option<DIDWebVHState>,
    signing_key: Option<A>,
    document: Option<Value>,
    update_keys: Option<Vec<Multibase>>,
    next_key_hashes: Option<Vec<Multibase>>,
    witness: Option<Witnesses>,
    watchers: Option<Vec<String>>,
    ttl: Option<u32>,
    portable: Option<bool>,
    deactivated: bool,
    migrate_to: Option<String>,
    witness_secrets: HashMap<String, W>,
}

impl<A: Signer, W: Signer> UpdateDIDConfigBuilder<A, W> {
    fn new() -> Self {
        Self {
            state: None,
            signing_key: None,
            document: None,
            update_keys: None,
            next_key_hashes: None,
            witness: None,
            watchers: None,
            ttl: None,
            portable: None,
            deactivated: false,
            migrate_to: None,
            witness_secrets: HashMap::default(),
        }
    }

    /// Set the DID WebVH state to update. Required.
    pub fn state(mut self, state: DIDWebVHState) -> Self {
        self.state = Some(state);
        self
    }

    /// Set the signing key for this update. Required.
    pub fn signing_key(mut self, key: A) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Set a new DID document. If not called, the current document is preserved.
    pub fn document(mut self, doc: Value) -> Self {
        self.document = Some(doc);
        self
    }

    /// Set new authorization keys. Replaces the current `update_keys`.
    pub fn update_keys(mut self, keys: Vec<Multibase>) -> Self {
        self.update_keys = Some(keys);
        self
    }

    /// Set new pre-rotation key hashes. Pass an empty vec to disable pre-rotation.
    pub fn next_key_hashes(mut self, hashes: Vec<Multibase>) -> Self {
        self.next_key_hashes = Some(hashes);
        self
    }

    /// Set new witness configuration. Pass `Witnesses::Empty{}` to disable witnesses.
    pub fn witness(mut self, witnesses: Witnesses) -> Self {
        self.witness = Some(witnesses);
        self
    }

    /// Set new watcher URLs. Pass an empty vec to disable watchers.
    pub fn watchers(mut self, watchers: Vec<String>) -> Self {
        self.watchers = Some(watchers);
        self
    }

    /// Set a new TTL in seconds.
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Disable portability. Only valid if the DID currently has `portable = true`.
    pub fn disable_portability(mut self) -> Self {
        self.portable = Some(false);
        self
    }

    /// Deactivate the DID permanently. This is irreversible.
    /// If pre-rotation is active, an intermediate log entry is created to disable it first.
    pub fn deactivate(mut self, deactivated: bool) -> Self {
        self.deactivated = deactivated;
        self
    }

    /// Migrate the DID to a new URL or DID address. Requires `portable = true`.
    /// All DID references in the document are rewritten, and the previous DID
    /// is added to `alsoKnownAs`.
    pub fn migrate_to(mut self, address: impl Into<String>) -> Self {
        self.migrate_to = Some(address.into());
        self
    }

    /// Add a witness signing secret keyed by witness DID.
    pub fn witness_secret(mut self, did: impl Into<String>, secret: W) -> Self {
        self.witness_secrets.insert(did.into(), secret);
        self
    }

    /// Set all witness signing secrets at once.
    pub fn witness_secrets(mut self, secrets: HashMap<String, W>) -> Self {
        self.witness_secrets = secrets;
        self
    }

    /// Build the [`UpdateDIDConfig`], returning an error if required fields are missing.
    pub fn build(self) -> Result<UpdateDIDConfig<A, W>, DIDWebVHError> {
        let state = self
            .state
            .ok_or_else(|| DIDWebVHError::DIDError("state is required".to_string()))?;
        let signing_key = self
            .signing_key
            .ok_or_else(|| DIDWebVHError::DIDError("signing_key is required".to_string()))?;

        if state.log_entries().is_empty() {
            return Err(DIDWebVHError::LogEntryError(
                "State must have at least one log entry to update".to_string(),
            ));
        }

        Ok(UpdateDIDConfig {
            state,
            signing_key,
            document: self.document,
            update_keys: self.update_keys,
            next_key_hashes: self.next_key_hashes,
            witness: self.witness,
            watchers: self.watchers,
            ttl: self.ttl,
            portable: self.portable,
            deactivated: self.deactivated,
            migrate_to: self.migrate_to,
            witness_secrets: self.witness_secrets,
        })
    }
}

impl UpdateDIDConfig {
    /// Create a new builder for `UpdateDIDConfig` using default signer types (`Secret`).
    pub fn builder() -> UpdateDIDConfigBuilder {
        UpdateDIDConfigBuilder::new()
    }
}

impl<A: Signer, W: Signer> UpdateDIDConfig<A, W> {
    /// Create a new builder for `UpdateDIDConfig` with custom signer types.
    pub fn builder_generic() -> UpdateDIDConfigBuilder<A, W> {
        UpdateDIDConfigBuilder::new()
    }
}

/// Result of updating a DID.
#[derive(Debug)]
pub struct UpdateDIDResult {
    /// The DID identifier (may change after migration).
    did: String,
    /// The new log entry (the last one created). For deactivation with pre-rotation,
    /// two entries are created — this is the final deactivation entry.
    log_entry: LogEntry,
    /// The full DID WebVH state with all log entries and witness proofs.
    state: DIDWebVHState,
}

impl UpdateDIDResult {
    /// The DID identifier after the update.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The newly created log entry.
    pub fn log_entry(&self) -> &LogEntry {
        &self.log_entry
    }

    /// The full DID WebVH state (all log entries + witness proofs).
    /// Use this to save the updated state to files.
    pub fn state(&self) -> &DIDWebVHState {
        &self.state
    }

    /// Consume the result and take ownership of the state.
    pub fn into_state(self) -> DIDWebVHState {
        self.state
    }
}

/// Update an existing DID using the provided configuration.
///
/// This is the main library entry point for DID updates. It handles:
///
/// 1. **Document updates** — Replace the DID document with a new version
/// 2. **Key rotation** — Change authorization keys (`update_keys`)
/// 3. **Parameter changes** — Modify witnesses, watchers, TTL, pre-rotation, portability
/// 4. **Migration** — Move the DID to a new domain (rewrites identifiers, adds alias)
/// 5. **Deactivation** — Permanently deactivate the DID (with automatic pre-rotation
///    teardown if needed)
/// 6. **Witness signing** — Signs witness proofs for all new log entries
///
/// # Examples
///
/// ```ignore
/// use didwebvh_rs::update::{UpdateDIDConfig, update_did};
///
/// // Update the document
/// let result = update_did(
///     UpdateDIDConfig::builder()
///         .state(webvh_state)
///         .signing_key(key)
///         .document(new_doc)
///         .build()?
/// ).await?;
///
/// // Save results
/// result.log_entry().save_to_file("did.jsonl")?;
/// result.state().witness_proofs().save_to_file("did-witness.json")?;
/// ```
pub async fn update_did<A: Signer, W: Signer>(
    mut config: UpdateDIDConfig<A, W>,
) -> Result<UpdateDIDResult, DIDWebVHError> {
    // Handle migration separately — it modifies the document
    if config.migrate_to.is_some() {
        let new_address = config.migrate_to.clone().unwrap();
        return do_migrate(config, new_address).await;
    }

    // Handle deactivation separately — may need pre-rotation teardown
    if config.deactivated {
        return do_deactivate(config).await;
    }

    // Standard update: build parameters and create log entry
    let last_params = config
        .state
        .log_entries()
        .last()
        .map(|e| e.validated_parameters.clone())
        .ok_or_else(|| DIDWebVHError::LogEntryError("No log entries exist".to_string()))?;

    let document = config.document.unwrap_or_else(|| {
        config
            .state
            .log_entries()
            .last()
            .unwrap()
            .get_state()
            .clone()
    });

    let mut params = last_params;
    if let Some(keys) = config.update_keys {
        params.update_keys = Some(Arc::new(keys));
    }
    if let Some(hashes) = config.next_key_hashes {
        params.next_key_hashes = Some(Arc::new(hashes));
    }
    if let Some(witness) = config.witness {
        params.witness = Some(Arc::new(witness));
    }
    if let Some(watchers) = config.watchers {
        params.watchers = Some(Arc::new(watchers));
    }
    if let Some(ttl) = config.ttl {
        params.ttl = Some(ttl);
    }
    if let Some(portable) = config.portable {
        params.portable = Some(portable);
    }

    config
        .state
        .create_log_entry(None, &document, &params, &config.signing_key)
        .await?;

    // Sign witness proofs
    sign_new_entry_witnesses(&mut config.state, &config.witness_secrets).await?;

    build_result(config.state)
}

/// Handle DID migration to a new domain.
async fn do_migrate<A: Signer, W: Signer>(
    mut config: UpdateDIDConfig<A, W>,
    new_address: String,
) -> Result<UpdateDIDResult, DIDWebVHError> {
    let last_entry = config
        .state
        .log_entries()
        .last()
        .ok_or_else(|| DIDWebVHError::LogEntryError("No log entries exist".to_string()))?;

    if last_entry.validated_parameters.portable != Some(true) {
        return Err(DIDWebVHError::ParametersError(
            "DID must have portable=true to migrate".to_string(),
        ));
    }

    let did = last_entry
        .get_state()
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DIDWebVHError::DIDError("DID not found in log entry state".to_string()))?
        .to_string();

    let did_url = WebVHURL::parse_did_url(&did)?;

    // Parse the new address
    let mut new_did_url = if new_address.starts_with("did:") {
        WebVHURL::parse_did_url(&new_address)?
    } else {
        let url = Url::parse(&new_address)
            .map_err(|e| DIDWebVHError::DIDError(format!("Invalid URL: {e}")))?;
        WebVHURL::parse_url(&url)?
    };
    new_did_url.scid = did_url.scid.clone();

    // Rewrite all DID references in the document
    let doc_str = serde_json::to_string(last_entry.get_state())
        .map_err(|e| DIDWebVHError::DIDError(format!("Failed to serialize document: {e}")))?;
    let new_doc_str = doc_str.replace(&did_url.to_string(), &new_did_url.to_string());
    let mut new_doc: Value = serde_json::from_str(&new_doc_str)
        .map_err(|e| DIDWebVHError::DIDError(format!("Failed to parse document: {e}")))?;

    // Add previous DID to alsoKnownAs
    if let Some(alias) = new_doc.get_mut("alsoKnownAs") {
        if let Some(arr) = alias.as_array_mut() {
            arr.push(Value::String(did));
        }
    } else {
        ensure_object_mut(&mut new_doc)?.insert(
            "alsoKnownAs".to_string(),
            Value::Array(vec![Value::String(did)]),
        );
    }

    // Build parameters (apply any additional changes from config)
    let mut params = last_entry.validated_parameters.clone();
    if let Some(keys) = config.update_keys {
        params.update_keys = Some(Arc::new(keys));
    }
    if let Some(hashes) = config.next_key_hashes {
        params.next_key_hashes = Some(Arc::new(hashes));
    }
    if let Some(witness) = config.witness {
        params.witness = Some(Arc::new(witness));
    }
    if let Some(watchers) = config.watchers {
        params.watchers = Some(Arc::new(watchers));
    }
    if let Some(ttl) = config.ttl {
        params.ttl = Some(ttl);
    }

    config
        .state
        .create_log_entry(None, &new_doc, &params, &config.signing_key)
        .await?;

    sign_new_entry_witnesses(&mut config.state, &config.witness_secrets).await?;

    build_result(config.state)
}

/// Handle DID deactivation, with automatic pre-rotation teardown if needed.
async fn do_deactivate<A: Signer, W: Signer>(
    mut config: UpdateDIDConfig<A, W>,
) -> Result<UpdateDIDResult, DIDWebVHError> {
    let last_entry = config
        .state
        .log_entries()
        .last()
        .ok_or_else(|| DIDWebVHError::LogEntryError("No log entries exist".to_string()))?;

    // If pre-rotation is active, create an intermediate entry to disable it first
    if last_entry.validated_parameters.pre_rotation_active {
        let doc = last_entry.get_state().clone();
        let vm = config.signing_key.verification_method();
        let pk = vm.split('#').next().unwrap_or(vm);
        let pk = pk.strip_prefix("did:key:").unwrap_or(pk);

        let disable_params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(pk.to_string())])),
            next_key_hashes: Some(Arc::new(Vec::new())),
            ..Default::default()
        };

        config
            .state
            .create_log_entry(None, &doc, &disable_params, &config.signing_key)
            .await?;

        // Sign witness proofs for the intermediate entry
        sign_new_entry_witnesses(&mut config.state, &config.witness_secrets).await?;
    }

    // Create the final deactivation entry
    let doc = config
        .state
        .log_entries()
        .last()
        .unwrap()
        .get_state()
        .clone();

    let deactivate_params = Parameters {
        deactivated: Some(true),
        update_keys: Some(Arc::new(Vec::new())),
        ..Default::default()
    };

    config
        .state
        .create_log_entry(None, &doc, &deactivate_params, &config.signing_key)
        .await?;

    sign_new_entry_witnesses(&mut config.state, &config.witness_secrets).await?;

    build_result(config.state)
}

/// Sign witness proofs for the most recent log entry in the state.
async fn sign_new_entry_witnesses<W: Signer>(
    state: &mut DIDWebVHState,
    witness_secrets: &HashMap<String, W>,
) -> Result<(), DIDWebVHError> {
    let (log_entries, witness_proofs) = state.log_entries_and_witness_proofs_mut();
    let entry = log_entries
        .last()
        .ok_or_else(|| DIDWebVHError::LogEntryError("No log entries after update".to_string()))?;

    sign_witness_proofs(
        witness_proofs,
        entry,
        &entry.get_active_witnesses(),
        witness_secrets,
    )
    .await?;

    Ok(())
}

/// Build the result from the final state.
fn build_result(state: DIDWebVHState) -> Result<UpdateDIDResult, DIDWebVHError> {
    let last_entry = state
        .log_entries()
        .last()
        .ok_or_else(|| DIDWebVHError::LogEntryError("No log entries after update".to_string()))?;

    let did = last_entry
        .get_state()
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let log_entry = last_entry.log_entry.clone();

    Ok(UpdateDIDResult {
        did,
        log_entry,
        state,
    })
}
