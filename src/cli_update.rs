/*!
 * Interactive CLI flow for updating an existing DID.
 *
 * Gated behind the `cli` feature flag. Third-party applications can use this
 * module to embed the DID update wizard in their own CLIs.
 *
 * # Supported Operations
 *
 * - **Modify**: Edit the DID document and/or change parameters (authorization keys,
 *   witnesses, watchers, TTL, portability)
 * - **Migrate**: Move the DID to a new domain (requires `portable = true`)
 * - **Revoke**: Permanently deactivate the DID
 *
 * # Usage
 *
 * ```ignore
 * use didwebvh_rs::cli_update::{InteractiveUpdateConfig, interactive_update_did};
 *
 * // Fully interactive - loads state from files, prompts for operation
 * let result = interactive_update_did(InteractiveUpdateConfig::default()).await?;
 *
 * // Pre-loaded state with secrets provided
 * let config = InteractiveUpdateConfig::builder()
 *     .state(webvh_state)
 *     .authorization_secrets(auth_secrets)
 *     .witness_secrets(witness_secrets)
 *     .build();
 * let result = interactive_update_did(config).await?;
 * ```
 */

use crate::{
    DIDWebVHError, DIDWebVHState, KeyType, Multibase, Secret, ValidationReport,
    cli_common::{
        map_io, map_key_err, prompt_confirm, prompt_edit_document, prompt_keys,
        prompt_next_key_hashes, prompt_witnesses,
    },
    create::sign_witness_proofs,
    did_key::generate_did_key,
    log_entry::LogEntry,
    log_entry_state::LogEntryState,
    parameters::Parameters,
    url::WebVHURL,
    witness::{Witness, Witnesses},
};
use ahash::HashMap;
use console::style;
use dialoguer::{Confirm, Input, MultiSelect, Select, theme::ColorfulTheme};
use serde_json::Value;
use std::sync::Arc;
use url::Url;

// ─────────────────────── Public types ───────────────────────

/// The type of update operation to perform.
///
/// # Example
///
/// ```ignore
/// use didwebvh_rs::cli_update::UpdateOperation;
///
/// let op = UpdateOperation::Modify;
/// assert_eq!(op, UpdateOperation::Modify);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateOperation {
    /// Modify the DID document and/or parameters (auth keys, witnesses, watchers, TTL).
    Modify,
    /// Migrate the DID to a new domain URL. Requires `portable = true`.
    Migrate,
    /// Permanently deactivate (revoke) the DID.
    Revoke,
}

/// Secrets needed for DID update operations.
///
/// Stores authorization key secrets with both hash-based and public-key-based lookups,
/// and witness signing secrets keyed by witness DID.
///
/// # Example
///
/// ```ignore
/// use didwebvh_rs::cli_update::UpdateSecrets;
/// use didwebvh_rs::affinidi_secrets_resolver::secrets::Secret;
///
/// let mut secrets = UpdateSecrets::default();
///
/// // Add an authorization key
/// let key = Secret::generate_ed25519(None, None);
/// secrets.add_key(&key)?;
///
/// // Look up by public key
/// let pk = key.get_public_keymultibase()?;
/// let found = secrets.find_by_public_key(&pk);
/// assert!(found.is_some());
///
/// // Add a witness secret
/// secrets.witnesses.insert("did:key:z6Mk...".to_string(), witness_key);
/// ```
#[derive(Clone, Debug, Default)]
pub struct UpdateSecrets {
    /// Authorization keys: public_key_multibase_hash → Secret
    pub keys_hash: HashMap<String, Secret>,
    /// Map: public_key_multibase → public_key_multibase_hash
    pub key_map: HashMap<String, String>,
    /// Witness signing secrets: witness_did → Secret
    pub witnesses: HashMap<String, Secret>,
}

impl UpdateSecrets {
    /// Add an authorization key secret.
    pub fn add_key(&mut self, secret: &Secret) -> Result<(), DIDWebVHError> {
        let hash = secret.get_public_keymultibase_hash().map_err(map_key_err)?;
        let public = secret.get_public_keymultibase().map_err(map_key_err)?;
        self.keys_hash.insert(hash.clone(), secret.clone());
        self.key_map.insert(public, hash);
        Ok(())
    }

    /// Find a secret by its public key multibase hash.
    pub fn find_by_hash(&self, hash: &str) -> Option<&Secret> {
        self.keys_hash.get(hash)
    }

    /// Find a secret by its public key multibase.
    pub fn find_by_public_key(&self, key: &str) -> Option<&Secret> {
        self.key_map
            .get(key)
            .and_then(|hash| self.keys_hash.get(hash))
    }
}

/// Configuration for the interactive DID update flow.
///
/// All fields default to `None`, meaning the user will be prompted interactively.
/// Pre-set fields skip their corresponding prompts.
///
/// # Examples
///
/// Fully interactive (loads from files, prompts for everything):
///
/// ```ignore
/// let config = InteractiveUpdateConfig::default();
/// let result = interactive_update_did(config).await?;
/// ```
///
/// Pre-loaded state with specific operation:
///
/// ```ignore
/// let config = InteractiveUpdateConfig::builder()
///     .state(webvh_state)
///     .secrets(update_secrets)
///     .operation(UpdateOperation::Modify)
///     .build();
/// let result = interactive_update_did(config).await?;
/// ```
///
/// Pre-configured migration:
///
/// ```ignore
/// let config = InteractiveUpdateConfig::builder()
///     .state(webvh_state)
///     .secrets(update_secrets)
///     .operation(UpdateOperation::Migrate)
///     .new_url("https://new-domain.example.com/")
///     .build();
/// let result = interactive_update_did(config).await?;
/// ```
#[derive(Default)]
pub struct InteractiveUpdateConfig {
    /// Pre-loaded DID WebVH state. If `None`, prompts for a `.jsonl` file path.
    pub(crate) state: Option<DIDWebVHState>,
    /// Authorization and witness secrets. If `None`, prompts for a secrets file path.
    pub(crate) secrets: Option<UpdateSecrets>,
    /// The update operation to perform. If `None`, shows a menu.
    pub(crate) operation: Option<UpdateOperation>,
    /// For Modify: pre-set new DID document. `None` = prompt to edit.
    pub(crate) new_document: Option<Option<Value>>,
    /// For Migrate: pre-set the new URL. `None` = prompt.
    pub(crate) new_url: Option<String>,
}

impl InteractiveUpdateConfig {
    /// Create a builder for constructing an `InteractiveUpdateConfig`.
    pub fn builder() -> InteractiveUpdateConfigBuilder {
        InteractiveUpdateConfigBuilder::default()
    }
}

// ─────────────────────── Builder ───────────────────────

/// Builder for [`InteractiveUpdateConfig`].
#[derive(Default)]
pub struct InteractiveUpdateConfigBuilder {
    state: Option<DIDWebVHState>,
    secrets: Option<UpdateSecrets>,
    operation: Option<UpdateOperation>,
    new_document: Option<Option<Value>>,
    new_url: Option<String>,
}

impl InteractiveUpdateConfigBuilder {
    /// Set the pre-loaded DID WebVH state. Skips file-loading prompt.
    pub fn state(mut self, state: DIDWebVHState) -> Self {
        self.state = Some(state);
        self
    }

    /// Set the secrets for authorization and witness operations. Skips secrets-file prompt.
    pub fn secrets(mut self, secrets: UpdateSecrets) -> Self {
        self.secrets = Some(secrets);
        self
    }

    /// Set the update operation. Skips the operation menu.
    pub fn operation(mut self, op: UpdateOperation) -> Self {
        self.operation = Some(op);
        self
    }

    /// For Modify: set the new DID document. `None` = keep current doc unchanged.
    pub fn new_document(mut self, doc: Option<Value>) -> Self {
        self.new_document = Some(doc);
        self
    }

    /// For Migrate: set the new URL to migrate to.
    pub fn new_url(mut self, url: impl Into<String>) -> Self {
        self.new_url = Some(url.into());
        self
    }

    /// Build the configuration.
    pub fn build(self) -> InteractiveUpdateConfig {
        InteractiveUpdateConfig {
            state: self.state,
            secrets: self.secrets,
            operation: self.operation,
            new_document: self.new_document,
            new_url: self.new_url,
        }
    }
}

// ─────────────────────── Result ───────────────────────

/// Result of the interactive DID update flow.
#[derive(Debug)]
pub struct InteractiveUpdateResult {
    did: String,
    log_entry: LogEntry,
    state: DIDWebVHState,
    secrets: UpdateSecrets,
}

impl InteractiveUpdateResult {
    /// The DID identifier.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The newly created log entry.
    pub fn log_entry(&self) -> &LogEntry {
        &self.log_entry
    }

    /// The full DID WebVH state (including all log entries and witness proofs).
    pub fn state(&self) -> &DIDWebVHState {
        &self.state
    }

    /// All secrets (potentially updated with newly generated keys).
    pub fn secrets(&self) -> &UpdateSecrets {
        &self.secrets
    }

    /// Consume the result and take ownership of both the state and secrets.
    pub fn into_parts(self) -> (DIDWebVHState, UpdateSecrets) {
        (self.state, self.secrets)
    }
}

// ─────────────────────── Main function ───────────────────────

/// Run the interactive DID update flow.
///
/// Loads existing DID state, validates it, presents the update menu,
/// and creates new log entries based on the chosen operation.
///
/// The flow follows these steps:
/// 1. Load DID state from files or use pre-loaded state
/// 2. Validate the loaded state (all log entries and witness proofs)
/// 3. Select the operation (Modify, Migrate, or Revoke)
/// 4. Execute the operation, creating new log entries
/// 5. Sign witness proofs for the new entry
/// 6. Return the result with updated state and secrets
///
/// # Operations
///
/// - **Modify**: Edit the DID document and/or update parameters (authorization keys,
///   witnesses, watchers, TTL, portability)
/// - **Migrate**: Move the DID to a new domain (requires `portable = true`). Rewrites
///   all DID references and adds the previous DID to `alsoKnownAs`.
/// - **Revoke**: Permanently deactivate the DID. If pre-rotation is active, creates
///   an intermediate entry to disable it first, then the final revocation entry.
///
/// # Returns
///
/// An [`InteractiveUpdateResult`] containing:
/// - The DID identifier
/// - The newly created log entry
/// - The full [`DIDWebVHState`] (all entries + witness proofs)
/// - Updated [`UpdateSecrets`] (with any newly generated keys)
///
/// # Errors
///
/// Returns [`DIDWebVHError`] if state loading, validation, log entry creation,
/// or witness signing fails. Also returns an error if the user rejects changes
/// or if migration prerequisites aren't met.
///
/// # Example
///
/// ```ignore
/// use didwebvh_rs::prelude::*;
///
/// // Fully interactive - loads from files
/// let result = interactive_update_did(InteractiveUpdateConfig::default()).await?;
///
/// // Save updated state
/// result.log_entry().save_to_file("did.jsonl")?;
/// result.state().witness_proofs().save_to_file("did-witness.json")?;
/// ```
pub async fn interactive_update_did(
    config: InteractiveUpdateConfig,
) -> Result<InteractiveUpdateResult, DIDWebVHError> {
    // ── Step 1: Load state ──
    let (mut webvh_state, mut secrets) = match (config.state, config.secrets) {
        (Some(state), Some(secrets)) => (state, secrets),
        (Some(state), None) => {
            let secrets = prompt_load_secrets()?;
            (state, secrets)
        }
        (None, Some(secrets)) => {
            let state = prompt_load_state()?;
            (state, secrets)
        }
        (None, None) => prompt_load_state_and_secrets()?,
    };

    // ── Step 2: Validate state ──
    webvh_state
        .validate()
        .and_then(ValidationReport::assert_complete)
        .map_err(|e| {
            DIDWebVHError::ValidationError(format!("Failed to validate DID WebVH state: {e}"))
        })?;

    println!(
        "{}",
        style("Successfully loaded and validated DID WebVH state")
            .color256(34)
            .blink()
    );

    let last_entry = webvh_state.log_entries().last().ok_or_else(|| {
        DIDWebVHError::LogEntryError("No log entries found in the state".to_string())
    })?;

    let metadata = webvh_state.generate_meta_data(last_entry);
    println!(
        "\n{}\n{}\n",
        style("Log Entry Parameters:").color256(69),
        style(serde_json::to_string_pretty(&last_entry.validated_parameters).unwrap()).color256(34),
    );
    println!(
        "{}\n{}\n",
        style("Log Entry Metadata:").color256(69),
        style(serde_json::to_string_pretty(&metadata).unwrap()).color256(34),
    );

    // ── Step 3: Select operation ──
    let operation = match config.operation {
        Some(op) => op,
        None => prompt_operation()?,
    };

    // ── Step 4: Execute operation ──
    match operation {
        UpdateOperation::Modify => {
            do_modify(&mut webvh_state, &mut secrets, config.new_document).await?;
        }
        UpdateOperation::Migrate => {
            do_migrate(&mut webvh_state, &mut secrets, config.new_url).await?;
        }
        UpdateOperation::Revoke => {
            do_revoke(&mut webvh_state, &secrets).await?;
        }
    }

    // ── Step 5: Witness the new entry ──
    let (log_entries, witness_proofs) = webvh_state.log_entries_and_witness_proofs_mut();
    let new_entry = log_entries
        .last()
        .ok_or_else(|| DIDWebVHError::LogEntryError("No log entry after update".to_string()))?;

    sign_witness_proofs(
        witness_proofs,
        new_entry,
        &new_entry.get_active_witnesses(),
        &secrets.witnesses,
    )
    .await?;

    // ── Step 6: Build result ──
    let new_entry = webvh_state
        .log_entries()
        .last()
        .ok_or_else(|| DIDWebVHError::LogEntryError("No log entry after update".to_string()))?;

    let did = new_entry
        .get_state()
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let log_entry = new_entry.log_entry.clone();

    println!(
        "\n{}\n{}",
        style("New Log Entry:").color256(69),
        style(serde_json::to_string_pretty(&log_entry).unwrap()).color256(34)
    );
    println!("{}", style("Update completed successfully").color256(34));

    Ok(InteractiveUpdateResult {
        did,
        log_entry,
        state: webvh_state,
        secrets,
    })
}

// ─────────────────────── Operation: Modify ───────────────────────

async fn do_modify(
    webvh_state: &mut DIDWebVHState,
    secrets: &mut UpdateSecrets,
    pre_document: Option<Option<Value>>,
) -> Result<(), DIDWebVHError> {
    println!(
        "{}",
        style("Modifying DID Document and/or Parameters").color256(69)
    );

    let previous = webvh_state
        .log_entries()
        .last()
        .ok_or_else(|| DIDWebVHError::LogEntryError("No log entries found".to_string()))?;

    // Edit DID Document?
    let new_state = match pre_document {
        Some(Some(doc)) => doc,
        Some(None) => previous.get_state().clone(),
        None => {
            if prompt_confirm("Edit the DID Document?", false)? {
                prompt_edit_document(previous.get_state())?
            } else {
                previous.get_state().clone()
            }
        }
    };

    // Update parameters
    let new_params = prompt_update_parameters(previous, secrets)?;

    // Find signing key
    let signing_key = secrets
        .find_by_public_key(new_params.active_update_keys[0].as_str())
        .ok_or_else(|| {
            DIDWebVHError::DIDError(format!(
                "No signing key found for active update key: {}",
                new_params.active_update_keys[0]
            ))
        })?
        .clone();

    let log_entry = webvh_state
        .create_log_entry(None, &new_state, &new_params, &signing_key)
        .await?;

    println!(
        "\n{}\n{}",
        style("New Log Entry:").color256(69),
        style(serde_json::to_string_pretty(&log_entry.log_entry).unwrap()).color256(34)
    );

    if !prompt_confirm("Accept this updated LogEntry?", true)? {
        webvh_state.remove_last_log_entry();
        return Err(DIDWebVHError::DIDError("Changes rejected".to_string()));
    }

    Ok(())
}

// ─────────────────────── Operation: Migrate ───────────────────────

async fn do_migrate(
    webvh_state: &mut DIDWebVHState,
    secrets: &mut UpdateSecrets,
    pre_url: Option<String>,
) -> Result<(), DIDWebVHError> {
    let last_entry = webvh_state
        .log_entries()
        .last()
        .ok_or_else(|| DIDWebVHError::LogEntryError("No log entries found".to_string()))?;

    if last_entry.validated_parameters.portable != Some(true) {
        return Err(DIDWebVHError::ParametersError(
            "Portable parameter must be true to migrate a webvh DID".to_string(),
        ));
    }

    let did = last_entry
        .get_state()
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DIDWebVHError::DIDError("DID not found in log entry state".to_string()))?
        .to_string();

    let did_url = WebVHURL::parse_did_url(&did)?;

    println!(
        "\n{}",
        style("WARNING: You are about to migrate this DID to a new domain.").color256(9)
    );
    println!(
        "\t{}",
        style(
            "The DID's SCID will remain the same, and the previous URL will be \
             added to alsoKnownAs. All references in the DID document will be \
             rewritten to the new domain."
        )
        .color256(69)
    );
    println!(
        "\n{} {}",
        style("Current URL:").color256(69),
        style(did_url.get_http_url(None)?).color256(45)
    );

    // Get new URL
    let new_url_str = match pre_url {
        Some(url) => url,
        None => {
            let input: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("New URL (e.g. https://new-domain.example.com/)")
                .with_initial_text(did_url.get_http_url(None)?)
                .interact_text()
                .map_err(map_io)?;
            input
        }
    };

    let new_url = Url::parse(&new_url_str)
        .map_err(|e| DIDWebVHError::DIDError(format!("Invalid URL format: {e}")))?;

    let mut new_did_url = WebVHURL::parse_url(&new_url)?;
    new_did_url.scid = did_url.scid.clone();

    println!(
        "\n{} {}\n",
        style("New DID:").color256(69),
        style(&new_did_url.to_string()).color256(141)
    );

    if !prompt_confirm("Migrate to this new URL?", true)? {
        return Err(DIDWebVHError::DIDError("Migration aborted".to_string()));
    }

    // Modify the DID Document - replace old DID with new DID
    let did_doc: String = serde_json::to_string(last_entry.get_state())
        .map_err(|e| DIDWebVHError::DIDError(format!("Failed to serialize DID doc: {e}")))?;
    let new_did_doc = did_doc.replace(&did_url.to_string(), &new_did_url.to_string());
    let mut new_did_doc: Value = serde_json::from_str(&new_did_doc)
        .map_err(|e| DIDWebVHError::DIDError(format!("Failed to parse new DID doc: {e}")))?;

    // Add previous DID to alsoKnownAs
    if let Some(alias) = new_did_doc.get_mut("alsoKnownAs") {
        if let Some(arr) = alias.as_array_mut() {
            arr.push(Value::String(did.clone()));
        }
    } else if let Some(obj) = new_did_doc.as_object_mut() {
        obj.insert(
            "alsoKnownAs".to_string(),
            Value::Array(vec![Value::String(did)]),
        );
    }

    println!(
        "{}",
        style(serde_json::to_string_pretty(&new_did_doc).unwrap()).color256(141)
    );

    if !prompt_confirm("Confirm changes to this DID?", true)? {
        return Err(DIDWebVHError::DIDError("Migration aborted".to_string()));
    }

    // Create new LogEntry
    let mut new_params = Parameters::default();
    prompt_update_authorization_keys(&last_entry.validated_parameters, &mut new_params, secrets)?;

    let signing_key = secrets
        .find_by_public_key(new_params.active_update_keys[0].as_str())
        .ok_or_else(|| {
            DIDWebVHError::DIDError(format!(
                "No signing key found for active update key: {}",
                new_params.active_update_keys[0]
            ))
        })?
        .clone();

    webvh_state
        .create_log_entry(None, &new_did_doc, &new_params, &signing_key)
        .await?;

    Ok(())
}

// ─────────────────────── Operation: Revoke ───────────────────────

async fn do_revoke(
    webvh_state: &mut DIDWebVHState,
    secrets: &UpdateSecrets,
) -> Result<(), DIDWebVHError> {
    let last_entry = webvh_state
        .log_entries()
        .last()
        .ok_or_else(|| DIDWebVHError::LogEntryError("No log entries found".to_string()))?;

    let did = last_entry
        .get_state()
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    println!(
        "\n{}\n",
        style("WARNING: You are about to permanently deactivate this DID.").color256(9)
    );
    println!(
        "\t{}",
        style(
            "Deactivation is irreversible. The DID will no longer be valid for \
             authentication, credential issuance, or any other purpose. Existing \
             credentials issued by this DID will fail verification."
        )
        .color256(69)
    );

    if !prompt_confirm(&format!("Permanently deactivate DID ({did})?"), false)? {
        return Err(DIDWebVHError::DIDError(
            "Deactivation cancelled".to_string(),
        ));
    }

    // If pre-rotation is active, must disable it first
    if last_entry.validated_parameters.pre_rotation_active {
        println!(
            "{}",
            style(
                "Pre-rotation is active — creating an intermediate log entry to \
                 disable it before deactivation..."
            )
            .color256(214)
        );
        deactivate_pre_rotation(webvh_state, secrets).await?;

        // Witness the intermediate entry
        {
            let (log_entries, witness_proofs) = webvh_state.log_entries_and_witness_proofs_mut();
            let entry = log_entries.last().ok_or_else(|| {
                DIDWebVHError::LogEntryError("No log entry after pre-rotation disable".to_string())
            })?;
            sign_witness_proofs(
                witness_proofs,
                entry,
                &entry.get_active_witnesses(),
                &secrets.witnesses,
            )
            .await?;
        }

        println!(
            "{}",
            style("Pre-rotation disabled successfully.").color256(34)
        );
    }

    // Create final deactivation entry
    revoke_entry(webvh_state, secrets).await?;

    println!(
        "\n{} {} {}",
        style("DID").color256(9),
        style(&did).color256(141),
        style("has been permanently deactivated.").color256(9)
    );

    Ok(())
}

/// Creates a LogEntry that disables pre-rotation.
async fn deactivate_pre_rotation(
    webvh_state: &mut DIDWebVHState,
    secrets: &UpdateSecrets,
) -> Result<(), DIDWebVHError> {
    let last_entry = webvh_state
        .log_entries()
        .last()
        .ok_or_else(|| DIDWebVHError::LogEntryError("No log entries found".to_string()))?;

    let next_key_hashes = last_entry
        .validated_parameters
        .next_key_hashes
        .as_ref()
        .ok_or_else(|| {
            DIDWebVHError::ParametersError("Expecting nextKeyHashes, but doesn't exist".to_string())
        })?;

    let hash = next_key_hashes.first().ok_or_else(|| {
        DIDWebVHError::ParametersError("No next key hashes available".to_string())
    })?;

    let new_update_key = secrets.find_by_hash(hash.as_str()).ok_or_else(|| {
        DIDWebVHError::ParametersError(format!("No secret found for next key hash: {hash}"))
    })?;

    let new_params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(
            new_update_key
                .get_public_keymultibase()
                .map_err(map_key_err)?,
        )])),
        next_key_hashes: Some(Arc::new(Vec::new())),
        ..Default::default()
    };

    let state = last_entry.get_state().clone();
    webvh_state
        .create_log_entry(None, &state, &new_params, new_update_key)
        .await?;

    Ok(())
}

/// Creates the final revocation LogEntry.
async fn revoke_entry(
    webvh_state: &mut DIDWebVHState,
    secrets: &UpdateSecrets,
) -> Result<(), DIDWebVHError> {
    let last_entry = webvh_state
        .log_entries()
        .last()
        .ok_or_else(|| DIDWebVHError::LogEntryError("No log entries found".to_string()))?;

    let key = last_entry
        .validated_parameters
        .active_update_keys
        .first()
        .ok_or_else(|| {
            DIDWebVHError::ParametersError("No active update key available".to_string())
        })?;

    let signing_key = secrets.find_by_public_key(key.as_str()).ok_or_else(|| {
        DIDWebVHError::ParametersError(format!("No secret found for update key: {key}"))
    })?;

    let new_params = Parameters {
        deactivated: Some(true),
        update_keys: Some(Arc::new(Vec::new())),
        ..Default::default()
    };

    let state = last_entry.get_state().clone();
    webvh_state
        .create_log_entry(None, &state, &new_params, signing_key)
        .await?;

    Ok(())
}

// ─────────────────────── Parameter update prompts ───────────────────────

fn prompt_update_parameters(
    old_entry: &LogEntryState,
    secrets: &mut UpdateSecrets,
) -> Result<Parameters, DIDWebVHError> {
    let mut new_params = Parameters::default();

    // Authorization Keys
    prompt_update_authorization_keys(&old_entry.validated_parameters, &mut new_params, secrets)?;

    println!(
        "{}{}{}",
        style("Pre-rotation (").color256(69),
        if new_params.pre_rotation_active {
            style("enabled").color256(34)
        } else {
            style("disabled").color256(214)
        },
        style(")").color256(69)
    );

    // Portability
    if let Some(true) = old_entry.validated_parameters.portable {
        if prompt_confirm("Disable portability for this DID?", false)? {
            new_params.portable = Some(false);
        } else {
            new_params.portable = Some(true);
        }
    }

    // Witnesses
    prompt_modify_witness_params(
        old_entry.validated_parameters.witness.clone(),
        &mut new_params,
        secrets,
    )?;

    // Watchers
    prompt_modify_watcher_params(
        old_entry.validated_parameters.watchers.clone(),
        &mut new_params,
    )?;

    // TTL
    prompt_modify_ttl(&old_entry.validated_parameters.ttl, &mut new_params)?;

    Ok(new_params)
}

fn prompt_update_authorization_keys(
    old_params: &Parameters,
    new_params: &mut Parameters,
    secrets: &mut UpdateSecrets,
) -> Result<(), DIDWebVHError> {
    let theme = ColorfulTheme::default();

    if old_params.pre_rotation_active {
        // Pre-rotation mode
        println!(
            "{}",
            style("Pre-rotation is currently enabled for this DID.").color256(69)
        );
        println!(
            "\t{}",
            style(
                "You must select one of your pre-committed keys to authorize this update. \
                 You can also choose to disable pre-rotation going forward."
            )
            .color256(69)
        );
        if prompt_confirm("Disable pre-rotation after this update?", false)? {
            new_params.pre_rotation_active = false;
            new_params.next_key_hashes = Some(Arc::new(Vec::new()));
            let update_keys =
                select_update_keys_from_next_hashes(&old_params.next_key_hashes, secrets)?;
            let new_keys: Vec<Multibase> = update_keys
                .iter()
                .map(|k| {
                    k.get_public_keymultibase()
                        .map(Multibase::new)
                        .map_err(map_key_err)
                })
                .collect::<Result<_, _>>()?;
            let new_keys = Arc::new(new_keys);
            new_params.update_keys = Some(new_keys.clone());
            new_params.active_update_keys = new_keys;
        } else {
            new_params.pre_rotation_active = true;
            let update_keys =
                select_update_keys_from_next_hashes(&old_params.next_key_hashes, secrets)?;
            let new_keys: Vec<Multibase> = update_keys
                .iter()
                .map(|k| {
                    k.get_public_keymultibase()
                        .map(Multibase::new)
                        .map_err(map_key_err)
                })
                .collect::<Result<_, _>>()?;
            let new_keys = Arc::new(new_keys);
            new_params.update_keys = Some(new_keys.clone());
            new_params.active_update_keys = new_keys;

            // New next key hashes
            let next_hashes = prompt_create_next_key_hashes_for_update(secrets)?;
            if next_hashes.is_empty() {
                return Err(DIDWebVHError::ParametersError(
                    "No next key hashes created for pre-rotation mode".to_string(),
                ));
            }
            new_params.next_key_hashes = Some(Arc::new(next_hashes));
        }
    } else {
        // Non pre-rotation mode
        new_params.active_update_keys = old_params.active_update_keys.clone();
        new_params.pre_rotation_active = false;

        if prompt_confirm(
            "Enable pre-rotation? (Commit to future key hashes for added security)",
            false,
        )? {
            let next_hashes = prompt_create_next_key_hashes_for_update(secrets)?;
            if next_hashes.is_empty() {
                return Err(DIDWebVHError::ParametersError(
                    "No next key hashes created for pre-rotation mode".to_string(),
                ));
            }
            new_params.next_key_hashes = Some(Arc::new(next_hashes));
        } else {
            // Optionally modify update keys
            if prompt_confirm("Change authorization keys for future updates?", false)? {
                if old_params.active_update_keys.is_empty() {
                    return Err(DIDWebVHError::ParametersError(
                        "No active update keys found in previous LogEntry".to_string(),
                    ));
                }

                let mut new_update_keys = Vec::new();

                let selected = MultiSelect::with_theme(&theme)
                    .with_prompt("Which existing authorization keys do you want to keep?")
                    .items(
                        old_params
                            .active_update_keys
                            .iter()
                            .collect::<Vec<_>>()
                            .as_slice(),
                    )
                    .interact()
                    .map_err(map_io)?;

                for i in selected {
                    new_update_keys.push(new_params.active_update_keys[i].clone());
                }

                if prompt_confirm(
                    "Would you like to create new update keys to add to the authorized keys?",
                    false,
                )? {
                    let keys = prompt_keys()?;
                    for k in keys {
                        new_update_keys.push(Multibase::new(
                            k.get_public_keymultibase().map_err(map_key_err)?,
                        ));
                        secrets.add_key(&k)?;
                    }
                }

                new_params.update_keys = Some(Arc::new(new_update_keys));
            } else {
                new_params.update_keys = None;
            }
        }
    }

    Ok(())
}

fn select_update_keys_from_next_hashes(
    next_key_hashes: &Option<Arc<Vec<Multibase>>>,
    secrets: &UpdateSecrets,
) -> Result<Vec<Secret>, DIDWebVHError> {
    let hashes = next_key_hashes.as_ref().ok_or_else(|| {
        DIDWebVHError::ParametersError("No next key hashes found for pre-rotation mode".to_string())
    })?;

    let selected = loop {
        let selected = MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Which pre-rotated keys do you want to use for this LogEntry update?")
            .items(hashes.iter().collect::<Vec<_>>().as_slice())
            .defaults(&[true])
            .interact()
            .map_err(map_io)?;
        if !selected.is_empty() {
            break selected;
        }
        println!(
            "{}",
            style("You MUST select at least one key from the pre-rolled keys!").color256(9)
        );
    };

    let mut selected_secrets = Vec::new();
    for i in selected {
        let secret = secrets.find_by_hash(hashes[i].as_str()).ok_or_else(|| {
            DIDWebVHError::ParametersError(format!(
                "Couldn't find a matching Secret key for hash: {}",
                hashes[i]
            ))
        })?;
        selected_secrets.push(secret.clone());
    }

    Ok(selected_secrets)
}

/// Wrapper around `prompt_next_key_hashes` that also stores generated keys in UpdateSecrets.
fn prompt_create_next_key_hashes_for_update(
    secrets: &mut UpdateSecrets,
) -> Result<Vec<Multibase>, DIDWebVHError> {
    let (hashes, keys) = prompt_next_key_hashes()?;
    for key in &keys {
        secrets.add_key(key)?;
    }
    Ok(hashes)
}

fn prompt_modify_witness_params(
    old_witness: Option<Arc<Witnesses>>,
    new_params: &mut Parameters,
    secrets: &mut UpdateSecrets,
) -> Result<(), DIDWebVHError> {
    let theme = ColorfulTheme::default();

    // Show current witness config
    if let Some(witnesses) = &old_witness {
        match &**witnesses {
            Witnesses::Value {
                threshold,
                witnesses,
            } => {
                println!(
                    "{}{}",
                    style("Witness threshold: ").color256(69),
                    style(threshold).color256(34)
                );
                for w in witnesses {
                    println!("\t{}", style(w.id.to_string()).color256(34));
                }
            }
            Witnesses::Empty {} => {
                println!(
                    "{}{}{}",
                    style("Witnesses are ").color256(69),
                    style("NOT").color256(214),
                    style(" being used by this DID!").color256(69)
                );
            }
        }
    } else {
        println!(
            "{}{}{}",
            style("Witnesses are ").color256(69),
            style("NOT").color256(214),
            style(" being used by this DID!").color256(69)
        );
    }

    if !prompt_confirm("Change Witness Parameters?", false)? {
        new_params.witness = None;
        return Ok(());
    }

    if let Some(witnesses) = &old_witness
        && matches!(&**witnesses, Witnesses::Value { .. })
    {
        if prompt_confirm("Disable Witnessing for this DID?", false)? {
            new_params.witness = Some(Arc::new(Witnesses::Empty {}));
            return Ok(());
        }

        let (threshold, witness_nodes) = match &**witnesses {
            Witnesses::Value {
                threshold,
                witnesses,
            } => (*threshold, witnesses),
            _ => {
                return Err(DIDWebVHError::ParametersError(
                    "Invalid witness state".to_string(),
                ));
            }
        };

        let new_threshold: u32 = Input::with_theme(&theme)
            .with_prompt("Witness Threshold Count?")
            .default(threshold)
            .interact()
            .map_err(map_io)?;

        let new_witnesses = prompt_modify_witness_nodes(witness_nodes, new_threshold, secrets)?;

        new_params.witness = Some(Arc::new(Witnesses::Value {
            threshold: new_threshold,
            witnesses: new_witnesses,
        }));
        return Ok(());
    }

    // No existing witnesses, create new ones
    let (witnesses, new_secrets) = prompt_witnesses()?;
    for (did, secret) in new_secrets {
        secrets.witnesses.insert(did, secret);
    }
    if matches!(&witnesses, Witnesses::Value { .. }) {
        new_params.witness = Some(Arc::new(witnesses));
    }

    Ok(())
}

fn prompt_modify_witness_nodes(
    witnesses: &[Witness],
    threshold: u32,
    secrets: &mut UpdateSecrets,
) -> Result<Vec<Witness>, DIDWebVHError> {
    let theme = ColorfulTheme::default();
    let mut new_witnesses = Vec::new();

    let items: Vec<String> = witnesses.iter().map(|w| w.id.to_string()).collect();
    let selected = MultiSelect::with_theme(&theme)
        .with_prompt("Which Witness Nodes do you want to keep?")
        .items(&items)
        .interact()
        .map_err(map_io)?;

    for i in selected {
        new_witnesses.push(witnesses[i].clone());
    }

    loop {
        println!(
            "{}{}{}{}",
            style("Current Witness Count/Threshold: ").color256(69),
            style(new_witnesses.len()).color256(34),
            style("/").color256(69),
            style(threshold).color256(34)
        );

        if prompt_confirm("Auto-generate witness key pairs?", true)? {
            let count = if new_witnesses.len() as u32 > threshold {
                break;
            } else {
                (threshold + 1) - new_witnesses.len() as u32
            };

            for i in 0..count {
                let (did, key) = generate_did_key(KeyType::Ed25519)
                    .map_err(|e| DIDWebVHError::DIDError(format!("Key generation failed: {e}")))?;
                println!(
                    "{} {}",
                    style(format!("Witness #{i:02}:")).color256(69),
                    style(&did).color256(141)
                );
                println!(
                    "\t{} {} {} {}",
                    style("publicKeyMultibase:").color256(69),
                    style(key.get_public_keymultibase().map_err(map_key_err)?).color256(34),
                    style("privateKeyMultibase:").color256(69),
                    style(key.get_private_keymultibase().map_err(map_key_err)?).color256(214)
                );
                new_witnesses.push(Witness {
                    id: Multibase::new(did.clone()),
                });
                secrets.witnesses.insert(did, key);
            }
            break;
        } else {
            let did: String = Input::with_theme(&theme)
                .with_prompt(format!("Witness #{:02} DID?", new_witnesses.len()))
                .interact()
                .map_err(map_io)?;

            new_witnesses.push(Witness {
                id: Multibase::new(did),
            });

            if !Confirm::with_theme(&theme)
                .with_prompt(format!(
                    "Add another witness: current:({:02}) threshold:({threshold:02})?",
                    new_witnesses.len(),
                ))
                .default(true)
                .interact()
                .map_err(map_io)?
            {
                break;
            }
        }
    }

    Ok(new_witnesses)
}

fn prompt_modify_watcher_params(
    old_watchers: Option<Arc<Vec<String>>>,
    new_params: &mut Parameters,
) -> Result<(), DIDWebVHError> {
    let theme = ColorfulTheme::default();

    // Show current watchers
    if let Some(watchers) = &old_watchers {
        for w in watchers.iter() {
            println!("\t{}", style(w).color256(34));
        }
    } else {
        println!(
            "{}{}{}",
            style("Watchers are ").color256(69),
            style("NOT").color256(214),
            style(" being used by this DID!").color256(69)
        );
    }

    if !prompt_confirm("Change Watcher Parameters?", false)? {
        new_params.watchers = None;
        return Ok(());
    }

    if let Some(watchers) = old_watchers {
        if prompt_confirm("Disable all watchers for this DID?", false)? {
            new_params.watchers = Some(Arc::new(Vec::new()));
            return Ok(());
        }

        // Keep/remove existing + add new
        let items: Vec<&str> = watchers.iter().map(|w| w.as_str()).collect();
        let selected = MultiSelect::with_theme(&theme)
            .with_prompt("Which Watcher Nodes do you want to keep?")
            .items(&items)
            .interact()
            .map_err(map_io)?;

        let mut new_watchers: Vec<String> = selected.iter().map(|&i| watchers[i].clone()).collect();

        loop {
            println!(
                "{}{}",
                style("Current Watchers Count: ").color256(69),
                style(new_watchers.len()).color256(34),
            );
            for w in &new_watchers {
                println!("\t{}", style(w).color256(34));
            }

            if prompt_confirm("Add new Watchers?", false)? {
                let url: String = Input::with_theme(&theme)
                    .with_prompt("Watcher URL")
                    .interact()
                    .map_err(map_io)?;
                new_watchers.push(url);

                if !prompt_confirm("Add another Watcher?", true)? {
                    break;
                }
            } else {
                break;
            }
        }

        new_params.watchers = Some(Arc::new(new_watchers));
    } else {
        // No existing watchers, create new ones
        let mut watchers = Vec::new();
        loop {
            let url: String = Input::with_theme(&theme)
                .with_prompt("Watcher URL?")
                .interact()
                .map_err(map_io)?;
            watchers.push(url);

            if !prompt_confirm("Add another watcher?", true)? {
                break;
            }
        }
        new_params.watchers = Some(Arc::new(watchers));
    }

    Ok(())
}

fn prompt_modify_ttl(ttl: &Option<u32>, params: &mut Parameters) -> Result<(), DIDWebVHError> {
    print!("{}", style("Current TTL: ").color256(69));
    let current_ttl = if let Some(ttl) = ttl {
        println!(
            "{} {}",
            style(ttl).color256(34),
            style("seconds").color256(69)
        );
        *ttl
    } else {
        println!(
            "{}",
            style("not set (resolver decides caching)").color256(214)
        );
        3600_u32
    };

    if prompt_confirm("Change the TTL?", false)? {
        let new_ttl: u32 = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("New TTL in seconds (e.g. 3600 = 1 hour)")
            .default(current_ttl)
            .interact()
            .map_err(map_io)?;

        params.ttl = Some(new_ttl);
    } else {
        params.ttl = *ttl;
    }

    Ok(())
}

// ─────────────────────── Loading prompts ───────────────────────

fn prompt_load_state_and_secrets() -> Result<(DIDWebVHState, UpdateSecrets), DIDWebVHError> {
    let theme = ColorfulTheme::default();

    let file_path: String = Input::with_theme(&theme)
        .with_prompt("DID LogEntry File?")
        .default("did.jsonl".to_string())
        .validate_with(|input: &String| {
            if input.is_empty() {
                Err("File name cannot be empty".to_string())
            } else if !input.ends_with(".jsonl") {
                Err("File name must end with .jsonl".to_string())
            } else {
                Ok(())
            }
        })
        .interact()
        .map_err(map_io)?;

    let mut state = DIDWebVHState::default();
    let Some((prefix, _)) = file_path.split_once(".") else {
        return Err(DIDWebVHError::DIDError(
            "Invalid file path! Must end with .jsonl".to_string(),
        ));
    };

    state.load_log_entries_from_file(&file_path)?;
    state.load_witness_proofs_from_file(&[prefix, "-witness.json"].concat());

    // Load secrets
    let secrets_path = [prefix, "-secrets.json"].concat();
    let secrets = load_secrets_from_file(&secrets_path)?;

    Ok((state, secrets))
}

fn prompt_load_state() -> Result<DIDWebVHState, DIDWebVHError> {
    let theme = ColorfulTheme::default();

    let file_path: String = Input::with_theme(&theme)
        .with_prompt("DID LogEntry File?")
        .default("did.jsonl".to_string())
        .validate_with(|input: &String| {
            if input.is_empty() {
                Err("File name cannot be empty".to_string())
            } else if !input.ends_with(".jsonl") {
                Err("File name must end with .jsonl".to_string())
            } else {
                Ok(())
            }
        })
        .interact()
        .map_err(map_io)?;

    let mut state = DIDWebVHState::default();
    let prefix = file_path
        .split_once(".")
        .map(|(p, _)| p)
        .unwrap_or(&file_path);

    state.load_log_entries_from_file(&file_path)?;
    state.load_witness_proofs_from_file(&[prefix, "-witness.json"].concat());

    Ok(state)
}

fn prompt_load_secrets() -> Result<UpdateSecrets, DIDWebVHError> {
    let theme = ColorfulTheme::default();

    let secrets_path: String = Input::with_theme(&theme)
        .with_prompt("Secrets File?")
        .default("did-secrets.json".to_string())
        .interact()
        .map_err(map_io)?;

    load_secrets_from_file(&secrets_path)
}

/// Load secrets from the wizard's ConfigInfo JSON format.
fn load_secrets_from_file(path: &str) -> Result<UpdateSecrets, DIDWebVHError> {
    let file = std::fs::File::open(path).map_err(|e| {
        DIDWebVHError::DIDError(format!("Failed to open secrets file ({path}): {e}"))
    })?;

    // The wizard saves ConfigInfo { keys_hash, key_map, witnesses, did_keys }
    let raw: serde_json::Value = serde_json::from_reader(file).map_err(|e| {
        DIDWebVHError::DIDError(format!("Failed to parse secrets file ({path}): {e}"))
    })?;

    let mut secrets = UpdateSecrets::default();

    // Parse keys_hash
    if let Some(keys) = raw.get("keys_hash").and_then(|v| v.as_object()) {
        for (hash, secret_val) in keys {
            if let Ok(secret) = serde_json::from_value::<Secret>(secret_val.clone()) {
                secrets.keys_hash.insert(hash.clone(), secret);
            }
        }
    }

    // Parse key_map
    if let Some(map) = raw.get("key_map").and_then(|v| v.as_object()) {
        for (public, hash_val) in map {
            if let Some(hash) = hash_val.as_str() {
                secrets.key_map.insert(public.clone(), hash.to_string());
            }
        }
    }

    // Parse witnesses
    if let Some(witnesses) = raw.get("witnesses").and_then(|v| v.as_object()) {
        for (did, secret_val) in witnesses {
            if let Ok(secret) = serde_json::from_value::<Secret>(secret_val.clone()) {
                secrets.witnesses.insert(did.clone(), secret);
            }
        }
    }

    Ok(secrets)
}

fn prompt_operation() -> Result<UpdateOperation, DIDWebVHError> {
    let menu = vec![
        "Modify  - Update the DID document and/or parameters",
        "Migrate - Move this DID to a new domain (requires portability)",
        "Deactivate - Permanently deactivate this DID (irreversible)",
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("What would you like to do?")
        .items(&menu)
        .default(0)
        .interact()
        .map_err(map_io)?;

    match selection {
        0 => Ok(UpdateOperation::Modify),
        1 => Ok(UpdateOperation::Migrate),
        2 => Ok(UpdateOperation::Revoke),
        _ => Err(DIDWebVHError::DIDError("Invalid selection".to_string())),
    }
}
