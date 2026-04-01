/*!
 * Interactive CLI flow for creating a new DID.
 *
 * Gated behind the `cli` feature flag. Third-party applications can use this
 * module to embed the same interactive DID creation wizard in their own CLIs.
 *
 * # Usage
 *
 * ```ignore
 * use didwebvh_rs::cli_create::{InteractiveCreateConfig, interactive_create_did};
 *
 * // Fully interactive - all values prompted
 * let result = interactive_create_did(InteractiveCreateConfig::default()).await?;
 * println!("Created DID: {}", result.did());
 *
 * // Pre-configured address and services, rest interactive
 * let config = InteractiveCreateConfig::builder()
 *     .address("https://example.com/")
 *     .service(serde_json::json!({
 *         "id": "{DID}#messaging",
 *         "type": "DIDCommMessaging",
 *         "serviceEndpoint": "https://example.com/didcomm"
 *     }))
 *     .portable(true)
 *     .build();
 * let result = interactive_create_did(config).await?;
 * ```
 *
 * # Placeholder Rewriting
 *
 * Use `{DID}` as a placeholder in pre-configured services and verification method IDs.
 * It will be replaced with the actual DID identifier (including SCID) during creation.
 */

use crate::{
    DIDWebVHError, Multibase, Secret,
    cli_common::{
        map_io, map_key_err, prompt_confirm, prompt_create_key, prompt_keys,
        prompt_next_key_hashes, prompt_watchers, prompt_witnesses,
    },
    create::{CreateDIDConfig, create_did},
    log_entry::LogEntry,
    parameters::Parameters,
    url::WebVHURL,
    witness::{Witnesses, proofs::WitnessProofCollection},
};
use ahash::HashMap;
use console::style;
use dialoguer::{Confirm, Editor, Input, MultiSelect, Select, theme::ColorfulTheme};
use serde_json::{Value, json};
use std::sync::Arc;
use url::Url;

// ─────────────────────── Public types ───────────────────────

/// Verification relationship types for a DID Document verification method.
///
/// These correspond to the standard DID Document verification relationship properties.
///
/// # Example
///
/// ```ignore
/// use didwebvh_rs::cli_create::VerificationRelationship;
///
/// let rels = vec![
///     VerificationRelationship::Authentication,
///     VerificationRelationship::AssertionMethod,
///     VerificationRelationship::KeyAgreement,
/// ];
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationRelationship {
    /// authentication
    Authentication,
    /// assertionMethod
    AssertionMethod,
    /// keyAgreement
    KeyAgreement,
    /// capabilityInvocation
    CapabilityInvocation,
    /// capabilityDelegation
    CapabilityDelegation,
}

impl VerificationRelationship {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::AssertionMethod => "assertionMethod",
            Self::KeyAgreement => "keyAgreement",
            Self::CapabilityInvocation => "capabilityInvocation",
            Self::CapabilityDelegation => "capabilityDelegation",
        }
    }
}

/// A pre-configured verification method to include in the DID Document.
///
/// If `id` is `None`, it will be auto-generated as `{DID}#key-{n}` where `n` is the index.
/// The `{DID}` placeholder in IDs is replaced with the actual DID during creation.
///
/// # Example
///
/// ```ignore
/// use didwebvh_rs::cli_create::{VerificationMethodInput, VerificationRelationship};
/// use didwebvh_rs::affinidi_secrets_resolver::secrets::Secret;
///
/// let key = Secret::generate_ed25519(None, None);
/// let vm = VerificationMethodInput {
///     id: Some("{DID}#key-0".to_string()),
///     secret: key,
///     relationships: vec![
///         VerificationRelationship::Authentication,
///         VerificationRelationship::AssertionMethod,
///     ],
/// };
/// ```
pub struct VerificationMethodInput {
    /// VM ID. Use `{DID}` placeholder for the DID portion. Auto-generated if `None`.
    pub id: Option<String>,
    /// The secret containing the key pair for this verification method.
    pub secret: Secret,
    /// The verification relationships this method serves.
    pub relationships: Vec<VerificationRelationship>,
}

/// Configuration for the interactive DID creation flow.
///
/// All fields default to `None` / empty, meaning the user will be prompted interactively.
/// Pre-set fields skip their corresponding interactive prompts.
///
/// Use [`InteractiveCreateConfig::builder()`] for a fluent construction API,
/// or [`InteractiveCreateConfig::default()`] for a fully interactive experience.
///
/// # Examples
///
/// Fully interactive (all values prompted via terminal):
///
/// ```ignore
/// let config = InteractiveCreateConfig::default();
/// let result = interactive_create_did(config).await?;
/// ```
///
/// Pre-configured with custom services and address (remaining values prompted):
///
/// ```ignore
/// let config = InteractiveCreateConfig::builder()
///     .address("https://example.com/")
///     .service(serde_json::json!({
///         "id": "{DID}#messaging",
///         "type": "DIDCommMessaging",
///         "serviceEndpoint": "https://example.com/didcomm"
///     }))
///     .portable(true)
///     .also_known_as_web(true)
///     .build();
/// ```
///
/// Fully pre-configured (no prompts triggered):
///
/// ```ignore
/// let config = InteractiveCreateConfig::builder()
///     .address("https://example.com/")
///     .authorization_key(signing_key)
///     .verification_method(vm_input)
///     .no_services()
///     .no_controller()
///     .also_known_as(vec![])
///     .portable(true)
///     .no_next_keys()
///     .no_witnesses()
///     .no_watchers()
///     .ttl(3600)
///     .also_known_as_web(true)
///     .also_known_as_scid(false)
///     .build();
/// ```
#[derive(Default)]
pub struct InteractiveCreateConfig {
    /// Pre-set address (URL or DID format). `None` = prompt.
    pub(crate) address: Option<String>,
    /// Pre-set authorization keys. Empty = prompt + generate.
    pub(crate) authorization_keys: Vec<Secret>,
    /// Pre-configured verification methods. Empty = prompt + generate.
    pub(crate) verification_methods: Vec<VerificationMethodInput>,
    /// Pre-configured services (`{DID}` placeholder supported).
    /// `None` = prompt, `Some(vec)` = use these.
    pub(crate) services: Option<Vec<Value>>,
    /// `None` = prompt, `Some(None)` = no controller, `Some(Some(did))` = use this.
    pub(crate) controller: Option<Option<String>>,
    /// `None` = prompt, `Some(vec)` = use these aliases.
    pub(crate) also_known_as: Option<Vec<String>>,
    /// `None` = prompt, `Some(bool)` = use this.
    pub(crate) portable: Option<bool>,
    /// Pre-rotation next keys. `None` = prompt, `Some(vec)` = use (empty = none).
    pub(crate) next_keys: Option<Vec<Secret>>,
    /// `None` = prompt, `Some(Witnesses::Empty)` = no witnesses, `Some(Value{..})` = use.
    pub(crate) witnesses: Option<Witnesses>,
    /// Witness signing secrets keyed by witness DID.
    pub(crate) witness_secrets: HashMap<String, Secret>,
    /// `None` = prompt, `Some(vec)` = use these.
    pub(crate) watchers: Option<Vec<String>>,
    /// `None` = prompt, `Some(None)` = no TTL, `Some(Some(n))` = use this.
    pub(crate) ttl: Option<Option<u32>>,
    /// `None` = prompt, `Some(bool)` = use this.
    pub(crate) also_known_as_web: Option<bool>,
    /// `None` = prompt, `Some(bool)` = use this.
    pub(crate) also_known_as_scid: Option<bool>,
}

impl InteractiveCreateConfig {
    /// Create a builder for constructing an `InteractiveCreateConfig`.
    pub fn builder() -> InteractiveCreateConfigBuilder {
        InteractiveCreateConfigBuilder::default()
    }
}

// ─────────────────────── Builder ───────────────────────

/// Builder for [`InteractiveCreateConfig`].
///
/// Any field not explicitly set will trigger an interactive prompt at runtime.
#[derive(Default)]
pub struct InteractiveCreateConfigBuilder {
    address: Option<String>,
    authorization_keys: Vec<Secret>,
    verification_methods: Vec<VerificationMethodInput>,
    services: Option<Vec<Value>>,
    controller: Option<Option<String>>,
    also_known_as: Option<Vec<String>>,
    portable: Option<bool>,
    next_keys: Option<Vec<Secret>>,
    witnesses: Option<Witnesses>,
    witness_secrets: HashMap<String, Secret>,
    watchers: Option<Vec<String>>,
    ttl: Option<Option<u32>>,
    also_known_as_web: Option<bool>,
    also_known_as_scid: Option<bool>,
}

impl InteractiveCreateConfigBuilder {
    /// Set the address (URL or DID format). Skips address prompt.
    pub fn address(mut self, address: impl Into<String>) -> Self {
        self.address = Some(address.into());
        self
    }

    /// Add a single authorization key. Skips key generation prompt if at least one is set.
    pub fn authorization_key(mut self, key: Secret) -> Self {
        self.authorization_keys.push(key);
        self
    }

    /// Set all authorization keys at once.
    pub fn authorization_keys(mut self, keys: Vec<Secret>) -> Self {
        self.authorization_keys = keys;
        self
    }

    /// Add a pre-configured verification method. Skips VM prompt if at least one is set.
    pub fn verification_method(mut self, vm: VerificationMethodInput) -> Self {
        self.verification_methods.push(vm);
        self
    }

    /// Set all verification methods at once.
    pub fn verification_methods(mut self, vms: Vec<VerificationMethodInput>) -> Self {
        self.verification_methods = vms;
        self
    }

    /// Add a pre-configured service. Use `{DID}` placeholder for identifiers.
    /// Skips service prompt if at least one is set.
    pub fn service(mut self, service: Value) -> Self {
        self.services.get_or_insert_with(Vec::new).push(service);
        self
    }

    /// Set all services at once.
    pub fn services(mut self, services: Vec<Value>) -> Self {
        self.services = Some(services);
        self
    }

    /// Explicitly set no services (skip prompt).
    pub fn no_services(mut self) -> Self {
        self.services = Some(Vec::new());
        self
    }

    /// Set the controller DID. Skips controller prompt.
    pub fn controller(mut self, controller: impl Into<String>) -> Self {
        self.controller = Some(Some(controller.into()));
        self
    }

    /// Explicitly set no controller (skip prompt).
    pub fn no_controller(mut self) -> Self {
        self.controller = Some(None);
        self
    }

    /// Set also-known-as aliases. Skips alias prompt.
    pub fn also_known_as(mut self, aliases: Vec<String>) -> Self {
        self.also_known_as = Some(aliases);
        self
    }

    /// Set the portable flag. Skips portable prompt.
    pub fn portable(mut self, portable: bool) -> Self {
        self.portable = Some(portable);
        self
    }

    /// Add a pre-rotation next key. Skips next-key prompt if at least one is set.
    pub fn next_key(mut self, key: Secret) -> Self {
        self.next_keys.get_or_insert_with(Vec::new).push(key);
        self
    }

    /// Set all next keys at once.
    pub fn next_keys(mut self, keys: Vec<Secret>) -> Self {
        self.next_keys = Some(keys);
        self
    }

    /// Explicitly set no next keys (skip prompt).
    pub fn no_next_keys(mut self) -> Self {
        self.next_keys = Some(Vec::new());
        self
    }

    /// Set witness configuration. Skips witness prompt.
    pub fn witnesses(mut self, witnesses: Witnesses) -> Self {
        self.witnesses = Some(witnesses);
        self
    }

    /// Explicitly set no witnesses (skip prompt).
    pub fn no_witnesses(mut self) -> Self {
        self.witnesses = Some(Witnesses::Empty {});
        self
    }

    /// Add a witness signing secret keyed by witness DID.
    pub fn witness_secret(mut self, did: impl Into<String>, secret: Secret) -> Self {
        self.witness_secrets.insert(did.into(), secret);
        self
    }

    /// Set all witness secrets at once.
    pub fn witness_secrets(mut self, secrets: HashMap<String, Secret>) -> Self {
        self.witness_secrets = secrets;
        self
    }

    /// Set watcher URLs. Skips watcher prompt.
    pub fn watchers(mut self, watchers: Vec<String>) -> Self {
        self.watchers = Some(watchers);
        self
    }

    /// Explicitly set no watchers (skip prompt).
    pub fn no_watchers(mut self) -> Self {
        self.watchers = Some(Vec::new());
        self
    }

    /// Set the TTL in seconds. Skips TTL prompt.
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(Some(ttl));
        self
    }

    /// Explicitly set no TTL (skip prompt).
    pub fn no_ttl(mut self) -> Self {
        self.ttl = Some(None);
        self
    }

    /// Set whether to add `did:web` to alsoKnownAs. Skips prompt.
    pub fn also_known_as_web(mut self, enabled: bool) -> Self {
        self.also_known_as_web = Some(enabled);
        self
    }

    /// Set whether to add `did:scid:vh` to alsoKnownAs. Skips prompt.
    pub fn also_known_as_scid(mut self, enabled: bool) -> Self {
        self.also_known_as_scid = Some(enabled);
        self
    }

    /// Build the configuration.
    pub fn build(self) -> InteractiveCreateConfig {
        InteractiveCreateConfig {
            address: self.address,
            authorization_keys: self.authorization_keys,
            verification_methods: self.verification_methods,
            services: self.services,
            controller: self.controller,
            also_known_as: self.also_known_as,
            portable: self.portable,
            next_keys: self.next_keys,
            witnesses: self.witnesses,
            witness_secrets: self.witness_secrets,
            watchers: self.watchers,
            ttl: self.ttl,
            also_known_as_web: self.also_known_as_web,
            also_known_as_scid: self.also_known_as_scid,
        }
    }
}

// ─────────────────────── Result ───────────────────────

/// Result of the interactive DID creation flow.
///
/// Contains the created DID, signed log entry, witness proofs,
/// and all secrets used or generated during creation.
#[derive(Clone, Debug)]
pub struct InteractiveCreateResult {
    did: String,
    log_entry: LogEntry,
    witness_proofs: WitnessProofCollection,
    authorization_secrets: Vec<Secret>,
    verification_method_secrets: HashMap<String, Secret>,
    next_key_secrets: Vec<Secret>,
    witness_secrets: HashMap<String, Secret>,
}

impl InteractiveCreateResult {
    /// The resolved DID identifier (with SCID).
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The signed first log entry. Serialize to JSON for `did.jsonl`.
    pub fn log_entry(&self) -> &LogEntry {
        &self.log_entry
    }

    /// Witness proofs. Empty if no witnesses configured.
    pub fn witness_proofs(&self) -> &WitnessProofCollection {
        &self.witness_proofs
    }

    /// Authorization key secrets (update keys).
    pub fn authorization_secrets(&self) -> &[Secret] {
        &self.authorization_secrets
    }

    /// Verification method secrets keyed by resolved VM ID.
    pub fn verification_method_secrets(&self) -> &HashMap<String, Secret> {
        &self.verification_method_secrets
    }

    /// Pre-rotation next key secrets.
    pub fn next_key_secrets(&self) -> &[Secret] {
        &self.next_key_secrets
    }

    /// Witness signing secrets keyed by witness DID.
    pub fn witness_secrets(&self) -> &HashMap<String, Secret> {
        &self.witness_secrets
    }
}

// ─────────────────────── Main function ───────────────────────

/// Run the interactive DID creation flow.
///
/// Uses pre-configured values from `config` where provided, and prompts
/// the user interactively for anything not pre-set.
///
/// The flow follows these steps:
/// 1. Resolve the DID address (URL or DID format)
/// 2. Collect or use authorization keys
/// 3. Build the DID Document (controller, aliases, verification methods, services)
/// 4. Configure parameters (portability, pre-rotation keys, witnesses, watchers, TTL)
/// 5. Optionally add `did:web` and `did:scid:vh` aliases
/// 6. Create and validate the log entry via [`crate::create::create_did`]
/// 7. Return the result with all generated secrets
///
/// # Returns
///
/// An [`InteractiveCreateResult`] containing:
/// - The resolved DID identifier (with SCID)
/// - The signed first log entry (serialize to JSONL for `did.jsonl`)
/// - Witness proofs (serialize to JSON for `did-witness.json`)
/// - All authorization, verification method, next-key, and witness secrets
///
/// # Errors
///
/// Returns [`DIDWebVHError`] if address parsing, key generation, log entry
/// creation, or validation fails. Also returns an error if an interactive
/// prompt encounters an I/O failure.
///
/// # Example
///
/// ```ignore
/// use didwebvh_rs::prelude::*;
///
/// let result = interactive_create_did(InteractiveCreateConfig::default()).await?;
/// println!("Created DID: {}", result.did());
/// result.log_entry().save_to_file("did.jsonl")?;
/// ```
pub async fn interactive_create_did(
    config: InteractiveCreateConfig,
) -> Result<InteractiveCreateResult, DIDWebVHError> {
    // ── Step 1: Resolve address ──
    let webvh_did = match config.address {
        Some(ref addr) => parse_address(addr)?,
        None => prompt_address()?,
    };

    println!(
        "\n{} {}\n",
        style("webvh DID:").color256(69),
        style(&webvh_did).color256(141)
    );

    // ── Step 2: Resolve authorization keys ──
    let auth_keys = if !config.authorization_keys.is_empty() {
        config.authorization_keys
    } else {
        prompt_authorization_keys(&webvh_did)?
    };

    println!("{}", style("Authorizing Keys:").color256(69));
    for k in &auth_keys {
        println!(
            "\t{}",
            style(k.get_public_keymultibase().map_err(map_key_err)?).color256(141)
        );
    }
    println!();

    // ── Step 3: Build DID Document ──
    let mut did_document = json!({
        "id": &webvh_did,
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1",
        ],
        "verificationMethod": [],
        "authentication": [],
        "assertionMethod": [],
        "keyAgreement": [],
        "capabilityInvocation": [],
        "capabilityDelegation": [],
    });

    // Controller
    let controller = match config.controller {
        Some(c) => c,
        None => prompt_controller()?,
    };
    if let Some(ref c) = controller {
        did_document["controller"] = json!(c);
    }

    // AlsoKnownAs
    let also_known_as = match config.also_known_as {
        Some(a) => a,
        None => prompt_also_known_as()?,
    };
    if !also_known_as.is_empty() {
        did_document["alsoKnownAs"] = json!(also_known_as);
    }

    // Verification Methods
    let vm_secrets = if !config.verification_methods.is_empty() {
        build_verification_methods(&webvh_did, &mut did_document, config.verification_methods)?
    } else {
        prompt_verification_methods(&webvh_did, &mut did_document)?
    };

    // Services
    let services = match config.services {
        Some(s) => s,
        None => prompt_services(&webvh_did)?,
    };
    if !services.is_empty() {
        did_document["service"] = json!(services);
    }

    println!(
        "\n{}\n{}",
        style("DID Document:").color256(69),
        style(serde_json::to_string_pretty(&did_document).unwrap()).color256(34)
    );

    // ── Step 4: Build Parameters ──
    let mut parameters = Parameters::default();

    // Update keys from auth keys
    let update_keys: Vec<Multibase> = auth_keys
        .iter()
        .map(|k| {
            k.get_public_keymultibase()
                .map(Multibase::new)
                .map_err(map_key_err)
        })
        .collect::<Result<_, _>>()?;
    parameters.update_keys = Some(Arc::new(update_keys));

    // Portable
    let portable = match config.portable {
        Some(p) => p,
        None => prompt_portable()?,
    };
    if portable {
        parameters.portable = Some(true);
    }

    // Next key hashes
    let (next_key_hashes, next_key_secrets) = match config.next_keys {
        Some(keys) => {
            let hashes = keys
                .iter()
                .map(|k| {
                    k.get_public_keymultibase_hash()
                        .map(Multibase::new)
                        .map_err(map_key_err)
                })
                .collect::<Result<Vec<_>, _>>()?;
            (hashes, keys)
        }
        None => prompt_next_key_hashes()?,
    };
    if !next_key_hashes.is_empty() {
        parameters.next_key_hashes = Some(Arc::new(next_key_hashes));
    }

    // Witnesses
    let (witnesses_config, witness_secrets) = match config.witnesses {
        Some(w) => (w, config.witness_secrets),
        None => prompt_witnesses()?,
    };
    if matches!(&witnesses_config, Witnesses::Value { .. }) {
        parameters.witness = Some(Arc::new(witnesses_config));
    }

    // Watchers
    let watchers = match config.watchers {
        Some(w) => w,
        None => prompt_watchers()?,
    };
    if !watchers.is_empty() {
        parameters.watchers = Some(Arc::new(watchers));
    }

    // TTL
    let ttl = match config.ttl {
        Some(t) => t,
        None => prompt_ttl()?,
    };
    if let Some(t) = ttl {
        parameters.ttl = Some(t);
    }

    // ── Step 5: Alias exports ──
    let also_known_as_web = match config.also_known_as_web {
        Some(v) => v,
        None => prompt_confirm(
            "Would you like to export this DID as a did:web document as well?",
            true,
        )?,
    };
    let also_known_as_scid = match config.also_known_as_scid {
        Some(v) => v,
        None => prompt_confirm(
            "Would you like to refer to this DID as a did:scid:vh in alsoKnownAs?",
            true,
        )?,
    };

    // ── Step 6: Create the DID ──
    let create_config = CreateDIDConfig::builder()
        .address(&webvh_did)
        .authorization_keys(auth_keys.clone())
        .did_document(did_document)
        .parameters(parameters)
        .witness_secrets(witness_secrets.clone())
        .also_known_as_web(also_known_as_web)
        .also_known_as_scid(also_known_as_scid)
        .build()?;

    let result = create_did(create_config).await?;

    let resolved_did = result.did().to_string();

    println!(
        "\n{}\n{}",
        style("First Log Entry:").color256(69),
        style(serde_json::to_string_pretty(result.log_entry()).unwrap()).color256(34)
    );
    println!("{}", style("Successfully Validated").color256(34));

    // ── Step 7: Rewrite secret IDs with resolved DID ──
    let vm_secrets = rewrite_secret_ids(vm_secrets, &webvh_did, &resolved_did);

    Ok(InteractiveCreateResult {
        did: resolved_did,
        log_entry: result.log_entry().clone(),
        witness_proofs: result.witness_proofs().clone(),
        authorization_secrets: auth_keys,
        verification_method_secrets: vm_secrets,
        next_key_secrets,
        witness_secrets,
    })
}

// ─────────────────────── Internal helpers ───────────────────────

/// Parse an address string into a webvh DID string.
fn parse_address(address: &str) -> Result<String, DIDWebVHError> {
    let did_url = if address.starts_with("did:") {
        WebVHURL::parse_did_url(address)?
    } else {
        let url = Url::parse(address)
            .map_err(|e| DIDWebVHError::DIDError(format!("Invalid URL ({address}): {e}")))?;
        WebVHURL::parse_url(&url)?
    };
    Ok(did_url.to_string())
}

/// Rewrite secret map keys and Secret.id from pre-SCID DID to resolved DID.
fn rewrite_secret_ids(
    secrets: HashMap<String, Secret>,
    pre_scid_did: &str,
    resolved_did: &str,
) -> HashMap<String, Secret> {
    secrets
        .into_iter()
        .map(|(k, mut v)| {
            let new_key = k
                .replace("{DID}", resolved_did)
                .replace(pre_scid_did, resolved_did);
            v.id =
                v.id.replace("{DID}", resolved_did)
                    .replace(pre_scid_did, resolved_did);
            (new_key, v)
        })
        .collect()
}

/// Build verification methods from pre-configured inputs into the DID document.
fn build_verification_methods(
    webvh_did: &str,
    document: &mut Value,
    vms: Vec<VerificationMethodInput>,
) -> Result<HashMap<String, Secret>, DIDWebVHError> {
    let mut secrets = HashMap::default();

    for (i, vm) in vms.into_iter().enumerate() {
        let id = vm.id.unwrap_or_else(|| format!("{webvh_did}#key-{i}"));

        let public_key = vm.secret.get_public_keymultibase().map_err(map_key_err)?;

        let vm_json = json!({
            "id": &id,
            "type": "Multikey",
            "publicKeyMultibase": public_key,
            "controller": webvh_did
        });

        document["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .push(vm_json);

        for rel in &vm.relationships {
            document[rel.as_str()]
                .as_array_mut()
                .unwrap()
                .push(Value::String(id.clone()));
        }

        secrets.insert(id, vm.secret);
    }

    Ok(secrets)
}

// ─────────────────────── Prompt functions ───────────────────────

fn prompt_address() -> Result<String, DIDWebVHError> {
    let theme = ColorfulTheme::default();

    println!(
        "{}",
        style("Where will this DID's log file (did.jsonl) be hosted?").color256(69)
    );
    println!(
        "\t{}",
        style(
            "Enter either a URL or a DID identifier. The SCID (Self-Certifying Identifier) \
             will be generated automatically during creation."
        )
        .color256(69)
    );
    println!();
    println!(
        "{} {} {} {}",
        style("URL example:").color256(69),
        style("https://example.com/.well-known/did.jsonl").color256(45),
        style("->").color256(69),
        style("did:webvh:{SCID}:example.com").color256(141),
    );
    println!(
        "{} {} {} {}",
        style("URL example:").color256(69),
        style("https://affinidi.com:8000/path/dids/did.jsonl").color256(45),
        style("->").color256(69),
        style("did:webvh:{SCID}:affinidi.com%3A8000:path:dids").color256(141)
    );

    let mut initial_text = String::new();
    loop {
        let mut input = Input::with_theme(&theme).with_prompt("Address");
        if initial_text.is_empty() {
            input = input.default("http://localhost:8000/".to_string());
        } else {
            input = input.with_initial_text(&initial_text);
        }
        let input: String = input.interact_text().map_err(map_io)?;

        let did_url = if input.starts_with("did:") {
            match WebVHURL::parse_did_url(&input) {
                Ok(u) => u,
                Err(e) => {
                    println!(
                        "{}  {}",
                        style("Invalid DID URL, please try again:").color256(196),
                        style(e.to_string()).color256(9),
                    );
                    initial_text = input;
                    continue;
                }
            }
        } else {
            let url = match Url::parse(&input) {
                Ok(u) => u,
                Err(e) => {
                    println!(
                        "{}  {}",
                        style("Invalid URL, please try again:").color256(196),
                        style(e.to_string()).color256(9),
                    );
                    initial_text = input;
                    continue;
                }
            };
            match WebVHURL::parse_url(&url) {
                Ok(u) => u,
                Err(e) => {
                    println!(
                        "{}  {}",
                        style("Invalid URL, please try again:").color256(196),
                        style(e.to_string()).color256(9),
                    );
                    initial_text = input;
                    continue;
                }
            }
        };

        let http_url = match did_url.get_http_url(None) {
            Ok(u) => u,
            Err(e) => {
                println!(
                    "{}  {}",
                    style("Invalid DID URL, please try again:").color256(196),
                    style(e.to_string()).color256(9),
                );
                initial_text = input;
                continue;
            }
        };

        println!(
            "{} {}",
            style("DID:").color256(69),
            style(&did_url).color256(141)
        );
        println!(
            "{} {}",
            style("URL:").color256(69),
            style(&http_url).color256(45)
        );

        if Confirm::with_theme(&theme)
            .with_prompt("Is this correct?")
            .default(true)
            .interact()
            .map_err(map_io)?
        {
            return Ok(did_url.to_string());
        }
    }
}

fn prompt_authorization_keys(webvh_did: &str) -> Result<Vec<Secret>, DIDWebVHError> {
    println!(
        "{}",
        style("Authorization keys control who can update this DID.").color256(69)
    );
    println!(
        "\t{}",
        style(
            "These keys are published as the DID's updateKeys. Anyone with a valid \
             authorization key can create new log entries (updates) for this DID."
        )
        .color256(69)
    );
    println!(
        "\t{} {}",
        style("At least one key is required.").color256(214),
        style("Multiple keys allow shared management.").color256(69)
    );
    println!(
        "\t{} {}",
        style("DID:").color256(69),
        style(webvh_did).color256(141),
    );

    prompt_keys()
}

fn prompt_controller() -> Result<Option<String>, DIDWebVHError> {
    let theme = ColorfulTheme::default();
    println!(
        "{}",
        style(
            "A controller is another DID that has authority over this DID. \
             This is optional — most DIDs are self-controlled."
        )
        .color256(69)
    );
    loop {
        if Confirm::with_theme(&theme)
            .with_prompt("Set a controller for this DID?")
            .default(false)
            .interact()
            .map_err(map_io)?
        {
            let input: String = Input::with_theme(&theme)
                .with_prompt("Controller DID (e.g. did:webvh:...)")
                .interact()
                .map_err(map_io)?;
            if Confirm::with_theme(&theme)
                .with_prompt(format!("Use ({input}) as controller?"))
                .interact()
                .map_err(map_io)?
            {
                return Ok(Some(input));
            }
        } else {
            return Ok(None);
        }
    }
}

fn prompt_also_known_as() -> Result<Vec<String>, DIDWebVHError> {
    let mut others: Vec<String> = Vec::new();
    let theme = ColorfulTheme::default();

    println!(
        "{}",
        style(
            "You can add alternative identifiers (aliases) for this DID. \
             These are listed in the alsoKnownAs field of the DID document. \
             The did:web and did:scid:vh aliases are handled separately later."
        )
        .color256(69)
    );
    if Confirm::with_theme(&theme)
        .with_prompt("Add any alsoKnownAs aliases?")
        .default(false)
        .interact()
        .map_err(map_io)?
    {
        loop {
            let input: String = Input::with_theme(&theme)
                .with_prompt("Other DID")
                .interact()
                .map_err(map_io)?;
            if Confirm::with_theme(&theme)
                .with_prompt(format!("Use ({input}) as alias?"))
                .interact()
                .map_err(map_io)?
            {
                others.push(input);
            }
            if !Confirm::with_theme(&theme)
                .with_prompt("Add another alias?")
                .default(false)
                .interact()
                .map_err(map_io)?
            {
                break;
            }
        }
    }
    Ok(others)
}

fn prompt_verification_methods(
    webvh_did: &str,
    doc: &mut Value,
) -> Result<HashMap<String, Secret>, DIDWebVHError> {
    let mut secrets = HashMap::default();
    let mut key_id: u32 = 0;
    let mut success_count: u32 = 0;
    let theme = ColorfulTheme::default();

    println!(
        "{}",
        style("Verification methods are cryptographic keys embedded in the DID document.")
            .color256(69)
    );
    println!(
        "\t{}",
        style("Each method is assigned one or more relationships that define how it can be used:")
            .color256(69)
    );
    println!(
        "\t  {} {} {}",
        style("authentication").color256(141),
        style("-").color256(69),
        style("Prove you control this DID (e.g. login, identity verification)").color256(69)
    );
    println!(
        "\t  {} {} {}",
        style("assertionMethod").color256(141),
        style("-").color256(69),
        style("Issue verifiable credentials and sign claims").color256(69)
    );
    println!(
        "\t  {} {} {}",
        style("keyAgreement").color256(141),
        style("-").color256(69),
        style("Establish encrypted communication channels").color256(69)
    );
    println!(
        "\t  {} {} {}",
        style("capabilityInvocation").color256(141),
        style("-").color256(69),
        style("Invoke capabilities (e.g. access control)").color256(69)
    );
    println!(
        "\t  {} {} {}",
        style("capabilityDelegation").color256(141),
        style("-").color256(69),
        style("Delegate capabilities to other parties").color256(69)
    );
    println!(
        "\t{}",
        style("At least one verification method is required.").color256(214)
    );

    loop {
        let vm_id: String = Input::with_theme(&theme)
            .with_prompt("Verification method ID")
            .default(format!("{webvh_did}#key-{key_id}"))
            .interact()
            .map_err(map_io)?;

        let secret = prompt_create_key(&vm_id)?;
        let vm = json!({
            "id": vm_id.clone(),
            "type": "Multikey",
            "publicKeyMultibase": secret.get_public_keymultibase().map_err(map_key_err)?,
            "controller": webvh_did
        });

        let relationships = [
            "authentication",
            "assertionMethod",
            "keyAgreement",
            "capabilityInvocation",
            "capabilityDelegation",
        ];
        let purpose = MultiSelect::with_theme(&theme)
            .with_prompt("Select relationships for this verification method (space to toggle)")
            .items(relationships)
            .defaults(&[true, true, true, false, false])
            .interact()
            .map_err(map_io)?;

        println!(
            "{}\n{}",
            style("Verification Method:").color256(69),
            style(serde_json::to_string_pretty(&vm).unwrap()).color256(141)
        );
        print!("{} ", style("Relationships:").color256(69));
        for r in &purpose {
            print!("{} ", style(relationships[*r]).color256(141));
        }
        println!();

        if Confirm::with_theme(&theme)
            .with_prompt("Accept this Verification Method?")
            .default(true)
            .interact()
            .map_err(map_io)?
        {
            success_count += 1;
            key_id += 1;

            doc["verificationMethod"]
                .as_array_mut()
                .unwrap()
                .push(vm.clone());
            for r in purpose {
                doc[relationships[r]]
                    .as_array_mut()
                    .unwrap()
                    .push(Value::String(vm_id.clone()));
            }
            secrets.insert(vm_id, secret);
        }
        if success_count > 0
            && !Confirm::with_theme(&theme)
                .with_prompt("Add another Verification Method?")
                .default(false)
                .interact()
                .map_err(map_io)?
        {
            break;
        }
    }

    Ok(secrets)
}

fn prompt_services(webvh_did: &str) -> Result<Vec<Value>, DIDWebVHError> {
    println!(
        "{}",
        style(
            "Services describe how to interact with this DID (e.g. messaging endpoints, \
             APIs, linked domains). Each service has an ID, a type, and an endpoint."
        )
        .color256(69)
    );
    let mut services: Vec<Value> = Vec::new();
    let theme = ColorfulTheme::default();
    let service_choice = ["Simple (ID + type + endpoint)", "Complex (JSON editor)"];
    let mut service_id: u32 = 0;

    let default_service_map = r#"{
  "id": "REPLACE",
  "type": "DIDCommMessaging",
  "serviceEndpoint": [
    {
      "accept": [
        "didcomm/v2"
      ],
      "routingKeys": [],
      "uri": "http://localhost:8000/api"
    }
  ]
}"#;

    loop {
        if !Confirm::with_theme(&theme)
            .with_prompt("Add a service for this DID?")
            .default(false)
            .interact()
            .map_err(map_io)?
        {
            return Ok(services);
        }

        let service = match Select::with_theme(&theme)
            .with_prompt("Service type?")
            .items(service_choice)
            .default(0)
            .interact()
            .map_err(map_io)?
        {
            0 => {
                // Simple
                let sid: String = Input::with_theme(&theme)
                    .with_prompt("Service ID")
                    .default(format!("{webvh_did}#service-{service_id}"))
                    .interact()
                    .map_err(map_io)?;

                let service_type: String = Input::with_theme(&theme)
                    .with_prompt("Service Type")
                    .interact()
                    .map_err(map_io)?;

                let service_endpoint: String = Input::with_theme(&theme)
                    .with_prompt("Service Endpoint")
                    .interact()
                    .map_err(map_io)?;

                json!({
                    "id": sid,
                    "type": service_type,
                    "serviceEndpoint": service_endpoint
                })
            }
            1 => {
                // Complex - open editor
                let template = default_service_map
                    .replace("REPLACE", &format!("{webvh_did}#service-{service_id}"));
                if let Some(service) = Editor::new()
                    .extension("json")
                    .edit(&template)
                    .map_err(map_io)?
                {
                    match serde_json::from_str(&service) {
                        Ok(s) => s,
                        Err(e) => {
                            println!("{}", style("Invalid service definition").color256(196));
                            println!("\t{}", style(e.to_string()).color256(196));
                            continue;
                        }
                    }
                } else {
                    println!("Service definition wasn't saved!");
                    continue;
                }
            }
            _ => continue,
        };

        println!(
            "\n{}\n{}\n",
            style("Service:").color256(69),
            style(serde_json::to_string_pretty(&service).unwrap()).color256(141)
        );

        if Confirm::with_theme(&theme)
            .with_prompt("Accept this Service?")
            .default(true)
            .interact()
            .map_err(map_io)?
        {
            services.push(service);
            service_id += 1;
        }
    }
}

fn prompt_portable() -> Result<bool, DIDWebVHError> {
    println!(
        "{}",
        style(
            "Portability allows this DID to be migrated to a different web domain in the future."
        )
        .color256(69)
    );
    println!(
        "\t{}",
        style(
            "If enabled, the DID's SCID remains the same when moved, and the old DID \
             is added as an alias. If disabled, the DID is permanently bound to this domain."
        )
        .color256(69)
    );
    println!(
        "\t{}",
        style("This setting can only be enabled at creation time — it cannot be added later.")
            .color256(214)
    );
    prompt_confirm("Enable portability for this DID?", true)
}

fn prompt_ttl() -> Result<Option<u32>, DIDWebVHError> {
    println!(
        "{}",
        style("TTL (Time To Live) tells resolvers how long to cache this DID before re-fetching.")
            .color256(69)
    );
    println!(
        "\t{}{}",
        style("Recommendation: ").color256(214),
        style(
            "3600 (1 hour) for most DIDs. Lower for frequently updated DIDs, \
             higher for stable ones. Not setting a TTL lets the resolver decide."
        )
        .color256(69)
    );

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Set a TTL?")
        .default(true)
        .interact()
        .map_err(map_io)?
    {
        let ttl: u32 = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("TTL in seconds (e.g. 3600 = 1 hour)")
            .default(3600_u32)
            .interact()
            .map_err(map_io)?;
        Ok(Some(ttl))
    } else {
        Ok(None)
    }
}
