/*!
 * Shared utilities for the interactive CLI flows (create and update).
 *
 * This module is internal to the `cli` feature and not re-exported publicly.
 * It contains common prompt helpers, error mappers, and key/witness generation
 * logic used by both [`crate::cli_create`] and [`crate::cli_update`].
 */

use crate::{
    DIDWebVHError, Multibase, Secret,
    witness::{Witness, Witnesses},
};
use affinidi_tdk::dids::{DID, KeyType};
use ahash::HashMap;
use console::style;
use dialoguer::{Confirm, Editor, Input, Select, theme::ColorfulTheme};
use serde_json::Value;

// ─────────────────────── Error mappers ───────────────────────

/// Map a dialoguer error to a DIDWebVHError.
pub(crate) fn map_io(e: dialoguer::Error) -> DIDWebVHError {
    DIDWebVHError::DIDError(format!("Interactive prompt failed: {e}"))
}

/// Map any Display error (e.g. from Secret operations) to a DIDWebVHError.
pub(crate) fn map_key_err(e: impl std::fmt::Display) -> DIDWebVHError {
    DIDWebVHError::DIDError(format!("Key operation failed: {e}"))
}

// ─────────────────────── Generic prompts ───────────────────────

/// Prompt the user for a yes/no confirmation.
pub(crate) fn prompt_confirm(prompt: &str, default: bool) -> Result<bool, DIDWebVHError> {
    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(default)
        .interact()
        .map_err(map_io)
}

/// Open a JSON editor for the user to edit a document.
pub(crate) fn prompt_edit_document(current: &Value) -> Result<Value, DIDWebVHError> {
    if let Some(document) = Editor::new()
        .extension("json")
        .edit(&serde_json::to_string_pretty(current).unwrap())
        .map_err(|e| DIDWebVHError::DIDError(format!("Editor failed: {e}")))?
    {
        serde_json::from_str(&document)
            .map_err(|e| DIDWebVHError::DIDError(format!("Invalid JSON: {e}")))
    } else {
        Ok(current.clone())
    }
}

// ─────────────────────── Key generation ───────────────────────

/// Prompt the user to generate or import one or more authorization keys.
///
/// Loops until at least one key is added and the user declines to add more.
pub(crate) fn prompt_keys() -> Result<Vec<Secret>, DIDWebVHError> {
    let mut keys: Vec<Secret> = Vec::new();
    let theme = ColorfulTheme::default();

    loop {
        if !keys.is_empty() {
            println!("{}", style("Authorization keys so far:").color256(69));
            for k in &keys {
                println!(
                    "\t{}",
                    style(k.get_public_keymultibase().map_err(map_key_err)?).color256(141)
                );
            }
            if !Confirm::with_theme(&theme)
                .with_prompt("Add another authorization key?")
                .default(false)
                .interact()
                .map_err(map_io)?
            {
                break;
            }
        }

        if Confirm::with_theme(&theme)
            .with_prompt("Do you already have a key to import? (No = generate a new one)")
            .default(false)
            .interact()
            .map_err(map_io)?
        {
            println!(
                "\t{}",
                style("Enter the key in multibase encoding (e.g. z6Mk...)").color256(69)
            );
            let public: String = Input::with_theme(&theme)
                .with_prompt("Public key (multibase)")
                .interact()
                .map_err(map_io)?;

            let private: String = Input::with_theme(&theme)
                .with_prompt("Private key (multibase)")
                .interact()
                .map_err(map_io)?;

            if Confirm::with_theme(&theme)
                .with_prompt(format!(
                    "Use public key ({public}) as an authorization key?"
                ))
                .interact()
                .map_err(map_io)?
            {
                keys.push(Secret::from_multibase(&private, None).map_err(map_key_err)?);
            }
        } else {
            let (did, key) = DID::generate_did_key(KeyType::Ed25519)
                .map_err(|e| DIDWebVHError::DIDError(format!("Key generation failed: {e}")))?;
            println!(
                "{} {}",
                style("Generated DID:").color256(69),
                style(&did).color256(141)
            );
            println!(
                "{} {} {} {}",
                style("publicKeyMultibase:").color256(69),
                style(key.get_public_keymultibase().map_err(map_key_err)?).color256(34),
                style("privateKeyMultibase:").color256(69),
                style(key.get_private_keymultibase().map_err(map_key_err)?).color256(214)
            );
            keys.push(key);
        }
    }

    Ok(keys)
}

/// Prompt the user to select a key type and generate a single key for a verification method.
pub(crate) fn prompt_create_key(id: &str) -> Result<Secret, DIDWebVHError> {
    println!(
        "{}",
        style("Select a key type for this verification method:").color256(69)
    );
    println!(
        "\t{} {} {}",
        style("Ed25519").color256(141),
        style("-").color256(69),
        style("Fast, compact signatures. Recommended for most use cases.").color256(69)
    );
    println!(
        "\t{} {} {}",
        style("X25519").color256(141),
        style("-").color256(69),
        style("Key agreement / encryption (derived from Ed25519).").color256(69)
    );
    println!(
        "\t{} {} {}",
        style("P-256").color256(141),
        style("-").color256(69),
        style("NIST curve. Common in enterprise and government systems.").color256(69)
    );
    println!(
        "\t{} {} {}",
        style("secp256k1").color256(141),
        style("-").color256(69),
        style("Used in Bitcoin/Ethereum ecosystems.").color256(69)
    );
    println!(
        "\t{} {} {}",
        style("P-384").color256(141),
        style("-").color256(69),
        style("NIST curve. Higher security margin than P-256.").color256(69)
    );

    let items = vec![
        KeyType::Ed25519.to_string(),
        "X25519".to_string(),
        KeyType::P256.to_string(),
        KeyType::Secp256k1.to_string(),
        KeyType::P384.to_string(),
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Key type")
        .items(&items)
        .default(0)
        .interact()
        .map_err(map_io)?;

    let mut secret = if selection == 1 {
        // X25519 - generate Ed25519 and convert
        let (_, secret) = DID::generate_did_key(KeyType::Ed25519)
            .map_err(|e| DIDWebVHError::DIDError(format!("Key generation failed: {e}")))?;
        secret
            .to_x25519()
            .map_err(|e| DIDWebVHError::DIDError(format!("X25519 conversion failed: {e}")))?
    } else {
        let key_type = KeyType::try_from(items[selection].as_str())
            .map_err(|e| DIDWebVHError::DIDError(format!("Invalid key type: {e}")))?;
        DID::generate_did_key(key_type)
            .map_err(|e| DIDWebVHError::DIDError(format!("Key generation failed: {e}")))?
            .1
    };

    secret.id = id.to_string();
    Ok(secret)
}

// ─────────────────────── Witness creation ───────────────────────

/// Prompt the user to set up witness nodes from scratch.
///
/// Returns the witness configuration and a map of witness DID -> Secret.
pub(crate) fn prompt_witnesses() -> Result<(Witnesses, HashMap<String, Secret>), DIDWebVHError> {
    let theme = ColorfulTheme::default();

    println!(
        "{}",
        style("Witnesses are independent nodes that co-sign DID updates.").color256(69)
    );
    println!(
        "\t{}",
        style(
            "They protect against unauthorized changes by requiring multiple parties \
             to approve each update. Even if an attacker compromises your authorization \
             keys, they cannot modify the DID without also compromising enough witnesses."
        )
        .color256(69)
    );

    if !Confirm::with_theme(&theme)
        .with_prompt("Enable witnesses for this DID?")
        .default(true)
        .interact()
        .map_err(map_io)?
    {
        return Ok((Witnesses::Empty {}, HashMap::default()));
    }

    println!(
        "{}",
        style(
            "The threshold is the minimum number of witness signatures required to \
             approve an update. Set this lower than your total witness count so the \
             DID remains updatable even if some witness nodes go offline."
        )
        .color256(69)
    );
    println!(
        "\t{}{}",
        style("Example: ").color256(214),
        style("threshold=2 with 3 witnesses means any 2 of 3 must sign.").color256(69)
    );

    let threshold: u32 = Input::with_theme(&theme)
        .with_prompt("Witness threshold (minimum signatures required)")
        .interact()
        .map_err(map_io)?;

    let (witnesses, secrets) = prompt_generate_witness_nodes(threshold)?;

    Ok((
        Witnesses::Value {
            threshold,
            witnesses,
        },
        secrets,
    ))
}

/// Prompt the user to generate or input witness nodes for a given threshold.
///
/// Used by both fresh witness setup and witness node modification.
pub(crate) fn prompt_generate_witness_nodes(
    threshold: u32,
) -> Result<(Vec<Witness>, HashMap<String, Secret>), DIDWebVHError> {
    let theme = ColorfulTheme::default();
    let mut witness_nodes = Vec::new();
    let mut secrets = HashMap::default();

    if Confirm::with_theme(&theme)
        .with_prompt("Auto-generate witness key pairs? (No = enter existing witness DIDs)")
        .default(true)
        .interact()
        .map_err(map_io)?
    {
        for i in 0..(threshold + 1) {
            let (did, key) = DID::generate_did_key(KeyType::Ed25519)
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
            witness_nodes.push(Witness {
                id: Multibase::new(did.clone()),
            });
            secrets.insert(did, key);
        }
    } else {
        println!(
            "\t{}",
            style("Enter each witness as a did:key identifier (e.g. did:key:z6Mk...)").color256(69)
        );
        loop {
            let did: String = Input::with_theme(&theme)
                .with_prompt(format!("Witness #{:02} DID", witness_nodes.len()))
                .interact()
                .map_err(map_io)?;

            witness_nodes.push(Witness {
                id: Multibase::new(did),
            });

            if !Confirm::with_theme(&theme)
                .with_prompt(format!(
                    "Add another witness? (current: {}, threshold: {})",
                    witness_nodes.len(),
                    threshold,
                ))
                .default(true)
                .interact()
                .map_err(map_io)?
            {
                break;
            }
        }
    }

    Ok((witness_nodes, secrets))
}

// ─────────────────────── Next key hashes ───────────────────────

/// Prompt the user to generate pre-rotated authorization key hashes.
///
/// Returns the hashes (for parameters) and the secrets (for storage).
pub(crate) fn prompt_next_key_hashes() -> Result<(Vec<Multibase>, Vec<Secret>), DIDWebVHError> {
    println!(
        "{}",
        style(
            "Pre-rotation protects against authorization key compromise. You commit \
             to the hash of your next key(s) now, so an attacker who steals your \
             current key cannot substitute their own — the next update must use a key \
             matching the pre-committed hash."
        )
        .color256(69)
    );
    println!(
        "{}{}",
        style("Recommendation: ").bold().color256(214),
        style("Generate at least one pre-rotated key. You can add more for redundancy.")
            .color256(69)
    );

    let mut hashes: Vec<Multibase> = Vec::new();
    let mut secrets: Vec<Secret> = Vec::new();

    loop {
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "Generate a pre-rotated key? ({} created so far)",
                hashes.len()
            ))
            .default(true)
            .interact()
            .map_err(map_io)?
        {
            let (_, key) = DID::generate_did_key(KeyType::Ed25519)
                .map_err(|e| DIDWebVHError::DIDError(format!("Key generation failed: {e}")))?;
            println!(
                "{} {} {} {}\n\t{} {}",
                style("publicKeyMultibase:").color256(69),
                style(key.get_public_keymultibase().map_err(map_key_err)?).color256(34),
                style("privateKeyMultibase:").color256(69),
                style(key.get_private_keymultibase().map_err(map_key_err)?).color256(214),
                style("key hash (published):").color256(69),
                style(key.get_public_keymultibase_hash().map_err(map_key_err)?).color256(214)
            );
            hashes.push(Multibase::new(
                key.get_public_keymultibase_hash().map_err(map_key_err)?,
            ));
            secrets.push(key);
        } else {
            break;
        }
    }

    Ok((hashes, secrets))
}

// ─────────────────────── Watchers ───────────────────────

/// Prompt the user to add watcher URLs from scratch.
pub(crate) fn prompt_watchers() -> Result<Vec<String>, DIDWebVHError> {
    let theme = ColorfulTheme::default();
    println!(
        "{}",
        style("Watchers are external nodes that monitor your DID for unauthorized changes.")
            .color256(69)
    );
    println!(
        "\t{}",
        style(
            "They provide an independent audit trail and can alert you if your DID \
             is modified unexpectedly. Adding watchers improves the reliability and \
             trustworthiness of your DID."
        )
        .color256(69)
    );

    if !Confirm::with_theme(&theme)
        .with_prompt("Add watchers for this DID?")
        .default(true)
        .interact()
        .map_err(map_io)?
    {
        return Ok(Vec::new());
    }

    let mut watchers = Vec::new();
    loop {
        let url: String = Input::with_theme(&theme)
            .with_prompt("Watcher URL (e.g. https://watcher.example.com)")
            .interact()
            .map_err(map_io)?;

        watchers.push(url);

        if !Confirm::with_theme(&theme)
            .with_prompt("Add another watcher?")
            .default(false)
            .interact()
            .map_err(map_io)?
        {
            break;
        }
    }

    Ok(watchers)
}
