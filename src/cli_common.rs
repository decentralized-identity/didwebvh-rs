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
            println!("{}", style("Authorizing Keys:").color256(69));
            for k in &keys {
                println!(
                    "\t{}",
                    style(k.get_public_keymultibase().map_err(map_key_err)?).color256(141)
                );
            }
            if !Confirm::with_theme(&theme)
                .with_prompt("Do you want to add another key?")
                .default(false)
                .interact()
                .map_err(map_io)?
            {
                break;
            }
        }

        if Confirm::with_theme(&theme)
            .with_prompt("Do you already have a key to use?")
            .default(false)
            .interact()
            .map_err(map_io)?
        {
            let public: String = Input::with_theme(&theme)
                .with_prompt("publicKeyMultibase")
                .interact()
                .map_err(map_io)?;

            let private: String = Input::with_theme(&theme)
                .with_prompt("privateKeyMultibase")
                .interact()
                .map_err(map_io)?;

            if Confirm::with_theme(&theme)
                .with_prompt(format!(
                    "Use public({public}) and private({private}) as an authorized key?"
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
                style("DID:").color256(69),
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
    let items = vec![
        KeyType::Ed25519.to_string(),
        "X25519".to_string(),
        KeyType::P256.to_string(),
        KeyType::Secp256k1.to_string(),
        KeyType::P384.to_string(),
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("What key type?")
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
/// Returns the witness configuration and a map of witness DID → Secret.
pub(crate) fn prompt_witnesses() -> Result<(Witnesses, HashMap<String, Secret>), DIDWebVHError> {
    let theme = ColorfulTheme::default();

    println!(
        "{}",
        style(
            "To protect against compromised controller authorization keys, \
             use witness nodes which can offer additional protection!"
        )
        .color256(69)
    );

    if !Confirm::with_theme(&theme)
        .with_prompt("Do you want to use witnesses?")
        .default(true)
        .interact()
        .map_err(map_io)?
    {
        return Ok((Witnesses::Empty {}, HashMap::default()));
    }

    println!(
        "{}",
        style("What is the minimum number (threshold) of witnesses required to witness a change?")
            .color256(69)
    );
    println!(
        "\t{}",
        style(
            "Number of witnesses should be higher than threshold \
             to handle failure of a witness node(s)"
        )
        .color256(69)
    );

    let threshold: u32 = Input::with_theme(&theme)
        .with_prompt("Witness Threshold Count?")
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
        .with_prompt("Generate witness DIDs for you?")
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
        loop {
            let did: String = Input::with_theme(&theme)
                .with_prompt(format!("Witness #{:02} DID?", witness_nodes.len()))
                .interact()
                .map_err(map_io)?;

            witness_nodes.push(Witness {
                id: Multibase::new(did),
            });

            if !Confirm::with_theme(&theme)
                .with_prompt(format!(
                    "Add another witness: current:({:02}) threshold:({threshold:02})?",
                    witness_nodes.len(),
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
            "Best practice to set pre-rotated authorization key(s), \
             protects against an attacker switching to new authorization keys"
        )
        .color256(69)
    );
    println!(
        "{}{}{}{}",
        style("NOTE: ").bold().color256(214),
        style("This will loop until you decide you have enough key hashes. Select").color256(69),
        style(" <no> ").color256(214),
        style("to stop generating key hashes").color256(69)
    );

    let mut hashes: Vec<Multibase> = Vec::new();
    let mut secrets: Vec<Secret> = Vec::new();

    loop {
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "Existing hashes ({}): Generate a new pre-rotated key?",
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
                style("key hash:").color256(69),
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
        style("For reliability and durability, you should nominate watchers for this DID")
            .color256(69)
    );

    if !Confirm::with_theme(&theme)
        .with_prompt("Do you want to add watchers?")
        .default(true)
        .interact()
        .map_err(map_io)?
    {
        return Ok(Vec::new());
    }

    let mut watchers = Vec::new();
    loop {
        let url: String = Input::with_theme(&theme)
            .with_prompt("Watcher URL?")
            .interact()
            .map_err(map_io)?;

        watchers.push(url);

        if !Confirm::with_theme(&theme)
            .with_prompt("Add another watcher?")
            .default(true)
            .interact()
            .map_err(map_io)?
        {
            break;
        }
    }

    Ok(watchers)
}
