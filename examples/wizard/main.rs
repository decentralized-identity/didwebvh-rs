/*!
*   Interactive webvh DID wizard.
*
*   Uses the library's embeddable CLI flows for DID creation and updates.
*   Run with: `cargo run --example wizard`
*/

use crate::{did_web::save_did_web, resolve::resolve};
use anyhow::Result;
use console::style;
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use didwebvh_rs::{
    cli_create::{InteractiveCreateConfig, interactive_create_did},
    cli_update::{InteractiveUpdateConfig, UpdateSecrets, interactive_update_did},
};
use serde_json::json;
use tracing_subscriber::filter;

mod did_web;
mod resolve;

/// Display a fun banner
fn show_banner() {
    println!();
    println!(
        "{}",
        style("██████╗ ██╗██████╗    ██╗    ██╗███████╗██████╗ ██╗   ██╗██╗  ██╗").color256(196)
    );
    println!(
        "{}",
        style("██╔══██╗██║██╔══██╗██╗██║    ██║██╔════╝██╔══██╗██║   ██║██║  ██║").color256(202)
    );
    println!(
        "{}",
        style("██║  ██║██║██║  ██║╚═╝██║ █╗ ██║█████╗  ██████╔╝██║   ██║███████║").color256(220)
    );
    println!(
        "{}",
        style("██║  ██║██║██║  ██║██╗██║███╗██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══██║").color256(34)
    );
    println!(
        "{}",
        style("██████╔╝██║██████╔╝╚═╝╚███╔███╔╝███████╗██████╔╝ ╚████╔╝ ██║  ██║").color256(21)
    );
    println!(
        "{}",
        style("╚═════╝ ╚═╝╚═════╝     ╚══╝╚══╝ ╚══════╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝").color256(92)
    );
    println!();

    println!(
        "{}",
        style("This wizard will walk you through all the steps in creating a webvh DID")
            .color256(69)
    );
    println!(
        "{} {} {} {} ❤️ ❤️ ❤️",
        style("Built by").color256(69),
        style("Affinidi").color256(255),
        style("- for - ").color256(69),
        style("everyone").color256(255)
    );
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    show_banner();

    let menu = vec![
        "Create a new webvh DID",
        "Update existing DID",
        "Resolve a WebVH DID",
        "Exit",
    ];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("What would you like to do?")
            .items(&menu)
            .default(0)
            .interact()
            .unwrap();

        match selection {
            0 => {
                println!("{}", style("Creating a new webvh DID").color256(69));
                create_new_did().await?;
            }
            1 => {
                println!("{}", style("Updating an existing webvh DID").color256(69));
                update_existing_did().await?;
            }
            2 => {
                println!("{}", style("Resolving a WebVH DID").color256(69));
                resolve().await;
            }
            3 => {
                println!("{}", style("Exiting the wizard, goodbye!").color256(69));
                break;
            }
            _ => {
                println!("{}", style("Invalid selection...").color256(196));
                continue;
            }
        }
    }

    Ok(())
}

/// Create a new DID using the library's interactive flow, then save to files.
async fn create_new_did() -> Result<()> {
    let result = interactive_create_did(InteractiveCreateConfig::default()).await?;

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Save to file?")
        .default(true)
        .interact()?
    {
        let file_name: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("File Name")
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
            .interact()?;

        if let Some((prefix, _)) = file_name.split_once(".") {
            // Save log entry
            result.log_entry().save_to_file(&file_name)?;
            println!(
                "{} {}",
                style("Log entry saved to:").color256(69),
                style(&file_name).color256(214),
            );

            // Save secrets in ConfigInfo-compatible format
            let secrets_file = format!("{prefix}-secrets.json");
            save_create_secrets(&secrets_file, &result)?;
            println!(
                "{} {}",
                style("Secrets saved to:").color256(69),
                style(&secrets_file).color256(214),
            );

            // Save witness proofs
            let witness_file = format!("{prefix}-witness.json");
            if result.witness_proofs().get_total_count() > 0 {
                result.witness_proofs().save_to_file(&witness_file)?;
            }
            println!(
                "{} {}",
                style("Witness proofs saved to:").color256(69),
                style(&witness_file).color256(214),
            );

            // Optionally export did:web
            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Export latest state to a did:web document?")
                .default(true)
                .interact()?
            {
                // Build a temporary LogEntryState to pass to save_did_web
                let mut webvh_state = didwebvh_rs::DIDWebVHState::default();
                webvh_state.load_log_entries_from_file(&file_name)?;
                webvh_state.validate()?;
                if let Some(entry) = webvh_state.log_entries().last() {
                    save_did_web(entry)?;
                }
            }
        }
    }

    Ok(())
}

/// Save create result secrets in the ConfigInfo-compatible JSON format
/// so they can be loaded by the update flow.
fn save_create_secrets(
    path: &str,
    result: &didwebvh_rs::cli_create::InteractiveCreateResult,
) -> Result<()> {
    let mut keys_hash = serde_json::Map::new();
    let mut key_map = serde_json::Map::new();

    // Authorization keys
    for secret in result.authorization_secrets() {
        if let (Ok(hash), Ok(pk)) = (
            secret.get_public_keymultibase_hash(),
            secret.get_public_keymultibase(),
        ) {
            keys_hash.insert(hash.clone(), serde_json::to_value(secret)?);
            key_map.insert(pk, serde_json::Value::String(hash));
        }
    }

    // Next key secrets (also authorization-class keys)
    for secret in result.next_key_secrets() {
        if let (Ok(hash), Ok(pk)) = (
            secret.get_public_keymultibase_hash(),
            secret.get_public_keymultibase(),
        ) {
            keys_hash.insert(hash.clone(), serde_json::to_value(secret)?);
            key_map.insert(pk, serde_json::Value::String(hash));
        }
    }

    // Witness secrets
    let mut witnesses = serde_json::Map::new();
    for (did, secret) in result.witness_secrets() {
        witnesses.insert(did.clone(), serde_json::to_value(secret)?);
    }

    // DID document verification method secrets
    let mut did_keys = serde_json::Map::new();
    for (id, secret) in result.verification_method_secrets() {
        did_keys.insert(id.clone(), serde_json::to_value(secret)?);
    }

    let config_info = json!({
        "keys_hash": keys_hash,
        "key_map": key_map,
        "witnesses": witnesses,
        "did_keys": did_keys,
    });

    let file = std::fs::File::create(path)?;
    serde_json::to_writer_pretty(file, &config_info)?;
    Ok(())
}

/// Update an existing DID using the library's interactive flow, then save to files.
async fn update_existing_did() -> Result<()> {
    let result = interactive_update_did(InteractiveUpdateConfig::default()).await?;

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Save to file?")
        .default(true)
        .interact()?
    {
        let file_name: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("File Name")
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
            .interact()?;

        if let Some((prefix, _)) = file_name.split_once(".") {
            // Save the new log entry (append)
            result.log_entry().save_to_file(&file_name)?;
            println!(
                "{} {}",
                style("Log entry saved to:").color256(69),
                style(&file_name).color256(214),
            );

            // Save secrets
            let secrets_file = format!("{prefix}-secrets.json");
            save_update_secrets(&secrets_file, result.secrets())?;
            println!(
                "{} {}",
                style("Secrets saved to:").color256(69),
                style(&secrets_file).color256(214),
            );

            // Save witness proofs
            let witness_file = format!("{prefix}-witness.json");
            if result.state().witness_proofs().get_total_count() > 0 {
                result
                    .state()
                    .witness_proofs()
                    .save_to_file(&witness_file)?;
            }
            println!(
                "{} {}",
                style("Witness proofs saved to:").color256(69),
                style(&witness_file).color256(214),
            );

            // Optionally export did:web
            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Export latest state to a did:web document?")
                .default(true)
                .interact()?
            {
                if let Some(entry) = result.state().log_entries().last() {
                    save_did_web(entry)?;
                }
            }
        }
    }

    Ok(())
}

/// Save UpdateSecrets in ConfigInfo-compatible JSON format.
fn save_update_secrets(path: &str, secrets: &UpdateSecrets) -> Result<()> {
    let mut keys_hash = serde_json::Map::new();
    for (hash, secret) in &secrets.keys_hash {
        keys_hash.insert(hash.clone(), serde_json::to_value(secret)?);
    }

    let mut key_map = serde_json::Map::new();
    for (pk, hash) in &secrets.key_map {
        key_map.insert(pk.clone(), serde_json::Value::String(hash.clone()));
    }

    let mut witnesses = serde_json::Map::new();
    for (did, secret) in &secrets.witnesses {
        witnesses.insert(did.clone(), serde_json::to_value(secret)?);
    }

    let config_info = json!({
        "keys_hash": keys_hash,
        "key_map": key_map,
        "witnesses": witnesses,
        "did_keys": {},
    });

    let file = std::fs::File::create(path)?;
    serde_json::to_writer_pretty(file, &config_info)?;
    Ok(())
}
