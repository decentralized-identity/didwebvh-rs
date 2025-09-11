/*!
*   Tasks relating to editing an existing webvh DID go here
*/
use crate::{
    ConfigInfo,
    did_web::save_did_web,
    edit_did_document,
    updating::{
        authorization::update_authorization_keys, portable::migrate_did, revoke::revoke_did,
        watchers::modify_watcher_params, witness::modify_witness_params,
    },
    witness::witness_log_entry,
};
use anyhow::{Result, bail};
use console::style;
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use didwebvh_rs::{
    DIDWebVHError, DIDWebVHState, log_entry_state::LogEntryState, parameters::Parameters,
};

mod authorization;
mod portable;
mod revoke;
mod watchers;
mod witness;

pub async fn edit_did() -> Result<()> {
    // Load in data from various files
    let file_path: String = Input::with_theme(&ColorfulTheme::default())
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
        .unwrap();

    let mut webvh_state = DIDWebVHState::default();
    let (mut config_info, file_name_prefix) = if let Some((start, _)) = file_path.split_once(".") {
        webvh_state.load_log_entries_from_file(&file_path)?;
        webvh_state.load_witness_proofs_from_file(&[start, "-witness.json"].concat());

        // Load the secrets
        let config_info = ConfigInfo::read_from_file(&[start, "-secrets.json"].concat())
            .map_err(|e| DIDWebVHError::ParametersError(format!("Failed to read secrets: {e}")))?;
        (config_info, start)
    } else {
        bail!("Invalid file path! Must end with .jsonl!");
    };

    // Validate webvh state
    match webvh_state.validate() {
        Ok(_) => {
            println!(
                "{}",
                style("Successfully loaded DID WebVH state")
                    .color256(34)
                    .blink()
            );
        }
        Err(e) => {
            println!(
                "{}",
                style(format!("Failed to validate DID WebVH state: {e}"))
                    .color256(196)
                    .blink()
            );
            return Err(e.into());
        }
    }

    let last_entry_state = webvh_state.log_entries.last().ok_or_else(|| {
        DIDWebVHError::ParametersError("No log entries found in the file".to_string())
    })?;
    let metadata = webvh_state.generate_meta_data(last_entry_state);

    println!(
        "{}\n{}",
        style("Log Entry Parameters:").color256(69),
        style(serde_json::to_string_pretty(&last_entry_state.validated_parameters).unwrap())
            .color256(34),
    );
    println!();
    println!(
        "{}\n{}\n\n{}",
        style("Log Entry Metadata:").color256(69),
        style(serde_json::to_string_pretty(&metadata).unwrap()).color256(34),
        style("Successfully Loaded").color256(34).blink(),
    );

    println!();

    let menu = vec![
        "Create a new Log Entry (Modify DID Document or Parameters)?",
        "Move to a new domain (portability)?",
        "Revoke this DID?",
        "Back",
    ];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Action")
            .items(&menu)
            .default(0)
            .interact()
            .unwrap();

        match selection {
            0 => {
                // Create a new LogEntry for a given DID
                create_log_entry(&mut webvh_state, &mut config_info).await?;

                let new_entry = webvh_state.log_entries.last().ok_or_else(|| {
                    DIDWebVHError::LogEntryError("No new LogEntry created".to_string())
                })?;

                let new_proofs = witness_log_entry(
                    &mut webvh_state.witness_proofs,
                    new_entry,
                    &new_entry.get_active_witnesses(),
                    &config_info,
                )?;

                // Save info to files
                new_entry.log_entry.save_to_file(&file_path)?;
                config_info.save_to_file(&[file_name_prefix, "-secrets.json"].concat())?;
                println!(
                    "{}",
                    style("Successfully created new LogEntry")
                        .color256(34)
                        .blink()
                );
                if new_proofs.is_some() {
                    webvh_state
                        .witness_proofs
                        .save_to_file(&[file_name_prefix, "-witness.json"].concat())?;
                }

                if Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Export latest state to a did:web document?")
                    .default(true)
                    .interact()
                    .unwrap()
                {
                    save_did_web(new_entry)?;
                }

                break;
            }
            1 => {
                // DID Portability
                if migrate_did(&mut webvh_state, &mut config_info)? {
                    let new_entry = webvh_state.log_entries.last().ok_or_else(|| {
                        DIDWebVHError::LogEntryError("No new LogEntry created".to_string())
                    })?;

                    let new_proofs = witness_log_entry(
                        &mut webvh_state.witness_proofs,
                        new_entry,
                        &new_entry.get_active_witnesses(),
                        &config_info,
                    )?;

                    // Save info to files
                    new_entry.log_entry.save_to_file(&file_path)?;
                    config_info.save_to_file(&[file_name_prefix, "-secrets.json"].concat())?;
                    println!(
                        "{}",
                        style("Successfully created new LogEntry")
                            .color256(34)
                            .blink()
                    );
                    if new_proofs.is_some() {
                        webvh_state
                            .witness_proofs
                            .save_to_file(&[file_name_prefix, "-witness.json"].concat())?;
                    }

                    if Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("Export latest state to a did:web document?")
                        .default(true)
                        .interact()
                        .unwrap()
                    {
                        save_did_web(new_entry)?;
                    }
                }

                break;
            }
            2 => {
                revoke_did(&file_path, &mut webvh_state, &config_info).await?;
                break;
            }
            3 => {
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

async fn create_log_entry(
    didwebvh: &mut DIDWebVHState,
    config_info: &mut ConfigInfo,
) -> Result<()> {
    println!(
        "{}",
        style("Modifying DID Document and/or Parameters").color256(69)
    );

    let previous_log_entry = didwebvh
        .log_entries
        .last()
        .ok_or_else(|| DIDWebVHError::LogEntryError("No log entries found".to_string()))?;

    // ************************************************************************
    // Change the DID Document?
    // ************************************************************************
    let new_state = if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Edit the DID Document?")
        .default(false)
        .interact()?
    {
        edit_did_document(previous_log_entry.get_state())?
    } else {
        previous_log_entry.get_state().clone()
    };

    // ************************************************************************
    // Change webvh Parameters
    // ************************************************************************
    let new_params = update_parameters(previous_log_entry, config_info)?;

    // ************************************************************************
    // Create a new LogEntry
    // ************************************************************************
    let Some(signing_key) =
        config_info.find_secret_by_public_key(&new_params.active_update_keys[0])
    else {
        bail!(
            "No signing key found for active update key: {}",
            new_params.active_update_keys[0]
        );
    };
    let log_entry = didwebvh.create_log_entry(None, &new_state, &new_params, signing_key)?;

    println!(
        "{}\n{}",
        style("New Log Entry:").color256(69),
        style(serde_json::to_string_pretty(&log_entry.log_entry).unwrap()).color256(34)
    );

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Accept this updated LogEntry?")
        .default(true)
        .interact()?
    {
        Ok(())
    } else {
        didwebvh.log_entries.pop(); // Remove the last entry
        println!("{}", style("Rejecting all changes!").color256(9));
        bail!("Changes Rejected")
    }
}

/// Run UI for creating new parameter set
/// Returns: New Parameters
fn update_parameters(
    old_log_entry: &LogEntryState,
    secrets: &mut ConfigInfo,
) -> Result<Parameters> {
    let mut new_params = Parameters::default();

    // ************************************************************************
    // Authorization Keys
    // ************************************************************************
    update_authorization_keys(
        &old_log_entry.validated_parameters,
        &mut new_params,
        secrets,
    )?;
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
    println!(
        "{}\n{}",
        style("nextKeyHashes: ").color256(69),
        style(serde_json::to_string_pretty(&new_params.next_key_hashes).unwrap()).color256(34)
    );
    println!(
        "{}\n{}",
        style("updateKeys: ").color256(69),
        style(serde_json::to_string_pretty(&new_params.update_keys).unwrap()).color256(34)
    );

    // ************************************************************************
    // Portability
    // ************************************************************************
    if let Some(portable) = old_log_entry.validated_parameters.portable
        && portable
    {
        // Portable
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Disable portability for this DID?")
            .default(false)
            .interact()
            .map_err(|e| {
                DIDWebVHError::ParametersError(format!("Invalid selection on portability: {e}"))
            })?
        {
            // Disable portability
            new_params.portable = Some(false);
        } else {
            // Keep portability
            new_params.portable = Some(true);
        }
    }

    // ************************************************************************
    // Witnesses
    // ************************************************************************
    modify_witness_params(
        old_log_entry.validated_parameters.witness.clone(),
        &mut new_params,
        secrets,
    )?;

    // ************************************************************************
    // Watchers
    // ************************************************************************

    modify_watcher_params(
        old_log_entry.validated_parameters.watchers.clone(),
        &mut new_params,
    )?;

    // ************************************************************************
    // TTL
    // ************************************************************************
    modify_ttl_params(&old_log_entry.validated_parameters.ttl, &mut new_params)?;

    // Map the new parameters to the previous validated parameters

    Ok(new_params)
}

/// Modify the TTL for this DID?
fn modify_ttl_params(ttl: &Option<u32>, params: &mut Parameters) -> Result<()> {
    print!("{}", style("Existing TTL: ").color256(69));
    let current_ttl = if let Some(ttl) = ttl {
        println!("{}", style(ttl).color256(34));
        ttl.to_owned()
    } else {
        println!("{}", style("NOT SET").color256(214));
        0_u32
    };

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Change the TTL?")
        .default(false)
        .interact()?
    {
        let new_ttl: u32 = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("New TTL (0 = Disable TTL)?")
            .default(current_ttl)
            .interact()?;

        if new_ttl == 0 {
            // Disable TTL
            params.ttl = Some(3600);
        } else {
            // Set new TTL
            params.ttl = Some(new_ttl);
        }
    } else {
        // Keep existing TTL
        params.ttl = ttl.to_owned();
    }

    Ok(())
}
