/*!
*   Revokes a webvh DID, this means it can no longer be updated or is valid from that date.
*
*   If key pre-rotation is in place, then two new LogEntries will be created
*   1. Stop key rotation
*   2. Deactivate the DID
*/

use crate::{ConfigInfo, witness::witness_log_entry};
use anyhow::{Result, anyhow, bail};
use console::style;
use dialoguer::{Confirm, theme::ColorfulTheme};
use didwebvh_rs::{DIDWebVHState, parameters::Parameters};
use std::sync::Arc;
use tracing::debug;

/// Revokes a webvh DID method
pub async fn revoke_did(
    file_path: &str,
    didwebvh: &mut DIDWebVHState,
    secrets: &ConfigInfo,
) -> Result<()> {
    println!(
        "{}",
        style("** DANGER ** : You are about to revoke a DID!")
            .color256(9)
            .blink()
    );

    let last_entry = didwebvh
        .log_entries
        .last()
        .ok_or_else(|| anyhow!("No LogEntries found!"))?;

    let our_did = if let Some(did) = last_entry.get_state().get("id") {
        if let Some(did) = did.as_str() {
            did.to_string()
        } else {
            bail!("Couldn't convert DID to string!");
        }
    } else {
        bail!("Couldn't find ID in DID Document!");
    };

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Are you sure you want to deactivate the DID({our_did})?",
        ))
        .default(false)
        .interact()?
    {
        if last_entry.validated_parameters.pre_rotation_active {
            // Need to deactivate pre-rotation
            println!(
                "{}",
                style("Key pre-rotation is active, must disable first! disabling...").color256(214)
            );
            deactivate_pre_rotation(didwebvh, secrets).await?;
            save_to_files(file_path, didwebvh, secrets)?;
            println!(
                "{}",
                style("Key Pre-rotation has been disabled").color256(34)
            );
        }

        // Revoke the DID!
        revoke_entry(didwebvh, secrets).await?;
        save_to_files(file_path, didwebvh, secrets)?;
        let Some(log_entry) = didwebvh.log_entries.last() else {
            bail!("No LogEntries found after revocation!");
        };
        println!(
            "{}{}{}{}{}",
            style(&log_entry.get_version_id()).color256(141),
            style(": ").color256(69),
            style("DID (").color256(9),
            style(&our_did).color256(141),
            style(") has been revoked!").color256(9)
        );
    }
    Ok(())
}

/// Creates a LogEntry that turns off pre-rotation
async fn deactivate_pre_rotation(didwebvh: &mut DIDWebVHState, secrets: &ConfigInfo) -> Result<()> {
    let last_entry = didwebvh
        .log_entries
        .last()
        .ok_or_else(|| anyhow!("No LogEntries found!"))?;

    // Create new Parameters with a valid updateKey from previous LogEntry
    let new_update_key =
        if let Some(next_key_hashes) = &last_entry.validated_parameters.next_key_hashes {
            if let Some(hash) = next_key_hashes.first() {
                if let Some(secret) = secrets.find_secret_by_hash(hash) {
                    secret.to_owned()
                } else {
                    bail!("No secret found for next key hash: {}", hash);
                }
            } else {
                bail!("No next key hashes available!");
            }
        } else {
            bail!("Expecting nextKeyHashes, but doesn't exist!");
        };

    let new_params = Parameters {
        update_keys: Some(Arc::new(vec![new_update_key.get_public_keymultibase()?])),
        next_key_hashes: Some(Arc::new(Vec::new())),
        ..Default::default()
    };

    didwebvh
        .create_log_entry(
            None,
            &last_entry.get_state().clone(),
            &new_params,
            &new_update_key,
        )
        .map_err(|e| anyhow!("Couldn't create LogEntry: {}", e))?;

    Ok(())
}

/// Final LogEntry
async fn revoke_entry(didwebvh: &mut DIDWebVHState, secrets: &ConfigInfo) -> Result<()> {
    let last_entry = didwebvh
        .log_entries
        .last()
        .ok_or_else(|| anyhow!("No LogEntries found!"))?;

    // Create new Parameters with a valid updateKey from previous LogEntry
    let new_update_key =
        if let Some(key) = &last_entry.validated_parameters.active_update_keys.first() {
            if let Some(secret) = secrets.find_secret_by_public_key(key) {
                secret.to_owned()
            } else {
                bail!("No secret found for update key: {}", key);
            }
        } else {
            bail!("No update key available!");
        };

    let new_params = Parameters {
        deactivated: Some(true),
        update_keys: Some(Arc::new(Vec::new())),
        ..Default::default()
    };

    debug!("Creating final revocation LogEntry");
    let state = last_entry.get_state().clone();
    didwebvh
        .create_log_entry(None, &state, &new_params, &new_update_key)
        .map_err(|e| anyhow!("Couldn't create LogEntry: {}", e))?;

    Ok(())
}
fn save_to_files(
    file_path: &str,
    webvh_state: &mut DIDWebVHState,
    config_info: &ConfigInfo,
) -> Result<()> {
    let new_entry = webvh_state
        .log_entries
        .last()
        .ok_or_else(|| anyhow!("No LogEntries found!"))?;

    let Some((file_name_prefix, _)) = file_path.split_once(".") else {
        bail!("Invalid filename!");
    };

    let new_proofs = witness_log_entry(
        &mut webvh_state.witness_proofs,
        new_entry,
        &new_entry.validated_parameters.active_witness,
        config_info,
    )?;

    // Save info to files
    new_entry.log_entry.save_to_file(file_path)?;
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

    Ok(())
}
