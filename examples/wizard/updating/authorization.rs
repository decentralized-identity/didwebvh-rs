/*!
*   Modifying authorization keys depends on whether the DID is
*   in pre-rotation mode or not
*/

use std::sync::Arc;

use crate::{ConfigInfo, create_next_key_hashes, get_keys};
use affinidi_secrets_resolver::secrets::Secret;
use anyhow::{Result, bail};
use console::style;
use dialoguer::{Confirm, MultiSelect, theme::ColorfulTheme};
use didwebvh_rs::{DIDWebVHError, parameters::Parameters};

/// Handles all possible states of updating updateKeys including pre-rotation and non-pre-rotation
/// modes. updateKeys and NextKeyHashes are modified here
/// Returns authorization key for this update
pub fn update_authorization_keys(
    old_params: &Parameters,
    new_params: &mut Parameters,
    existing_secrets: &mut ConfigInfo,
) -> Result<()> {
    // What mode are we operating in?
    if old_params.pre_rotation_active {
        // Pre-Rotation mode

        // Disable pre-rotation mode?
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Disable pre-rotation mode?")
            .default(false)
            .interact()?
        {
            // Disabling pre-rotation mode
            new_params.pre_rotation_active = false;
            new_params.next_key_hashes = Some(Arc::new(Vec::new()));
            let update_keys =
                select_update_keys_from_next_hashes(&old_params.next_key_hashes, existing_secrets)?;
            let mut tmp_keys = Vec::new();
            for key in update_keys {
                tmp_keys.push(key.get_public_keymultibase()?);
            }
            let new_keys = Arc::new(tmp_keys);
            new_params.update_keys = Some(new_keys.clone());
            new_params.active_update_keys = new_keys;
        } else {
            // Staying in pre-rotation mode
            new_params.pre_rotation_active = true;

            // Select update_keys for this update
            let update_keys =
                select_update_keys_from_next_hashes(&old_params.next_key_hashes, existing_secrets)?;
            let mut tmp_keys = Vec::new();
            for key in update_keys {
                tmp_keys.push(key.get_public_keymultibase()?);
            }
            let new_keys = Arc::new(tmp_keys);
            new_params.update_keys = Some(new_keys.clone());
            new_params.active_update_keys = new_keys;

            // Create new next_key_hashes
            let next_key_hashes = create_next_key_hashes(existing_secrets)?;
            if next_key_hashes.is_empty() {
                bail!("No next key hashes created for pre-rotation mode");
            }
            new_params.next_key_hashes = Some(Arc::new(next_key_hashes));
        }
    } else {
        // Non pre-rotation mode
        new_params.active_update_keys = old_params.active_update_keys.clone();
        new_params.pre_rotation_active = false;

        // Do you want to enable pre-rotation mode?
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Enable pre-rotation mode?")
            .default(false)
            .interact()?
        {
            // Enable pre-rotation mode
            let next_key_hashes = create_next_key_hashes(existing_secrets)?;
            if next_key_hashes.is_empty() {
                bail!("No next key hashes created for pre-rotation mode");
            }
            new_params.next_key_hashes = Some(Arc::new(next_key_hashes));
        } else {
            // Stay in non pre-rotation mode
            // check if modify updateKeys
            modify_update_keys(new_params, old_params, existing_secrets)?;
        }
    }
    Ok(())
}

/// What update key will we use? Must be from an existing set of keys authorized keys
/// Returns array of Secrets
fn select_update_keys_from_next_hashes(
    next_key_hashes: &Option<Arc<Vec<String>>>,
    existing_secrets: &ConfigInfo,
) -> Result<Vec<Secret>> {
    let Some(hashes) = next_key_hashes else {
        bail!("No next key hashes found for pre-rotation mode".to_string());
    };

    let selected = loop {
        let selected = MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Which pre-rotated keys do you want to use for this LogEntry update?")
            .items(hashes)
            .defaults(&[true])
            .interact()
            .unwrap();
        if !selected.is_empty() {
            break selected;
        } else {
            println!(
                "{}",
                style("You MUST select at least one key from the pre-rolled keys!").color256(9)
            );
        }
    };

    let mut selected_secrets = Vec::new();
    for i in selected {
        existing_secrets
            .find_secret_by_hash(&hashes[i])
            .map(|secret| selected_secrets.push(secret.to_owned()))
            .ok_or_else(|| {
                DIDWebVHError::ParametersError(format!(
                    "Couldn't find a matching Secret key for hash: {}",
                    hashes[i]
                ))
            })?;
    }

    Ok(selected_secrets)
}

/// Any changes to the updateKeys?
fn modify_update_keys(
    new_params: &mut Parameters,
    old_params: &Parameters,
    existing_secrets: &mut ConfigInfo,
) -> Result<()> {
    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Do you want to change authorization keys going forward from this update?")
        .default(false)
        .interact()?
    {
        if old_params.active_update_keys.is_empty() {
            bail!("No active update keys found in previous LogEntry parameters");
        }

        let mut new_update_keys = Vec::new();

        let selected = MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Which existing authorization keys do you want to keep?")
            .items(&old_params.active_update_keys)
            .interact()
            .unwrap();

        // Add new keys
        for i in selected {
            new_update_keys.push(new_params.active_update_keys[i].clone());
        }

        // Do we want to add new keys?
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Would you like to create new update keys to add to the authorized keys?")
            .default(false)
            .interact()?
        {
            let keys = get_keys()?;
            for k in keys {
                new_update_keys.push(k.get_public_keymultibase()?);
                existing_secrets.add_key(&k);
            }
        }

        new_params.update_keys = Some(Arc::new(new_update_keys));
    } else {
        // No changes made to existing authorization keys
        new_params.update_keys = None;
    }

    Ok(())
}
