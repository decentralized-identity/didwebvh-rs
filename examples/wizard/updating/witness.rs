/*!
*   Modifying webvh witness parameters is in here
*
*   New witness parameters only take effect on the next update, not the current LogEntry
*/

use std::sync::Arc;

use affinidi_tdk::dids::{DID, KeyType};
use anyhow::{Result, bail};
use console::style;
use dialoguer::{Confirm, Input, MultiSelect, theme::ColorfulTheme};
use didwebvh_rs::{
    parameters::Parameters,
    witness::{Witness, Witnesses},
};

use crate::{ConfigInfo, manage_witnesses};

/// Modify Witness Parameters for an existing DID
pub fn modify_witness_params(
    old_witness: Option<Arc<Witnesses>>,
    new_params: &mut Parameters,
    secrets: &mut ConfigInfo,
) -> Result<()> {
    // Print the existing Witness Configuration
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
            _ => bail!("Invalid Witness Parameter state"),
        }
    } else {
        println!(
            "{}{}{}",
            style("Witnesses are ").color256(69),
            style("NOT").color256(214),
            style(" being used by this DID!").color256(69)
        );
    }

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Change Witness Parameters?")
        .default(false)
        .interact()?
    {
        // If witnesses are being used - disable them alltogether?
        if let Some(witnesses) = &old_witness {
            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Disable Witnessing for this DID?")
                .default(false)
                .interact()?
            {
                // Disable witness parameters
                new_params.witness = Some(Arc::new(Witnesses::Empty {}));
                return Ok(());
            }

            let (threshold, witness_nodes) = match &**witnesses {
                Witnesses::Value {
                    threshold,
                    witnesses,
                } => (threshold.to_owned(), witnesses),
                _ => bail!("Empty Witness Parameters is an invalid state"),
            };

            // Edit existing witness parameters
            let new_threshold = change_threshold(threshold);

            let witness_nodes = modify_witness_nodes(witness_nodes, new_threshold, secrets)?;

            new_params.witness = Some(Arc::new(Witnesses::Value {
                threshold: new_threshold,
                witnesses: witness_nodes,
            }));
        } else {
            // No existing witness setup, create a new one
            manage_witnesses(new_params, secrets)?;
        }
    } else {
        // No changes to Witness configuration
        new_params.witness = None;
    }

    Ok(())
}

/// Change witness threshold #
fn change_threshold(existing: u32) -> u32 {
    Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Witness Threshold Count?")
        .default(existing)
        .interact()
        .unwrap()
}

/// Any changes to the witnesses?
fn modify_witness_nodes(
    witnesses: &[Witness],
    threshold: u32,
    secrets: &mut ConfigInfo,
) -> Result<Vec<Witness>> {
    let mut new_witnesses = Vec::new();

    let selected = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Which Witness Nodes do you want to keep?")
        .items(witnesses)
        .interact()
        .unwrap();

    // Add selected witnesses
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

        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Generate witness DIDs for you?")
            .default(true)
            .interact()?
        {
            let count = if new_witnesses.len() as u32 > threshold {
                break;
            } else {
                (threshold + 1) - new_witnesses.len() as u32
            };

            for i in 0..count {
                let (did, key) = DID::generate_did_key(KeyType::Ed25519).unwrap();
                println!(
                    "{} {}",
                    style(format!("Witness #{i:02}:")).color256(69),
                    style(&did).color256(141)
                );
                println!(
                    "\t{} {} {} {}",
                    style("publicKeyMultibase:").color256(69),
                    style(&key.get_public_keymultibase()?).color256(34),
                    style("privateKeyMultibase:").color256(69),
                    style(&key.get_private_keymultibase()?).color256(214)
                );
                new_witnesses.push(Witness { id: did.clone() });
                secrets.witnesses.insert(did, key);
            }
            break;
        } else {
            let did: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt(format!("Witness #{:02} DID?", new_witnesses.len()))
                .interact()
                .unwrap();

            new_witnesses.push(Witness { id: did });

            if !Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt(format!(
                    "Add another witness: current:({:02}) threshold:({:02})?",
                    new_witnesses.len(),
                    threshold
                ))
                .default(true)
                .interact()?
            {
                break;
            }
        }
    }

    Ok(new_witnesses)
}
