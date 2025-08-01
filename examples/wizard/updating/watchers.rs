/*!
*   Manage the parameters for watchers
*/
use crate::manage_watchers;
use anyhow::Result;
use console::style;
use dialoguer::{Confirm, Input, MultiSelect, theme::ColorfulTheme};
use didwebvh_rs::parameters::Parameters;
use std::sync::Arc;

pub fn modify_watcher_params(
    old_watchers: Option<Arc<Vec<String>>>,
    new_params: &mut Parameters,
) -> Result<()> {
    // Print the existing Watcher Configuration
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

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Change Watcher Parameters?")
        .default(false)
        .interact()?
    {
        // If watchers are being used - disable them alltogether?
        if let Some(watchers) = old_watchers {
            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Disable all watchers for this DID?")
                .default(false)
                .interact()?
            {
                // Disable watcher parameters
                new_params.watchers = Some(Arc::new(Vec::new()));
                return Ok(());
            }

            // Edit existing watcher parameters
            let watchers = modify_watcher_nodes(&watchers)?;

            new_params.watchers = Some(Arc::new(watchers));
        } else {
            // No existing watcher setup, create a new one
            manage_watchers(new_params)?;
        }
    } else {
        // No changes to Watcher configuration
        new_params.watchers = None;
    }
    Ok(())
}

/// Any changes to the watchers?
fn modify_watcher_nodes(watchers: &Arc<Vec<String>>) -> Result<Vec<String>> {
    let mut new_watchers = Vec::new();

    let selected = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Which Watcher Nodes do you want to keep?")
        .items(watchers)
        .interact()
        .unwrap();

    // Add selected watchers
    for i in selected {
        new_watchers.push(watchers[i].clone());
    }

    loop {
        println!(
            "{}{}",
            style("Current Watchers Count: ").color256(69),
            style(new_watchers.len()).color256(34),
        );
        for w in &new_watchers {
            println!("\t{}", style(w).color256(34));
        }

        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Add new Watchers?")
            .default(false)
            .interact()?
        {
            let url: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Watcher URL")
                .interact()
                .unwrap();

            new_watchers.push(url);

            if !Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Add another Watcher?")
                .default(true)
                .interact()?
            {
                break;
            }
        } else {
            break;
        }
    }

    Ok(new_watchers)
}
