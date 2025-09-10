//! Handles the migration (portability) of a DID
//! from an existing URL to a new URL
//!
//! 1. portable Parameter must be true
//! 2. SCID must be the same
//! 3. DID Doc must have alsoKnownAs attribute set to prior DID

use crate::{ConfigInfo, updating::authorization::update_authorization_keys};
use anyhow::{Result, anyhow, bail};
use console::style;
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
use didwebvh_rs::{DIDWebVHState, parameters::Parameters, url::WebVHURL};
use serde_json::Value;
use url::Url;

/// Revokes a webvh DID method
pub fn migrate_did(didwebvh: &mut DIDWebVHState, secrets: &mut ConfigInfo) -> Result<bool> {
    let Some(log_entry) = didwebvh.log_entries.last() else {
        bail!("There must at least be a first LogEntry for this DID to migrate it");
    };

    if log_entry.validated_parameters.portable != Some(true) {
        bail!("Portable parameter must be true to migrate a webvh DID!");
    }

    let did = log_entry
        .get_state()
        .get("id")
        .ok_or_else(|| anyhow::anyhow!("DID not found in the log entry state"))?
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("DID is not a string"))?
        .to_string();

    let did_url = WebVHURL::parse_did_url(&did)?;

    println!(
        "\n{}",
        style("** DANGER ** : You are about to migrate this DID to a new URL!")
            .color256(9)
            .blink()
    );

    // Get the new URL
    println!(
        "{} {}",
        style("Current DID URL:").color256(69),
        style(&did_url.get_http_url(None)?).color256(45)
    );

    let new_url: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("New URL")
        .with_initial_text(did_url.get_http_url(None)?)
        .interact_text()?;

    let new_url = Url::parse(&new_url).map_err(|_| anyhow!("Invalid URL format"))?;

    let mut new_did_url = WebVHURL::parse_url(&new_url)?;
    new_did_url.scid = did_url.scid.clone();

    println!(
        "\n{} {}\n",
        style("New DID:").color256(69),
        style(&new_did_url.to_string()).color256(141)
    );

    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Migrate to this new URL?")
        .default(true)
        .interact()?
    {
        return Ok(false);
    }

    // Modify the DID Doc and create new LogEntry
    let did_doc: String = serde_json::to_string(&log_entry.get_state())?;
    let new_did_doc = did_doc.replace(&did_url.to_string(), &new_did_url.to_string());
    let mut new_did_doc: Value = serde_json::from_str(&new_did_doc)?;

    // Add to alsoKnownAs
    if let Some(alias) = new_did_doc.get_mut("alsoKnownAs") {
        alias.as_array_mut().unwrap().push(Value::String(did));
    } else {
        new_did_doc.as_object_mut().unwrap().insert(
            "alsoKnownAs".to_string(),
            Value::Array(vec![Value::String(did)]),
        );
    }

    println!(
        "{}",
        style(serde_json::to_string_pretty(&new_did_doc).unwrap()).color256(141)
    );
    println!();
    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Confirm changes to this DID?")
        .default(true)
        .interact()?
    {
        println!("{}", style("Migration aborted!").color256(141));
        return Ok(false);
    }

    // Create new LogEntry for this migration

    // Create new Parameters with a valid updateKey from previous LogEntry
    let mut new_params = Parameters::default();
    update_authorization_keys(&log_entry.validated_parameters, &mut new_params, secrets)?;

    let Some(signing_key) = secrets.find_secret_by_public_key(&new_params.active_update_keys[0])
    else {
        bail!(
            "No signing key found for active update key: {}",
            new_params.active_update_keys[0]
        );
    };

    didwebvh
        .create_log_entry(None, &new_did_doc, &new_params, signing_key)
        .map_err(|e| anyhow!("Couldn't create LogEntry: {}", e))?;

    Ok(true)
}
