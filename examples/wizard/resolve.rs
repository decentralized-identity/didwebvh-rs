use chrono::Utc;
use console::style;
use dialoguer::{Input, theme::ColorfulTheme};
use didwebvh_rs::{DIDWebVHState, log_entry::LogEntryMethods};

pub async fn resolve() {
    let did: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("WebVH DID")
        .default("did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs".to_string())
        .validate_with(|input: &String| {
            if input.is_empty() {
                Err("DID cannot be empty".to_string())
            } else if !input.starts_with("did:webvh:") {
                Err("DID must start with did:webvh:".to_string())
            } else {
                Ok(())
            }
        })
        .interact()
        .unwrap();

    let mut webvh = DIDWebVHState::default();
    println!(
        "{}{}{}",
        style("Resolving (").color256(69),
        style(&did).color256(141),
        style(")").color256(69),
    );

    let start = Utc::now();
    match webvh.resolve(&did, None).await {
        Ok((log_entry, metadata)) => {
            let end = Utc::now();
            println!(
                "{}{}{}{}{}",
                style("Sucessfully resolved (").color256(69),
                style(did).color256(141),
                style(") in ").color256(69),
                style(end.signed_duration_since(start).num_milliseconds()).color256(141),
                style(" milliseconds").color256(69),
            );

            println!(
                "{}",
                style("DID passed all verification and validation checks!").color256(34)
            );

            println!();
            println!(
                "{}",
                style(format!(
                    "DID Doc:\n{}",
                    serde_json::to_string_pretty(&log_entry.get_state())
                        .expect("Failed to serialize DID Document")
                ))
                .color256(34)
            );

            println!();
            println!("{}", style(format!("{:#?}", metadata)).color256(141));
            println!();
        }
        Err(e) => {
            println!("Couldn't resolve DID ({did} Reason: {}", e);
        }
    }
}
