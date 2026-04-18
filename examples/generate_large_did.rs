//! Generate a large (1 MB+) WebVH DID file
//!
//! Creates a valid did.jsonl with enough log entries to exceed 1 MB, using
//! backdated timestamps so the file passes verification. Each update rotates
//! keys and adds service endpoints to bulk up the DID document.
//!
//! Usage:
//!   cargo run --example generate_large_did -- --url https://example.com
//!   cargo run --example generate_large_did -- --url https://example.com:8080/custom/path
//!   cargo run --example generate_large_did -- --url https://example.com --target-kb 2048

use affinidi_secrets_resolver::{SecretsResolver, SimpleSecretsResolver, secrets::Secret};
use anyhow::{Result, anyhow};
use byte_unit::{Byte, UnitType};
use chrono::{Duration as ChronoDuration, FixedOffset, Utc};
use clap::Parser;
use console::style;
use didwebvh_rs::{
    DIDWebVHState, Multibase, did_key::generate_did_key, parameters::Parameters, prelude::KeyType,
    url::WebVHURL,
};
use serde_json::json;
use std::{fs::OpenOptions, io::Write, sync::Arc, time::SystemTime};
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about = "Generate a large (1 MB+) WebVH DID file")]
struct Args {
    /// URL for the DID (e.g. "https://example.com" or "https://example.com:8080/custom/path")
    #[arg(short, long)]
    url: String,

    /// Target file size in KB (default: 1024 = 1 MB)
    #[arg(short, long, default_value_t = 1024)]
    target_kb: u64,

    /// Number of service endpoints per DID document (bulks up each entry)
    #[arg(short, long, default_value_t = 5)]
    services: usize,
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let args: Args = Args::parse();

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let target_bytes = args.target_kb * 1024;

    // Parse the URL into a WebVHURL to properly derive the DID template
    let parsed_url =
        url::Url::parse(&args.url).map_err(|e| anyhow!("Invalid URL '{}': {e}", args.url))?;
    let webvh_url = WebVHURL::parse_url(&parsed_url)
        .map_err(|e| anyhow!("Cannot convert URL to WebVH DID: {e}"))?;
    // to_did_base() produces "did:webvh:{SCID}:domain%3Aport:path" with proper encoding
    let did_template = webvh_url.to_did_base();

    println!(
        "{}{}{}{}{}{}{} ",
        style("Generate Large DID: target ").color256(34),
        style(format!("{} KB", args.target_kb)).color256(69),
        style(", URL: ").color256(34),
        style(&args.url).color256(69),
        style(", services per doc: ").color256(34),
        style(args.services).color256(69),
        style(")").color256(34),
    );
    println!(
        "\t{}{}",
        style("DID template: ").color256(34),
        style(&did_template).color256(69),
    );

    let mut didwebvh = DIDWebVHState::default();
    let mut secrets = SimpleSecretsResolver::new(&[]).await;

    // Estimate entries needed (we'll keep going until we hit target size)
    // Use a base time far enough in the past to accommodate many entries
    let estimated_entries = (target_bytes / 800).max(1500) as i64;
    let base_time = (Utc::now() - ChronoDuration::seconds(estimated_entries + 10)).fixed_offset();

    // === Generate initial DID ===
    let gen_start = SystemTime::now();

    let (signing_key, next_keys) = generate_keys(&mut secrets).await?;

    let did_document = build_did_document(&did_template, &signing_key, args.services)?;

    let params = Parameters::new()
        .with_portable(true)
        .with_update_keys(vec![signing_key.get_public_keymultibase()?])
        .with_next_key_hashes(vec![
            next_keys[0].get_public_keymultibase_hash()?,
            next_keys[1].get_public_keymultibase_hash()?,
        ])
        .with_ttl(3600)
        .build();

    didwebvh
        .create_log_entry(Some(base_time), &did_document, &params, &signing_key)
        .await?;

    // Get the actual DID (with SCID resolved) for subsequent documents
    let scid = didwebvh.scid();
    let did_id = did_template.replace("{SCID}", scid);

    println!(
        "\t{}{}",
        style("DID created: ").color256(34),
        style(&did_id).color256(69),
    );

    // === Generate updates until we exceed target size ===
    let mut previous_keys = next_keys;
    let mut entry_count: u32 = 1;
    let mut current_size: u64 = estimate_current_size(&didwebvh);

    while current_size < target_bytes {
        entry_count += 1;
        let version_time = base_time + ChronoDuration::seconds(entry_count as i64);

        let (new_next_keys, _) = create_update_entry(
            &mut didwebvh,
            &mut secrets,
            &previous_keys,
            &did_id,
            args.services,
            entry_count,
            version_time,
        )
        .await?;

        previous_keys = new_next_keys;
        current_size = estimate_current_size(&didwebvh);

        if entry_count.is_multiple_of(100) {
            let size = Byte::from_u64(current_size).get_appropriate_unit(UnitType::Decimal);
            println!(
                "\t{}{}{}{:#.2}",
                style("  entries: ").color256(34),
                style(entry_count).color256(69),
                style("  size: ").color256(34),
                style(size).color256(199),
            );
        }
    }

    let gen_end = SystemTime::now();
    let gen_duration_ms = gen_end.duration_since(gen_start).unwrap().as_millis();

    // === Write to disk ===
    let write_start = SystemTime::now();
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("did.jsonl")?;

    let mut byte_count: u64 = 0;
    for entry in didwebvh.log_entries().iter() {
        let json_entry = serde_json::to_string(&entry.log_entry)?;
        file.write_all(json_entry.as_bytes())?;
        file.write_all(b"\n")?;
        byte_count += json_entry.len() as u64 + 1;
    }
    let write_end = SystemTime::now();
    let write_duration_ms = write_end.duration_since(write_start).unwrap().as_millis();

    let file_size = Byte::from_u64(byte_count).get_appropriate_unit(UnitType::Decimal);

    println!();
    println!("{}", style("=== Generation Results ===").color256(214));
    println!(
        "\t{}{} {}{}",
        style("LogEntries: ").color256(34),
        style(entry_count).color256(69),
        style("File size: ").color256(34),
        style(format!("{file_size:#.2}")).color256(199),
    );
    println!(
        "\t{}{}{}{} {}{}",
        style("Generation: ").color256(34),
        style(format!("{gen_duration_ms}ms")).color256(141),
        style("  Write to disk: ").color256(34),
        style(format!("{write_duration_ms}ms")).color256(141),
        style("Total: ").color256(34),
        style(format!("{}ms", gen_duration_ms + write_duration_ms)).color256(141),
    );

    let throughput = if gen_duration_ms + write_duration_ms > 0 {
        (1000.0 / (gen_duration_ms + write_duration_ms) as f64) * entry_count as f64
    } else {
        0.0
    };
    println!(
        "\t{}{}",
        style("Throughput: ").color256(34),
        style(format!("{throughput:.0} entries/sec")).color256(69),
    );

    // === Verify by loading and validating ===
    println!();
    println!("{}", style("=== Verification ===").color256(214),);

    let mut verify_state = DIDWebVHState::default();

    let load_start = SystemTime::now();
    verify_state.load_log_entries_from_file("did.jsonl")?;
    let load_end = SystemTime::now();
    let load_ms = load_end.duration_since(load_start).unwrap().as_millis();
    println!(
        "\t{}{}",
        style("Load from file: ").color256(34),
        style(format!("{load_ms}ms")).color256(141),
    );

    let validate_start = SystemTime::now();
    verify_state.validate()?.assert_complete()?;
    let validate_end = SystemTime::now();
    let validate_ms = validate_end
        .duration_since(validate_start)
        .unwrap()
        .as_millis();
    println!(
        "\t{}{}",
        style("Validation: ").color256(34),
        style(format!("{validate_ms}ms")).color256(141),
    );

    let total_verify_ms = load_ms + validate_ms;
    let verify_throughput = if total_verify_ms > 0 {
        (1000.0 / total_verify_ms as f64) * verify_state.log_entries().len() as f64
    } else {
        0.0
    };
    println!(
        "\t{}{} {}{}",
        style("Total verify: ").color256(34),
        style(format!("{total_verify_ms}ms")).color256(141),
        style("@ ").color256(34),
        style(format!("{verify_throughput:.0} entries/sec")).color256(69),
    );

    println!();
    println!(
        "{}",
        style("All log entries verified successfully!").color256(34),
    );

    Ok(())
}

/// Generate a signing key and two next-rotation keys
async fn generate_keys(secrets: &mut SimpleSecretsResolver) -> Result<(Secret, Vec<Secret>)> {
    let signing_key = generate_did_key(KeyType::Ed25519)?.1;
    secrets.insert(signing_key.clone()).await;

    let next_key1 = generate_did_key(KeyType::Ed25519)?.1;
    secrets.insert(next_key1.clone()).await;
    let next_key2 = generate_did_key(KeyType::Ed25519)?.1;
    secrets.insert(next_key2.clone()).await;

    Ok((signing_key, vec![next_key1, next_key2]))
}

/// Build a DID document with multiple service endpoints to increase size
fn build_did_document(
    did_template: &str,
    signing_key: &Secret,
    num_services: usize,
) -> Result<serde_json::Value> {
    let pk = signing_key.get_public_keymultibase()?;

    let services: Vec<serde_json::Value> = (0..num_services)
        .map(|i| {
            json!({
                "id": format!("{did_template}#service-{i}"),
                "type": "LinkedDomains",
                "serviceEndpoint": format!("https://service-{i}.example.com/api/v1/endpoint")
            })
        })
        .collect();

    Ok(json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": did_template,
        "verificationMethod": [{
            "id": format!("{did_template}#key-0"),
            "type": "Multikey",
            "publicKeyMultibase": pk,
            "controller": did_template
        }],
        "authentication": [format!("{did_template}#key-0")],
        "assertionMethod": [format!("{did_template}#key-0")],
        "service": services
    }))
}

/// Create an update log entry with key rotation
async fn create_update_entry(
    didwebvh: &mut DIDWebVHState,
    secrets: &mut SimpleSecretsResolver,
    previous_keys: &[Secret],
    did_id: &str,
    num_services: usize,
    count: u32,
    version_time: chrono::DateTime<FixedOffset>,
) -> Result<(Vec<Secret>, ())> {
    let old_entry = didwebvh
        .log_entries()
        .last()
        .ok_or_else(|| anyhow!("No previous log entry found"))?;

    let mut new_params = old_entry.validated_parameters.clone();

    // Generate new next keys for pre-rotation
    let next_key1 = generate_did_key(KeyType::Ed25519)?.1;
    secrets.insert(next_key1.clone()).await;
    let next_key2 = generate_did_key(KeyType::Ed25519)?.1;
    secrets.insert(next_key2.clone()).await;

    new_params.next_key_hashes = Some(Arc::new(vec![
        Multibase::new(next_key1.get_public_keymultibase_hash()?),
        Multibase::new(next_key2.get_public_keymultibase_hash()?),
    ]));

    // Rotate update keys to previous next keys
    let update_keys = previous_keys
        .iter()
        .map(|s| Multibase::new(s.get_public_keymultibase().unwrap()))
        .collect();
    new_params.update_keys = Some(Arc::new(update_keys));

    // Build an updated document with varied services to add bulk
    let signing_key = previous_keys
        .first()
        .ok_or_else(|| anyhow!("No signing key available"))?;
    let pk = signing_key.get_public_keymultibase()?;

    let services: Vec<serde_json::Value> = (0..num_services)
        .map(|i| {
            json!({
                "id": format!("{did_id}#service-{i}"),
                "type": "LinkedDomains",
                "serviceEndpoint": format!("https://service-{i}.example.com/api/v{count}/endpoint")
            })
        })
        .collect();

    let new_state = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": did_id,
        "verificationMethod": [{
            "id": format!("{did_id}#key-0"),
            "type": "Multikey",
            "publicKeyMultibase": pk,
            "controller": did_id
        }],
        "authentication": [format!("{did_id}#key-0")],
        "assertionMethod": [format!("{did_id}#key-0")],
        "service": services
    });

    didwebvh
        .create_log_entry(Some(version_time), &new_state, &new_params, signing_key)
        .await?;

    Ok((vec![next_key1, next_key2], ()))
}

/// Estimate the current serialized size of all log entries
fn estimate_current_size(didwebvh: &DIDWebVHState) -> u64 {
    didwebvh
        .log_entries()
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).unwrap().len() as u64 + 1)
        .sum()
}
