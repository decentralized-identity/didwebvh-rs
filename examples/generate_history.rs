//! Generate a large WebVH DID
//!
//! Test different complex larger history DIDs
//!
//! Example:
//! Model an business DID with the following characteristics
//! 1. Must be used for 10 years
//! 2. They rotate webVH keys every month (two keys per update)
//! 3. They swap a witness node once every 6 months (maintaining 3 threashold, 4 witnesses)
//! 4. They swap a watcher node once every 6 months (maintaining 3 watchers)

use affinidi_data_integrity::DataIntegrityProof;
use affinidi_secrets_resolver::{SecretsResolver, SimpleSecretsResolver, secrets::Secret};
use affinidi_tdk::dids::{DID, KeyType};
use anyhow::{Result, anyhow, bail};
use byte_unit::{Byte, UnitType};
use chrono::{DateTime, Duration as ChronoDuration, FixedOffset, Utc};
use clap::Parser;
use console::style;
use didwebvh_rs::{
    DIDWebVHState,
    parameters::Parameters,
    witness::{Witness, Witnesses},
};
use format_num::format_num;
use rand::{RngExt, distr::Alphabetic};
use serde_json::json;
use std::{
    fs::OpenOptions,
    io::Write,
    sync::Arc,
    thread::sleep,
    time::{Duration, SystemTime},
};
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Number of LogEntries to generate (default: 120)
    #[arg(short, long, default_value_t = 120)]
    count: u32,

    /// Enables Witnesses with a given threshold (set to 0 to disable)
    #[arg(short, long, default_value_t = 3)]
    witnesses: u32,

    /// Enables Interactive mode (user presses enter to proceed to next step)
    #[arg(short, long)]
    interactive: bool,
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let args: Args = Args::parse();

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let mut didwebvh = DIDWebVHState::default();
    let mut secrets = SimpleSecretsResolver::new(&[]).await;

    println!(
        "{}{}{}{}{}",
        style("Generate History: LogEntries (").color256(34),
        style(args.count).color256(69),
        style(") Witnesses (").color256(34),
        style(args.witnesses).color256(69),
        style(")").color256(34),
    );

    if args.interactive {
        print!(
            "{}",
            style("Interactive mode enabled - press ENTER to proceed to each step").color256(214)
        );
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        println!();
    } else {
        println!(
            "{}",
            style("System rest - Sleeping for 3 seconds...").color256(214)
        );
        sleep(Duration::from_secs(3));
    }

    println!(
        "{}",
        style("Generating complete WebVH DID with history...").color256(214),
    );
    let start = SystemTime::now();

    // Use a fixed start date in the past with 1-second increments to ensure
    // each versionTime is strictly greater than the previous (required by spec)
    let base_time: DateTime<FixedOffset> =
        (Utc::now() - ChronoDuration::seconds(args.count as i64 + 10)).fixed_offset();

    // Generate initial DID
    let mut next = generate_did(&mut didwebvh, &mut secrets, &args, base_time).await?;

    // Loop for count months (first entry represents the first month)
    for i in 2..(args.count + 1) {
        let version_time = base_time + ChronoDuration::seconds(i as i64);
        next =
            create_log_entry(&mut didwebvh, &mut secrets, &next, i, &args, version_time).await?;
    }

    let end = SystemTime::now();
    let webvh_generate_duration = end.duration_since(start).unwrap().as_millis();

    // Write records to disk
    let start = SystemTime::now();
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("did.jsonl")?;

    let mut byte_count: u64 = 0;
    for entry in didwebvh.log_entries.iter() {
        // Convert LogEntry to JSON and write to file
        let json_entry = serde_json::to_string(&entry.log_entry)?;
        file.write_all(json_entry.as_bytes())?;
        file.write_all("\n".as_bytes())?;
        byte_count += 2 + json_entry.len() as u64; // 2 for newline characters
    }
    let end = SystemTime::now();
    let webvh_le_save_duration = end.duration_since(start).unwrap().as_millis();

    let bytes = Byte::from_u64(byte_count).get_appropriate_unit(UnitType::Decimal);

    println!(
        "\t{}{}",
        style("DID First LogEntry created: ").color256(34),
        style(&didwebvh.log_entries.first().unwrap().get_version_id()).color256(69)
    );
    println!(
        "\t{}{}",
        style("DID Last LogEntry created: ").color256(34),
        style(&didwebvh.log_entries.last().unwrap().get_version_id()).color256(69)
    );

    println!(
        "\t{}{} {}{}",
        style("LogEntries Count: ").color256(34),
        style(format_num!(",.0", didwebvh.log_entries.len() as f64)).color256(69),
        style("File Size (bytes): ").color256(34),
        style(format!("{bytes:#.2}")).color256(199),
    );

    let throughput = (1000.0 / (webvh_generate_duration + webvh_le_save_duration) as f64)
        * didwebvh.log_entries.len() as f64;

    let throughput = format_num!(",.02", throughput);

    println!(
        "\t{}{}{}{}\n\t{}{}{}{}{}",
        style("Timing: Generating WebVH: ").color256(34),
        style(format!("{webvh_generate_duration}ms",)).color256(141),
        style(", save to disk: ").color256(34),
        style(format!("{webvh_le_save_duration}ms",)).color256(141),
        style("Total Time: ").color256(34),
        style(format!(
            "{}ms",
            webvh_generate_duration + webvh_le_save_duration
        ))
        .color256(141),
        style(" @ ").color256(34),
        style(throughput).color256(69),
        style(" LogEntries/Second").color256(34),
    );

    if args.witnesses > 0 {
        println!();
        println!(
            "\t{}{}",
            style("Witnesses enabled with threshold: ").color256(34),
            style(args.witnesses).color256(69)
        );
        let start = SystemTime::now();
        // Witness proofs
        didwebvh.witness_proofs.write_optimise_records()?;
        let bytes = didwebvh.witness_proofs.save_to_file("did-witness.json")?;
        let end = SystemTime::now();
        let bytes = Byte::from_u64(bytes as u64).get_appropriate_unit(UnitType::Decimal);

        println!(
            "\t{}{} {}{}",
            style("Witness Proof Count: ").color256(34),
            style(didwebvh.witness_proofs.get_total_count().to_string()).color256(69),
            style("File Size (bytes): ").color256(34),
            style(format!("{bytes:#.2}")).color256(199),
        );
        println!(
            "\t{}{}",
            style("WebVH DID Witness-Proofs Save Duration: ").color256(34),
            style(format!(
                "{}ms",
                &end.duration_since(start).unwrap().as_millis()
            ))
            .color256(141)
        );
    }

    println!();
    println!(
        "{}",
        style("Resetting state... ready for verification").color256(214)
    );

    let mut verify_state = DIDWebVHState::default();
    if args.interactive {
        print!(
            "{}",
            style("Press ENTER to proceed to verifying this WebVH DID").color256(214)
        );
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        println!();
    } else {
        println!(
            "{}",
            style("System rest - Sleeping for 3 seconds...").color256(214)
        );
        sleep(Duration::from_secs(3));
    }

    let start = SystemTime::now();
    verify_state.load_log_entries_from_file("did.jsonl")?;
    let end = SystemTime::now();

    let throughput = (1000.0 / end.duration_since(start).unwrap().as_millis() as f64)
        * verify_state.log_entries.len() as f64;

    let throughput = format_num!(",.02", throughput);

    println!("{}", style("Reading data - no validation").color256(214));
    println!(
        "\t{}{} {} {}{}",
        style("Reading LogEntries from file Duration: ").color256(34),
        style(format!(
            "{}ms",
            end.duration_since(start).unwrap().as_millis()
        ))
        .color256(141),
        style("@").color256(34),
        style(throughput).color256(69),
        style(" LogEntries/Second throughput").color256(34),
    );
    let mut total_validation = end.duration_since(start).unwrap().as_millis();

    if !args.interactive {
        println!("{}", style("Sleeping for 3 seconds...").color256(214));
        sleep(Duration::from_secs(3));
    }

    let start2 = SystemTime::now();
    verify_state.load_witness_proofs_from_file("did-witness.json");
    let end = SystemTime::now();

    let throughput = (1000.0 / end.duration_since(start2).unwrap().as_millis() as f64)
        * verify_state.witness_proofs.get_total_count() as f64;
    let throughput = format_num!(",.02", throughput);

    println!(
        "\t{}{} {} {}{}",
        style("Reading Witness-Proofs from file Duration: ").color256(34),
        style(format!(
            "{}ms",
            end.duration_since(start2).unwrap().as_millis()
        ))
        .color256(141),
        style("@").color256(34),
        style(throughput).color256(69),
        style(" Witness-Proofs/Second throughput").color256(34),
    );

    total_validation += end.duration_since(start2).unwrap().as_millis();

    if !args.interactive {
        println!("{}", style("Sleeping for 3 seconds...").color256(214));
        sleep(Duration::from_secs(3));
    }

    let start3 = SystemTime::now();
    verify_state.validate()?;
    let end = SystemTime::now();

    println!();
    println!("{}", style("Validating history...").color256(214));
    println!(
        "\t{}{}",
        style("WebVH DID History Validation Duration: ").color256(34),
        style(format!(
            "{}ms",
            end.duration_since(start3).unwrap().as_millis()
        ))
        .color256(141)
    );
    total_validation += end.duration_since(start3).unwrap().as_millis();

    let throughput = (1000.0 / total_validation as f64) * verify_state.log_entries.len() as f64;
    let throughput = format_num!(",.02", throughput);
    println!();
    println!(
        "{}{} {} {}{}",
        style("Total Validation including data load: ").color256(34),
        style(format!("{total_validation}ms")).color256(141),
        style("@").color256(34),
        style(throughput).color256(69),
        style(" Entries/Second throughput").color256(34),
    );

    Ok(())
}

async fn generate_did(
    didwebvh: &mut DIDWebVHState,
    secrets: &mut SimpleSecretsResolver,
    args: &Args,
    version_time: DateTime<FixedOffset>,
) -> Result<Vec<Secret>> {
    let raw_did = r#"{
    "@context": [
        "https://www.w3.org/ns/did/v1"
    ],
    "assertionMethod": [
        "did:webvh:{SCID}:test.affinidi.com#key-0"
    ],
    "authentication": [
        "did:webvh:{SCID}:test.affinidi.com#key-0"
    ],
    "id": "did:webvh:{SCID}:test.affinidi.com",
    "service": [
        {
        "id": "did:webvh:{SCID}:test.affinidi.com#service-0",
        "serviceEndpoint": [
            {
            "accept": [
                "didcomm/v2"
            ],
            "routingKeys": [],
            "uri": "http://mediator.affinidi.com:/api"
            }
        ],
        "type": "DIDCommMessaging"
        }
    ],
    "verificationMethod": [
        {
        "controller": "did:webvh:{SCID}:test.affinidi.com",
        "id": "did:webvh:{SCID}:test.affinidi.com#key-0",
        "publicKeyMultibase": "test1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "type": "Multikey"
        }
    ]
    }"#;

    let did_document = serde_json::from_str::<serde_json::Value>(raw_did).unwrap();

    // ***** Generate Parameters *****

    // Generate updateKey for first log entry
    let signing_did1_secret = DID::generate_did_key(affinidi_tdk::dids::KeyType::Ed25519)?.1;
    secrets.insert(signing_did1_secret.clone()).await;

    // Generate next_key_hashes
    let next_key1 = DID::generate_did_key(KeyType::Ed25519)?.1;
    secrets.insert(next_key1.clone()).await;
    let next_key2 = DID::generate_did_key(KeyType::Ed25519)?.1;
    secrets.insert(next_key2.clone()).await;

    // Generate witnesses
    let witness = if args.witnesses > 0 {
        let mut witness_nodes = Vec::new();

        for _ in 0..args.witnesses {
            let (w_did, w_secret) = DID::generate_did_key(KeyType::Ed25519)?;
            secrets.insert(w_secret.clone()).await;
            witness_nodes.push(Witness { id: w_did });
        }

        Some(Witnesses::Value {
            threshold: args.witnesses,
            witnesses: witness_nodes,
        })
    } else {
        None
    };

    let params = Parameters::new()
        .with_portable(true)
        .with_update_keys(vec![signing_did1_secret.get_public_keymultibase()?])
        .with_next_key_hashes(vec![
            next_key1.get_public_keymultibase_hash()?,
            next_key2.get_public_keymultibase_hash()?,
        ])
        .with_witnesses(witness.unwrap())
        .with_watchers(vec![
            "https://watcher-1.affinidi.com/v1/webvh".to_string(),
            "https://watcher-2.affinidi.com/v1/webvh".to_string(),
            "https://watcher-3.affinidi.com/v1/webvh".to_string(),
        ])
        .with_ttl(3600)
        .build();

    let _ = didwebvh.create_log_entry(
        Some(version_time),
        &did_document,
        &params,
        &secrets.get_secret(&signing_did1_secret.id).await.unwrap(),
    )?;

    // Witness LogEntry
    witness_log_entry(didwebvh, secrets).await?;

    Ok(vec![next_key1, next_key2])
}

async fn witness_log_entry(
    didwebvh: &mut DIDWebVHState,
    secrets: &SimpleSecretsResolver,
) -> Result<()> {
    let log_entry = didwebvh
        .log_entries
        .last()
        .ok_or_else(|| anyhow!("Couldn't find a LogEntry to witness"))?;

    let Some(witnesses) = &log_entry.get_active_witnesses() else {
        println!(
            "{}",
            style("Witnesses are not being used for this LogEntry. No witnessing is required")
                .color256(69)
        );
        return Ok(());
    };

    let Some(witness_nodes) = witnesses.witnesses() else {
        bail!("No witness nodes found!");
    };

    for witness in witness_nodes {
        let key = witness.id.split_at(8);
        // Get secret for Witness
        let Some(secret) = secrets
            .get_secret(&[&witness.id, "#", key.1].concat())
            .await
        else {
            bail!("Couldn't find secret for witness ({})!", witness.id)
        };

        // Generate Signature
        let proof = DataIntegrityProof::sign_jcs_data(
            &json!({"versionId": &log_entry.get_version_id()}),
            None,
            &secret,
            None,
        )
        .map_err(|e| {
            anyhow!("Couldn't generate Data Integrity Proof for LogEntry. Reason: {e}",)
        })?;

        // Save proof to collection
        didwebvh
            .witness_proofs
            .add_proof(&log_entry.get_version_id(), &proof, false)
            .map_err(|e| anyhow!("Error adding proof: {e}"))?;
    }

    Ok(())
}

async fn create_log_entry(
    didwebvh: &mut DIDWebVHState,
    secrets: &mut SimpleSecretsResolver,
    previous_keys: &[Secret],
    count: u32,
    args: &Args,
    version_time: DateTime<FixedOffset>,
) -> Result<Vec<Secret>> {
    let old_log_entry = didwebvh
        .log_entries
        .last()
        .ok_or_else(|| anyhow!("No previous log entry found. Please generate a DID first."))?;
    let new_state = old_log_entry.get_state().clone();

    let mut new_params = old_log_entry.validated_parameters.clone();

    // Generate next_key_hashes
    let next_key1 = DID::generate_did_key(KeyType::Ed25519)?.1;
    secrets.insert(next_key1.clone()).await;
    let next_key2 = DID::generate_did_key(KeyType::Ed25519)?.1;
    secrets.insert(next_key2.clone()).await;

    new_params.next_key_hashes = Some(Arc::new(vec![
        next_key1.get_public_keymultibase_hash()?,
        next_key2.get_public_keymultibase_hash()?,
    ]));

    // Modify update_key for this entry
    let update_keys = previous_keys
        .iter()
        .map(|s| s.get_public_keymultibase().unwrap())
        .collect();
    new_params.update_keys = Some(Arc::new(update_keys));

    // Swap a witness node?
    if args.witnesses > 0 && count % 6 == 3 {
        swap_witness(&mut new_params, secrets).await?;
    }

    // Swap a watcher node?
    if count.is_multiple_of(6) {
        swap_watcher(&mut new_params)?;
    }

    let _ = didwebvh.create_log_entry(
        Some(version_time),
        &new_state,
        &new_params,
        previous_keys
            .first()
            .ok_or_else(|| anyhow!("No next key provided for log entry creation"))?,
    )?;

    // Witness LogEntry
    witness_log_entry(didwebvh, secrets).await?;

    Ok(vec![next_key1, next_key2])
}

async fn swap_witness(params: &mut Parameters, secrets: &mut SimpleSecretsResolver) -> Result<()> {
    // Pick a random witness and remove it
    let mut rng = rand::rng();

    let Some(witnesses) = &params.witness else {
        bail!("Witnesses incorrectly configured for this test!");
    };

    let (threshold, mut new_witnesses) = match &**witnesses {
        Witnesses::Value {
            threshold,
            witnesses,
        } => (threshold, witnesses.clone()),
        _ => bail!("Witnesses incorrectly configured for this test!"),
    };

    let rn = rng.random_range(0..new_witnesses.len());

    // remove random witness
    new_witnesses.remove(rn);

    let (new_witness_did, secret) = DID::generate_did_key(KeyType::Ed25519)?;
    secrets.insert(secret.clone()).await;

    new_witnesses.push(Witness {
        id: new_witness_did,
    });

    params.witness = Some(Arc::new(Witnesses::Value {
        threshold: threshold.to_owned(),
        witnesses: new_witnesses,
    }));

    Ok(())
}

/// Removes a random watcher and adds a new one
fn swap_watcher(params: &mut Parameters) -> Result<()> {
    // Instantiate RNG
    let mut rng = rand::rng();

    let mut watchers = if let Some(watchers) = params.watchers.as_deref() {
        watchers.to_owned()
    } else {
        bail!("Watchers incorrectly configured for this test!");
    };

    // remove a random watcher
    watchers.remove(rng.random_range(0..watchers.len()));

    // Generate random watcher ID for new watcher
    let new_watcher_id: String = rng
        .sample_iter(&Alphabetic)
        .take(4)
        .map(char::from)
        .collect();

    watchers.push(
        [
            "https://watcher-",
            &new_watcher_id,
            ".affinidi.com/v1/webvh",
        ]
        .concat(),
    );

    Ok(())
}
