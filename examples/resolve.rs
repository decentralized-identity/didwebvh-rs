//! Example: Resolve a did:webvh DID over HTTP(S) and display the document.
//!
//! Fetches the DID's log file, validates all signatures and parameter
//! transitions, and displays the resolved DID Document and metadata.
//!
//! Run with: `cargo run --example resolve -- did:webvh:<scid>:example.com`

use chrono::{TimeDelta, Utc};
use clap::Parser;
use console::style;
use didwebvh_rs::prelude::*;
use didwebvh_rs::resolve::{DEFAULT_MAX_RESPONSE_BYTES, ResolveOptions};
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Resolve a did:webvh DID",
    long_about = "Resolve a did:webvh DID by fetching and verifying its log entries over HTTP(S).\n\n\
        The resolver downloads the DID's did.jsonl (and optionally did-witness.json),\n\
        validates all log entry signatures and parameter transitions, and displays\n\
        the resolved DID Document along with WebVH metadata.\n\n\
        Examples:\n  \
          resolve did:webvh:<scid>:example.com\n  \
          resolve did:webvh:<scid>:example.com%3A8080\n  \
          resolve did:webvh:<scid>:example.com:custom:path\n  \
          resolve did:webvh:<scid>:example.com --max-size-kb 500\n  \
          resolve \"did:webvh:<scid>:example.com?versionId=2-Qm...\""
)]
struct Args {
    /// The DID to resolve (e.g. "did:webvh:<scid>:example.com")
    did: String,

    /// Maximum HTTP response size in KB. Responses larger than this limit are
    /// rejected to prevent memory exhaustion. Applies independently to each
    /// downloaded file (did.jsonl, did-witness.json).
    #[arg(short = 'l', long, default_value_t = DEFAULT_MAX_RESPONSE_BYTES / 1024)]
    max_size_kb: u64,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let options = ResolveOptions {
        max_response_bytes: args.max_size_kb * 1024,
        ..ResolveOptions::default()
    };

    let elapsed = resolve(&args.did, options).await;
    println!();
    println!(
        "{}{}{}",
        style("Time Taken: ").color256(69),
        style(elapsed.num_milliseconds()).color256(141),
        style("ms").color256(69)
    );
}

async fn resolve(did: &str, options: ResolveOptions) -> TimeDelta {
    let max_kb = options.max_response_bytes / 1024;
    println!(
        "{}{}",
        style("Max response size: ").color256(69),
        style(format!("{max_kb} KB")).color256(141),
    );

    let mut webvh = DIDWebVHState::default();
    let start = Utc::now();
    let (log_entry, meta) = match webvh.resolve(did, options).await {
        Ok(res) => res,
        Err(e) => {
            panic!("Error: {e:?}");
        }
    };
    let stop = Utc::now();

    let did_document = match log_entry.get_did_document() {
        Ok(doc) => doc,
        Err(e) => {
            panic!("Error: {e:?}");
        }
    };

    println!(
        "{}\n{}",
        style("DID Document:").color256(69),
        style(serde_json::to_string_pretty(&did_document).unwrap()).color256(34)
    );

    println!();
    println!(
        "{}\n{}",
        style("WebVH Metadata:").color256(69),
        style(serde_json::to_string_pretty(&meta).unwrap()).color256(214)
    );

    stop.signed_duration_since(start)
}
