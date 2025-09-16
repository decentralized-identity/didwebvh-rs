use chrono::{TimeDelta, Utc};
use console::style;
use didwebvh_rs::{DIDWebVHState, log_entry::LogEntryMethods};
use std::env;
use tracing_subscriber::filter;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // First argument is the command executed, second is the DID to parse
    if args.len() != 2 {
        eprintln!("Usage: {} <did:webvh>", args[0]);
        std::process::exit(1);
    }

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let elapsed = resolve(&args[1]).await;
    println!();
    println!(
        "{}{}{}",
        style("Time Taken: ").color256(69),
        style(elapsed.num_milliseconds()).color256(141),
        style("ms").color256(69)
    );
}

async fn resolve(did: &str) -> TimeDelta {
    let mut webvh = DIDWebVHState::default();
    let start = Utc::now();
    let (log_entry, meta) = match webvh.resolve(did, None).await {
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
