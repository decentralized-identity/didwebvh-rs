use chrono::{TimeDelta, Utc};
use console::style;
use didwebvh_rs::resolve::DIDWebVH;
use ssi::dids::{DID, DIDResolver};
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

    let did = unsafe { DID::new_unchecked(args[1].as_bytes()) };

    let elapsed = ssi_resolve(did).await;
    println!(
        "{}{}{}",
        style("Time Taken: ").color256(69),
        style(elapsed.num_milliseconds()).color256(141),
        style("ms").color256(69)
    );
}

// Resolves using the SSI Library traits
async fn ssi_resolve(did: &DID) -> TimeDelta {
    let webvh = DIDWebVH;
    let start = Utc::now();
    let output = match webvh.resolve(did).await {
        Ok(res) => res,
        Err(e) => {
            panic!("Error: {e:?}");
        }
    };
    let stop = Utc::now();

    println!(
        "DID Document:\n{}",
        serde_json::to_string_pretty(&output.document).unwrap()
    );
    println!("Metadata: {:?}", output.metadata);

    stop.signed_duration_since(start)
}
