//! Resolving WebVH DID's logic is handled here
//!
//! A WebVH DID can be loaded via HTTP(S) or local file (testing)
//! [`crate::DIDWebVHState::resolve`] Will load a WebVH DID using HTTP(S)
//! [`crate::DIDWebVHState::resolve_file`] Will load a WebVH DID using a local file path
//! [`crate::DIDWebVHState::resolve_state`] Is an internal function that will validate the DID return
//! the resolved result

use crate::{
    DIDWebVHError, DIDWebVHState,
    log_entry::{LogEntry, MetaData},
    log_entry_state::{LogEntryState, LogEntryValidationStatus},
    parameters::Parameters,
    url::{URLType, WebVHURL},
    witness::proofs::WitnessProofCollection,
};
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode};
use std::time::Duration;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use tracing::trace;
use tracing::{Instrument, Level, span, warn};
use url::Url;

/// Integration with the Spruice ID SSI Library
#[cfg(feature = "ssi")]
pub mod ssi_resolve;

pub mod implicit; // WebVH specification implies specific Services for a DID Document

pub struct DIDWebVH;

impl DIDWebVH {
    // Handles the fetching of the file from a given URL
    async fn download_file(client: Client, url: Url) -> Result<String, DIDWebVHError> {
        let response = client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| DIDWebVHError::NetworkError(format!("url ({url}): {e}")))?;

        if response.status() == StatusCode::OK {
            response.text().await.map_err(|e| {
                DIDWebVHError::NetworkError(format!("url ({url}): Failed to read response: {e}"))
            })
        } else {
            warn!("url ({url}): HTTP Status code = {}", response.status());
            Err(DIDWebVHError::NetworkError(format!(
                "url ({url}): HTTP Status code = {}",
                response.status()
            )))
        }
    }

    /// Handles all processing and fetching for LogEntry file
    async fn get_log_entries(url: WebVHURL, client: Client) -> Result<String, DIDWebVHError> {
        let log_entries_url = match url.get_http_url(Some("did.jsonl")) {
            Ok(url) => url,
            Err(e) => {
                warn!("Invalid URL for DID: {e}");
                return Err(DIDWebVHError::InvalidMethodIdentifier(format!(
                    "Couldn't generate a valid URL from the DID: {e}"
                )));
            }
        };

        Self::download_file(client, log_entries_url).await
    }

    /// Handles all processing and fetching for witness proofs
    async fn get_witness_proofs(url: WebVHURL, client: Client) -> Result<String, DIDWebVHError> {
        let witness_url = match url.get_http_url(Some("did-witness.json")) {
            Ok(url) => url,
            Err(e) => {
                warn!("Invalid URL for DID: {e}");
                return Err(DIDWebVHError::InvalidMethodIdentifier(format!(
                    "Couldn't generate a valid URL from the DID: {e}"
                )));
            }
        };

        Self::download_file(client, witness_url).await
    }
}

impl DIDWebVHState {
    /// Load a WebVH DID from a local file (useful for testing)
    /// did: DID to resolve (can use query parameters here)
    /// log_entries_path: path to the did.jsonl file
    /// witness_proofs_file: optional path to the did-witness.json file
    pub async fn resolve_file(
        &mut self,
        did: &str,
        log_entries_path: &str,
        witness_proofs_file: Option<&str>,
    ) -> Result<(&LogEntry, MetaData), DIDWebVHError> {
        let _span = span!(Level::DEBUG, "resolve_file", PATH = log_entries_path);
        async move {
            let parsed_did_url = WebVHURL::parse_did_url(did)?;

            // Load log entries from file
            self.load_log_entries_from_file(log_entries_path)?;

            // Load witness proofs from file if provided
            if let Some(witness_path) = witness_proofs_file {
                self.load_witness_proofs_from_file(witness_path);
            } else {
                self.witness_proofs = WitnessProofCollection::default();
            }

            // Have LogEntries and Witness Proofs, now can validate the DID
            self.validated = false;
            self.expires = DateTime::default();

            self.resolve_state(&parsed_did_url)
        }
        .instrument(_span)
        .await
    }

    /// Resolves a webvh DID fetched using HTTP(S)
    ///
    /// Inputs:
    /// did: DID to resolve
    /// timeout: how many seconds (Default: 10) before timing out on network operations
    pub async fn resolve(
        &mut self,
        did: &str,
        timeout: Option<Duration>,
    ) -> Result<(&LogEntry, MetaData), DIDWebVHError> {
        let _span = span!(Level::DEBUG, "resolve", DID = did);
        async move {
            let parsed_did_url = WebVHURL::parse_did_url(did)?;

            if parsed_did_url.type_ == URLType::WhoIs {
                // TODO: whois is not implemented yet
                return Err(DIDWebVHError::NotImplemented(
                    "/whois isn't implemented yet".to_string(),
                ));
            }

            if !self.validated || self.expires < Utc::now() {
                // If building for WASM then don't use tokio::spawn
                // This means sequential retrieval of files
                #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
                let (r1, r2) = {
                    trace!("timeout is not available in WASM builds! {timeout:#?}");
                    let client = reqwest::Client::new();

                    let r1 = DIDWebVH::get_log_entries(parsed_did_url.clone(), client.clone());
                    let r2 = DIDWebVH::get_witness_proofs(parsed_did_url.clone(), client.clone());
                    (r1.await, r2.await)
                };

                // Otherwise use tokio::spawn to do async downloads
                #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
                let (r1, r2) = {
                    // Set network timeout values. Will default to 10 seconds for any reasons
                    let network_timeout = if let Some(timeout) = timeout {
                        timeout
                    } else {
                        Duration::from_secs(10)
                    };

                    // Async download did.jsonl and did-witness.json
                    let client = reqwest::ClientBuilder::new()
                        .timeout(network_timeout)
                        .build()
                        .unwrap();
                    let r1 = tokio::spawn(DIDWebVH::get_log_entries(
                        parsed_did_url.clone(),
                        client.clone(),
                    ));

                    let r2 = tokio::spawn(DIDWebVH::get_witness_proofs(
                        parsed_did_url.clone(),
                        client.clone(),
                    ));

                    let r1 = match r1.await {
                        Ok(log_entries) => log_entries,
                        Err(e) => {
                            return Err(DIDWebVHError::NetworkError(format!(
                                "Error downloading LogEntries for DID: {e}"
                            )));
                        }
                    };

                    let r2 = match r2.await {
                        Ok(witness_proofs) => witness_proofs,
                        Err(_) => Ok("{}".to_string()),
                    };
                    (r1, r2)
                };

                // LogEntry
                let log_entries = match r1 {
                    Ok(entries) => {
                        let mut log_entries = Vec::new();
                        let mut version = None;
                        for line in entries.lines() {
                            let log_entry = LogEntry::deserialize_string(line, version)?;

                            version = Some(log_entry.get_webvh_version());

                            log_entries.push(LogEntryState {
                                log_entry: log_entry.clone(),
                                version_number: log_entry.get_version_id_fields()?.0,
                                validation_status: LogEntryValidationStatus::NotValidated,
                                validated_parameters: Parameters::default(),
                            });
                        }
                        log_entries
                    }
                    Err(e) => {
                        return Err(DIDWebVHError::NetworkError(format!(
                            "Error downloading LogEntries for DID: {e}"
                        )));
                    }
                };

                if log_entries.is_empty() {
                    warn!("No LogEntries found for DID: {did}");
                    return Err(DIDWebVHError::NotFound);
                }

                // If there is any error with witness proofs then set witness proofs to an empty proof
                // WitnessProofCollection
                // If a webvh DID is NOT using witnesses then it will still successfully validate
                let witness_proofs = match r2 {
                    Ok(proofs_string) => WitnessProofCollection {
                        proofs: serde_json::from_str(&proofs_string).map_err(|e| {
                            DIDWebVHError::WitnessProofError(format!(
                                "Couldn't deserialize Witness Proofs Data: {e}",
                            ))
                        })?,
                        ..Default::default()
                    },
                    Err(e) => {
                        warn!("Error downloading witness proofs: {e}");
                        WitnessProofCollection::default()
                    }
                };

                // Have LogEntries and Witness Proofs, now can validate the DID
                self.log_entries = log_entries;
                self.witness_proofs = witness_proofs;
                self.validated = false;
                self.expires = DateTime::default();
            }

            self.resolve_state(&parsed_did_url)
        }
        .instrument(_span)
        .await
    }

    fn resolve_state(
        &mut self,
        parsed_did_url: &WebVHURL,
    ) -> Result<(&LogEntry, MetaData), DIDWebVHError> {
        let _span = span!(Level::DEBUG, "resolve_state").entered();
        self.validate()?;

        // Ensure metadata is set for the DID
        if let Some(first) = self.log_entries.first() {
            self.scid = first.get_scid().unwrap();
            self.meta_first_ts = first.get_version_time_string();
        }
        if let Some(last) = self.log_entries.last() {
            self.meta_last_ts = last.get_version_time_string();
        }

        // DID is fully validated
        if parsed_did_url.query_version_id.is_some()
            || parsed_did_url.query_version_time.is_some()
            || parsed_did_url.query_version_number.is_some()
        {
            match self.get_specific_log_entry(
                parsed_did_url.query_version_id.as_deref(),
                parsed_did_url.query_version_time,
                parsed_did_url.query_version_number,
            ) {
                Ok(entry) => {
                    let metadata = self.generate_meta_data(entry);
                    Ok((&entry.log_entry, metadata))
                }
                Err(_) => Err(DIDWebVHError::NotFound),
            }
        } else if let Some(last) = self.log_entries.last() {
            let metadata = self.generate_meta_data(last);
            Ok((&last.log_entry, metadata))
        } else {
            Err(DIDWebVHError::NotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::DIDWebVHState;

    #[tokio::test]
    async fn resolve_reference() {
        let mut webvh = DIDWebVHState::default();

        let result = webvh.resolve(
            "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs",
            None,
        ).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn resolve_reference_specific_version() {
        let mut webvh = DIDWebVHState::default();

        let result = webvh.resolve(
            "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs?versionId=2-QmUCFFYYGBJhzZqyouAtvRJ7ULdd8FqSUvwb61FPTMH1Aj",
            None,
        ).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn resolve_reference_specific_time() {
        let mut webvh = DIDWebVHState::default();

        let result = webvh.resolve(
            "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs?versionTime=2025-08-01T00:00:00Z",
            None,
        ).await;

        assert!(result.is_ok());
    }
}
