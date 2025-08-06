//! Resolving WebVH DID's logic is handled here

use crate::{
    DIDWebVHError, DIDWebVHState,
    log_entry::{LogEntry, MetaData},
    log_entry_state::{LogEntryState, LogEntryValidationStatus},
    parameters::Parameters,
    url::{URLType, WebVHURL},
    witness::proofs::WitnessProofCollection,
};
use chrono::{DateTime, Utc};
use reqwest::Client;
use std::time::Duration;
use tracing::{Instrument, Level, span, warn};
use url::Url;

/// Integration with the Spruice ID SSI Library
pub mod ssi_resolve;

pub struct DIDWebVH;

impl DIDWebVH {
    // Handles the fetching of the file from a given URL
    async fn download_file(client: Client, url: Url) -> Result<String, DIDWebVHError> {
        client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| DIDWebVHError::NetworkError(format!("url ({url}): {e}")))?
            .text()
            .await
            .map_err(|e| {
                DIDWebVHError::NetworkError(format!("url ({url}): Failed to read response: {e}"))
            })
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
    /// Resolves a webvh DID
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
                // Set network timeout values. Will default to 10 seconds for any reasons
                let network_timeout = if let Some(timeout) = timeout {
                    timeout
                } else {
                    Duration::from_secs(10)
                };

                // Async download did.jsonl and did-witness.json
                let client = reqwest::Client::new();
                let r1 = tokio::time::timeout(
                    network_timeout,
                    tokio::spawn(DIDWebVH::get_log_entries(
                        parsed_did_url.clone(),
                        client.clone(),
                    )),
                );

                let r2 = tokio::time::timeout(
                    network_timeout,
                    tokio::spawn(DIDWebVH::get_witness_proofs(
                        parsed_did_url.clone(),
                        client.clone(),
                    )),
                );

                let (r1, r2) = (r1.await, r2.await);

                // LogEntry

                let log_entries = if let Ok(log_entries) = r1 {
                    match log_entries {
                        Ok(entries) => match entries {
                            Ok(log_entries_text) => {
                                let mut log_entries = Vec::new();
                                let mut version = None;
                                for line in log_entries_text.lines() {
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
                                warn!("Error downloading LogEntries: {e}");
                                return Err(e);
                            }
                        },
                        Err(e) => {
                            warn!("tokio join error: {e}");
                            return Err(DIDWebVHError::NetworkError(format!(
                                "Error downloading LogEntries for DID: {e}"
                            )));
                        }
                    }
                } else {
                    warn!("timeout error on LogEntry download");
                    return Err(DIDWebVHError::NetworkError(
                        "Network timeout on downloaded LogEntries for DID".to_string(),
                    ));
                };

                if log_entries.is_empty() {
                    warn!("No LogEntries found for DID: {did}");
                    return Err(DIDWebVHError::NotFound);
                }

                // If there is any error with witness proofs then set witness proofs to an empty proof
                // WitnessProofCollection
                // If a webvh DID is NOT using witnesses then it will still successfully validate
                let witness_proofs = if let Ok(proofs) = r2 {
                    match proofs {
                        Ok(proofs) => match proofs {
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
                        },
                        Err(e) => {
                            warn!("tokio join error: {e}");
                            WitnessProofCollection::default()
                        }
                    }
                } else {
                    warn!("Downloading witness proofs timedout. Defaulting to no witness proofs");
                    WitnessProofCollection::default()
                };

                // Have LogEntries and Witness Proofs, now can validate the DID
                self.log_entries = log_entries;
                self.witness_proofs = witness_proofs;
                self.validated = false;
                self.expires = DateTime::default();

                self.validate()?;

                // Ensure metadata is set for the DID
                if let Some(first) = self.log_entries.first() {
                    self.scid = first.get_scid().unwrap();
                    self.meta_first_ts = first.get_version_time_string();
                }
                if let Some(last) = self.log_entries.last() {
                    self.meta_last_ts = last.get_version_time_string();
                }
            }

            // DID is fully validated
            if parsed_did_url.query_version_id.is_some()
                || parsed_did_url.query_version_time.is_some()
            {
                match self.get_specific_log_entry(
                    parsed_did_url.query_version_id.as_deref(),
                    parsed_did_url.query_version_time,
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
        .instrument(_span)
        .await
    }
}
