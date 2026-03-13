//! Resolving WebVH DID's logic is handled here
//!
//! A WebVH DID can be loaded via HTTP(S) or local file (testing)
//! [`crate::DIDWebVHState::resolve`] Will load a WebVH DID using HTTP(S)
//! [`crate::DIDWebVHState::resolve_file`] Will load a WebVH DID using a local file path
//! `resolve_state` is an internal function that will validate the DID and return
//! the resolved result

use crate::{
    DIDWebVHError, DIDWebVHState,
    log_entry::{LogEntry, MetaData},
    url::WebVHURL,
    witness::proofs::WitnessProofCollection,
};
#[cfg(feature = "network")]
use crate::{
    log_entry::LogEntryMethods,
    log_entry_state::{LogEntryState, LogEntryValidationStatus},
    parameters::Parameters,
    url::URLType,
};
use chrono::DateTime;
#[cfg(feature = "network")]
use chrono::Utc;
#[cfg(feature = "network")]
use reqwest::{Client, StatusCode};
#[cfg(feature = "network")]
use std::time::Duration;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use tracing::trace;
#[cfg(feature = "network")]
use tracing::warn;
use tracing::{Instrument, Level, span};
#[cfg(feature = "network")]
use url::Url;

/// Integration with the Spruice ID SSI Library
#[cfg(feature = "ssi")]
pub mod ssi_resolve;

pub mod implicit; // WebVH specification implies specific Services for a DID Document

/// HTTP client helpers for fetching DID log entries and witness proofs.
#[cfg(feature = "network")]
pub struct DIDWebVH;

#[cfg(feature = "network")]
impl DIDWebVH {
    // Handles the fetching of the file from a given URL
    async fn download_file(client: Client, url: Url) -> Result<String, DIDWebVHError> {
        let url_str = url.to_string();
        let response =
            client
                .get(url.clone())
                .send()
                .await
                .map_err(|e| DIDWebVHError::NetworkError {
                    url: url_str.clone(),
                    status_code: None,
                    message: format!("Request failed: {e}"),
                })?;

        if response.status() == StatusCode::OK {
            response
                .text()
                .await
                .map_err(|e| DIDWebVHError::NetworkError {
                    url: url_str,
                    status_code: Some(200),
                    message: format!("Failed to read response body: {e}"),
                })
        } else {
            let status = response.status().as_u16();
            warn!("url ({url_str}): HTTP Status code = {status}");
            Err(DIDWebVHError::NetworkError {
                url: url_str,
                status_code: Some(status),
                message: format!("HTTP {status}"),
            })
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

    /// Like [`resolve_file()`](Self::resolve_file), but returns owned (cloned) values
    /// so the caller does not borrow `self`.
    pub async fn resolve_file_owned(
        &mut self,
        did: &str,
        log_entries_path: &str,
        witness_proofs_file: Option<&str>,
    ) -> Result<(LogEntry, MetaData), DIDWebVHError> {
        let (entry, metadata) = self
            .resolve_file(did, log_entries_path, witness_proofs_file)
            .await?;
        Ok((entry.clone(), metadata))
    }
}

#[cfg(feature = "network")]
impl DIDWebVHState {
    /// Parse raw log entry lines into a vec of `LogEntryState`
    fn parse_log_entries(raw: &str) -> Result<Vec<LogEntryState>, DIDWebVHError> {
        let mut log_entries = Vec::new();
        let mut version = None;
        for line in raw.lines() {
            let log_entry = LogEntry::deserialize_string(line, version)?;
            version = Some(log_entry.get_webvh_version());
            log_entries.push(LogEntryState {
                log_entry: log_entry.clone(),
                version_number: log_entry.get_version_id_fields()?.0,
                validation_status: LogEntryValidationStatus::NotValidated,
                validated_parameters: Parameters::default(),
            });
        }
        Ok(log_entries)
    }

    /// Check whether any log entry has a non-empty witness parameter
    fn needs_witness_proofs(log_entries: &[LogEntryState]) -> bool {
        log_entries.iter().any(|e| {
            e.log_entry
                .get_parameters()
                .witness
                .as_ref()
                .is_some_and(|w| !w.is_empty())
        })
    }

    /// Parse a raw witness proofs string into a `WitnessProofCollection`
    fn parse_witness_proofs(raw: &str) -> Result<WitnessProofCollection, DIDWebVHError> {
        Ok(WitnessProofCollection {
            proofs: serde_json::from_str(raw).map_err(|e| {
                DIDWebVHError::WitnessProofError(format!(
                    "Couldn't deserialize Witness Proofs Data: {e}",
                ))
            })?,
            ..Default::default()
        })
    }

    /// Validate that parsed log entries are non-empty, returning a contextual error.
    fn validate_log_entries(log_entries: &[LogEntryState], did: &str) -> Result<(), DIDWebVHError> {
        if log_entries.is_empty() {
            warn!("No LogEntries found for DID: {did}");
            return Err(DIDWebVHError::NotFound(format!(
                "No LogEntries found for DID: {did}",
            )));
        }
        Ok(())
    }

    /// Resolve witness proofs from a download result, applying the
    /// "witnesses configured but download failed" policy.
    fn resolve_witness_proofs(
        raw_result: Result<String, DIDWebVHError>,
        needs_witnesses: bool,
    ) -> Result<WitnessProofCollection, DIDWebVHError> {
        match raw_result {
            Ok(raw) => Self::parse_witness_proofs(&raw),
            Err(e) => {
                if needs_witnesses {
                    Err(DIDWebVHError::WitnessProofError(format!(
                        "Witnesses are configured but witness proofs could not be downloaded: {e}"
                    )))
                } else {
                    Ok(WitnessProofCollection::default())
                }
            }
        }
    }

    /// Resolves a `did:webvh` DID by fetching its log entries and witness proofs over HTTP(S).
    ///
    /// Downloads `did.jsonl`, parses and validates all log entries, verifies witness
    /// proofs against configured thresholds, and returns the resolved [`LogEntry`] with
    /// [`MetaData`]. Results are cached until `self.expires`; subsequent calls reuse
    /// the cached state unless expired.
    ///
    /// # Arguments
    /// * `did` — The DID to resolve (may include query parameters like `?versionId=...`).
    /// * `timeout` — Network timeout (default: 10 seconds).
    /// * `eager_witness_download` — If `true`, download `did.jsonl` and `did-witness.json`
    ///   concurrently (faster when witnesses are expected). If `false` (recommended default),
    ///   download `did.jsonl` first, then only fetch `did-witness.json` when the log entries
    ///   actually configure witnesses.
    pub async fn resolve(
        &mut self,
        did: &str,
        timeout: Option<Duration>,
        eager_witness_download: bool,
    ) -> Result<(&LogEntry, MetaData), DIDWebVHError> {
        let _span = span!(Level::DEBUG, "resolve", DID = did);
        async move {
            let parsed_did_url = WebVHURL::parse_did_url(did)?;

            if parsed_did_url.type_ == URLType::WhoIs {
                return Err(DIDWebVHError::NotImplemented(
                    "Resolving /whois URLs is not yet supported. Use the DID's #whois service endpoint directly.".to_string(),
                ));
            }

            if !self.validated || self.expires < Utc::now() {
                // If building for WASM then don't use tokio::spawn
                // This means sequential retrieval of files
                #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
                let (log_entries, witness_proofs) = {
                    trace!("timeout is not available in WASM builds! {timeout:#?}");
                    let client = reqwest::Client::new();

                    let raw_entries =
                        DIDWebVH::get_log_entries(parsed_did_url.clone(), client.clone()).await?;
                    let log_entries = Self::parse_log_entries(&raw_entries)?;
                    Self::validate_log_entries(&log_entries, did)?;

                    let needs_witnesses = Self::needs_witness_proofs(&log_entries);
                    let witness_proofs = if eager_witness_download || needs_witnesses {
                        let raw_result =
                            DIDWebVH::get_witness_proofs(parsed_did_url.clone(), client.clone())
                                .await;
                        Self::resolve_witness_proofs(raw_result, needs_witnesses)?
                    } else {
                        WitnessProofCollection::default()
                    };

                    (log_entries, witness_proofs)
                };

                // Otherwise use tokio::spawn to do async downloads
                #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
                let (log_entries, witness_proofs) = {
                    // Set network timeout values. Will default to 10 seconds for any reasons
                    let network_timeout = timeout.unwrap_or(Duration::from_secs(10));

                    let client = reqwest::ClientBuilder::new()
                        .timeout(network_timeout)
                        .build()
                        .map_err(|e| DIDWebVHError::NetworkError {
                            url: String::new(),
                            status_code: None,
                            message: format!("Failed to build HTTP client: {e}"),
                        })?;

                    if eager_witness_download {
                        // Eager path: download both files concurrently
                        let r1 = tokio::spawn(DIDWebVH::get_log_entries(
                            parsed_did_url.clone(),
                            client.clone(),
                        ));
                        let r2 = tokio::spawn(DIDWebVH::get_witness_proofs(
                            parsed_did_url.clone(),
                            client.clone(),
                        ));

                        let raw_entries = r1.await.map_err(|e| {
                            DIDWebVHError::NetworkError {
                                url: did.to_string(),
                                status_code: None,
                                message: format!("Error downloading LogEntries for DID: {e}"),
                            }
                        })??;
                        let witness_result = match r2.await {
                            Ok(result) => result,
                            Err(_) => Ok("{}".to_string()),
                        };

                        let log_entries = Self::parse_log_entries(&raw_entries)?;
                        Self::validate_log_entries(&log_entries, did)?;

                        let needs_witnesses = Self::needs_witness_proofs(&log_entries);
                        let witness_proofs =
                            Self::resolve_witness_proofs(witness_result, needs_witnesses)?;

                        (log_entries, witness_proofs)
                    } else {
                        // Deferred path: download did.jsonl first, then conditionally fetch witnesses
                        let raw_entries = tokio::spawn(DIDWebVH::get_log_entries(
                            parsed_did_url.clone(),
                            client.clone(),
                        ))
                        .await
                        .map_err(|e| DIDWebVHError::NetworkError {
                            url: did.to_string(),
                            status_code: None,
                            message: format!("Error downloading LogEntries for DID: {e}"),
                        })??;

                        let log_entries = Self::parse_log_entries(&raw_entries)?;
                        Self::validate_log_entries(&log_entries, did)?;

                        let witness_proofs = if Self::needs_witness_proofs(&log_entries) {
                            let raw_result = DIDWebVH::get_witness_proofs(
                                parsed_did_url.clone(),
                                client.clone(),
                            )
                            .await;
                            Self::resolve_witness_proofs(raw_result, true)?
                        } else {
                            WitnessProofCollection::default()
                        };

                        (log_entries, witness_proofs)
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

    /// Like [`resolve()`](Self::resolve), but returns owned (cloned) values
    /// so the caller does not borrow `self`.
    pub async fn resolve_owned(
        &mut self,
        did: &str,
        timeout: Option<Duration>,
        eager_witness_download: bool,
    ) -> Result<(LogEntry, MetaData), DIDWebVHError> {
        let (entry, metadata) = self.resolve(did, timeout, eager_witness_download).await?;
        Ok((entry.clone(), metadata))
    }
}

impl DIDWebVHState {
    fn resolve_state(
        &mut self,
        parsed_did_url: &WebVHURL,
    ) -> Result<(&LogEntry, MetaData), DIDWebVHError> {
        let _span = span!(Level::DEBUG, "resolve_state").entered();
        self.validate()?;

        // Per spec (Read/Resolve step 6): the DID being resolved MUST match the
        // top-level `id` in at least one version of the DIDDoc.
        let resolved_did = parsed_did_url.to_did_base();
        let did_matches_any = self.log_entries.iter().any(|entry| {
            entry
                .get_state()
                .get("id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == resolved_did)
        });
        if !did_matches_any {
            return Err(DIDWebVHError::ValidationError(format!(
                "DID being resolved ({resolved_did}) does not match the top-level 'id' in any DIDDoc version",
            )));
        }

        // Ensure metadata is set for the DID
        if let Some(first) = self.log_entries.first() {
            self.scid = first
                .get_scid()
                .ok_or_else(|| {
                    DIDWebVHError::ValidationError("First log entry is missing SCID".to_string())
                })?
                .to_string();
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
                Err(e) => Err(DIDWebVHError::NotFound(format!(
                    "Query matched no log entry: {e}"
                ))),
            }
        } else if let Some(last) = self.log_entries.last() {
            let metadata = self.generate_meta_data(last);
            Ok((&last.log_entry, metadata))
        } else {
            Err(DIDWebVHError::NotFound(
                "No LogEntries found after validation".to_string(),
            ))
        }
    }
}

#[cfg(all(test, feature = "network"))]
mod tests {
    use crate::{DIDWebVHError, DIDWebVHState};

    // ===== Mock-based resolve tests =====
    //
    // These tests create a DID locally and serve it via wiremock, so they
    // run deterministically in CI without hitting any external servers.

    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{any, path},
    };

    /// Helper: start a mock server, create a DID targeting its port, serialize
    /// to JSONL, mount the mock response, and return `(server, did_url)`.
    async fn setup_mock_resolve() -> (MockServer, String) {
        use crate::test_utils::{did_doc_with_key, key_and_params};

        let server = MockServer::start().await;
        let port = server.address().port();

        let (key, params) = key_and_params();
        let did_template = format!("did:webvh:{{SCID}}:localhost%3A{port}");
        let doc = did_doc_with_key(&did_template, &key);

        let mut state = DIDWebVHState::default();
        state
            .create_log_entry(None, &doc, &params, &key)
            .await
            .expect("Failed to create log entry");

        let log_entry = &state.log_entries[0].log_entry;
        let jsonl = serde_json::to_string(log_entry).unwrap();
        let scid = state.scid();
        let did = format!("did:webvh:{scid}:localhost%3A{port}");

        Mock::given(path("/.well-known/did.jsonl"))
            .respond_with(ResponseTemplate::new(200).set_body_string(&jsonl))
            .mount(&server)
            .await;

        (server, did)
    }

    /// Resolve a DID served from a local mock server.
    #[tokio::test]
    async fn resolve_mock() {
        let (_server, did) = setup_mock_resolve().await;

        let mut webvh = DIDWebVHState::default();
        let result = webvh.resolve(&did, None, false).await;
        assert!(result.is_ok(), "resolve failed: {result:?}");
    }

    /// Resolve with eager witness download (no witnesses configured).
    #[tokio::test]
    async fn resolve_mock_eager() {
        let (server, did) = setup_mock_resolve().await;

        // Witness file returns 404 — that's fine, no witnesses configured
        Mock::given(path("/.well-known/did-witness.json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let mut webvh = DIDWebVHState::default();
        let result = webvh.resolve(&did, None, true).await;
        assert!(result.is_ok(), "eager resolve failed: {result:?}");
    }

    /// Resolve a specific versionId served from a local mock server.
    #[tokio::test]
    async fn resolve_mock_specific_version() {
        use crate::log_entry::LogEntryMethods;

        let (_server, did) = setup_mock_resolve().await;

        // First resolve to get the versionId
        let mut webvh = DIDWebVHState::default();
        let (entry, _) = webvh.resolve(&did, None, false).await.unwrap();
        let version_id = entry.get_version_id().to_string();

        // Resolve again with ?versionId=...
        let mut webvh2 = DIDWebVHState::default();
        let did_with_version = format!("{did}?versionId={version_id}");
        let result = webvh2.resolve(&did_with_version, None, false).await;
        assert!(result.is_ok(), "versionId resolve failed: {result:?}");
    }

    /// Resolve with ?versionTime query from a local mock server.
    #[tokio::test]
    async fn resolve_mock_specific_time() {
        use crate::log_entry::LogEntryMethods;

        let (_server, did) = setup_mock_resolve().await;

        // Resolve to get a valid versionTime
        let mut webvh = DIDWebVHState::default();
        let (entry, _) = webvh.resolve(&did, None, false).await.unwrap();
        let version_time = entry.get_version_time_string();

        // Resolve again with ?versionTime=...
        let mut webvh2 = DIDWebVHState::default();
        let did_with_time = format!("{did}?versionTime={version_time}");
        let result = webvh2.resolve(&did_with_time, None, false).await;
        assert!(result.is_ok(), "versionTime resolve failed: {result:?}");
    }

    // ===== Network failure tests =====
    //
    // These tests use wiremock to simulate HTTP failures without hitting real servers.
    // DIDs pointing to `localhost` use `http://` (not HTTPS), allowing local mock servers.

    /// Helper: build a DID URL pointing at the given wiremock server.
    /// Format: `did:webvh:<scid>:localhost%3A<port>`
    fn mock_did(server: &wiremock::MockServer, scid: &str) -> String {
        let port = server.address().port();
        format!("did:webvh:{scid}:localhost%3A{port}")
    }

    /// Tests that resolving against a server that returns HTTP 404 produces a
    /// NetworkError with status_code = Some(404).
    #[tokio::test]
    async fn resolve_http_404() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let did = mock_did(&server, "testscid404");
        let mut webvh = DIDWebVHState::default();
        let result = webvh.resolve(&did, None, false).await;

        match result {
            Err(DIDWebVHError::NetworkError {
                status_code: Some(404),
                ..
            }) => {} // expected
            other => panic!("Expected NetworkError with status 404, got: {other:?}"),
        }
    }

    /// Tests that resolving against a server that returns HTTP 500 produces a
    /// NetworkError with status_code = Some(500).
    #[tokio::test]
    async fn resolve_http_500() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let did = mock_did(&server, "testscid500");
        let mut webvh = DIDWebVHState::default();
        let result = webvh.resolve(&did, None, false).await;

        match result {
            Err(DIDWebVHError::NetworkError {
                status_code: Some(500),
                ..
            }) => {}
            other => panic!("Expected NetworkError with status 500, got: {other:?}"),
        }
    }

    /// Tests that resolving against a server that returns 200 with invalid JSON
    /// (not valid JSONL log entries) produces a deserialization error.
    #[tokio::test]
    async fn resolve_malformed_response() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("this is not jsonl"))
            .mount(&server)
            .await;

        let did = mock_did(&server, "testscidbad");
        let mut webvh = DIDWebVHState::default();
        let result = webvh.resolve(&did, None, false).await;

        match result {
            Err(DIDWebVHError::LogEntryError(_)) => {} // expected: invalid JSON
            other => panic!("Expected LogEntryError for malformed response body, got: {other:?}"),
        }
    }

    /// Tests that resolving against a server that returns 200 with an empty body
    /// produces a NotFound error (no log entries).
    #[tokio::test]
    async fn resolve_empty_response() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;

        let did = mock_did(&server, "testscidempty");
        let mut webvh = DIDWebVHState::default();
        let result = webvh.resolve(&did, None, false).await;

        match result {
            Err(DIDWebVHError::NotFound(msg)) => {
                assert!(
                    msg.contains("No LogEntries"),
                    "Expected 'No LogEntries' message, got: {msg}"
                );
            }
            other => panic!("Expected NotFound error, got: {other:?}"),
        }
    }

    /// Tests that a network timeout is surfaced as a NetworkError with no status_code.
    #[tokio::test]
    async fn resolve_timeout() {
        use std::time::Duration;
        let server = MockServer::start().await;
        // Respond after 5 seconds — longer than our 1-second timeout
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;

        let did = mock_did(&server, "testscidtimeout");
        let mut webvh = DIDWebVHState::default();
        let result = webvh
            .resolve(&did, Some(Duration::from_secs(1)), false)
            .await;

        match result {
            Err(DIDWebVHError::NetworkError {
                status_code: None, ..
            }) => {} // transport-level timeout, no HTTP status
            other => panic!("Expected NetworkError with no status_code (timeout), got: {other:?}"),
        }
    }

    /// Tests that connection refused (no server listening) produces a NetworkError
    /// with no status_code.
    #[tokio::test]
    async fn resolve_connection_refused() {
        // Use a port where nothing is listening
        let did = "did:webvh:testscidrefused:localhost%3A1";
        let mut webvh = DIDWebVHState::default();
        let result = webvh
            .resolve(did, Some(std::time::Duration::from_secs(2)), false)
            .await;

        match result {
            Err(DIDWebVHError::NetworkError {
                status_code: None, ..
            }) => {}
            other => panic!(
                "Expected NetworkError with no status_code (connection refused), got: {other:?}"
            ),
        }
    }

    /// Tests that the structured NetworkError fields are correctly populated
    /// (url contains the expected host, status_code and message are set).
    #[tokio::test]
    async fn resolve_network_error_fields() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let did = mock_did(&server, "testscidfields");
        let mut webvh = DIDWebVHState::default();
        let result = webvh.resolve(&did, None, false).await;

        match result {
            Err(DIDWebVHError::NetworkError {
                ref url,
                status_code,
                ref message,
            }) => {
                assert!(
                    url.contains("localhost"),
                    "url should contain localhost: {url}"
                );
                assert_eq!(status_code, Some(503));
                assert!(
                    message.contains("503"),
                    "message should contain status: {message}"
                );
            }
            other => panic!("Expected structured NetworkError, got: {other:?}"),
        }
    }
}
