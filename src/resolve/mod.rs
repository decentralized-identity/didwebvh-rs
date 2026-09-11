//! Resolving WebVH DID's logic is handled here
//!
//! A WebVH DID can be loaded via HTTP(S), local file (testing), or raw string data
//! [`crate::DIDWebVHState::resolve`] Will load a WebVH DID using HTTP(S)
//! [`crate::DIDWebVHState::resolve_file`] Will load a WebVH DID using a local file path
//! [`crate::DIDWebVHState::resolve_log`] Will load a WebVH DID from raw JSONL string data
//! `resolve_state` is an internal function that will validate the DID and return
//! the resolved result
//!
//! Network resolution only contacts hosts allowed by the
//! [host policy](crate::host_policy) in `ResolveOptions`, which defaults to
//! public hosts only. The file and in-memory variants make no network
//! requests.

#[cfg(feature = "network")]
pub use crate::host_policy::HostPolicy;
#[cfg(feature = "network")]
use crate::host_policy::blocked_resolution_in_chain;
#[cfg(all(
    feature = "network",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
pub use crate::host_policy::{guarded_dns_resolver, guarded_dns_resolver_with};
#[cfg(feature = "network")]
use crate::url::URLType;
use crate::{
    DIDWebVHError, DIDWebVHState,
    log_entry::{LogEntry, LogEntryMethods, MetaData},
    log_entry_state::{LogEntryState, LogEntryValidationStatus},
    parameters::Parameters,
    url::WebVHURL,
    witness::proofs::WitnessProofCollection,
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

/// Default maximum HTTP response size: 200 KB.
#[cfg(feature = "network")]
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 200 * 1024;

#[cfg(feature = "network")]
const LOG_FILE: &str = "did.jsonl";
#[cfg(feature = "network")]
const WITNESS_FILE: &str = "did-witness.json";

/// Options for network-based DID resolution.
///
/// Every field has a secure default. Set individual fields with
/// `ResolveOptions { field: value, ..ResolveOptions::default() }` or the
/// `with_*` methods.
#[cfg(feature = "network")]
#[derive(Debug, Clone)]
pub struct ResolveOptions {
    /// Network timeout (default: 10 seconds).
    ///
    /// Applied to the client this crate builds. With
    /// [`http_client`](Self::http_client) set, a `Some` value is applied to
    /// each request instead. Not applied on wasm32.
    pub timeout: Option<Duration>,
    /// Download witnesses concurrently with log entries (default: false).
    pub eager_witness_download: bool,
    /// Maximum allowed HTTP response body size in bytes (default: 200 KB).
    /// Applies independently to each downloaded file (did.jsonl, did-witness.json).
    pub max_response_bytes: u64,
    /// Which hosts resolution may contact (default: [`HostPolicy::PublicOnly`]).
    ///
    /// Applied to every fetch (`did.jsonl`, `did-witness.json`), including
    /// fetches made through a caller-supplied [`http_client`](Self::http_client).
    /// Local development against `did:webvh:{SCID}:localhost%3A<port>` needs
    /// [`HostPolicy::AllowPrivate`].
    pub host_policy: HostPolicy,
    /// HTTP client to fetch with, instead of the one this crate builds
    /// (default: `None`).
    ///
    /// When `None`, native builds use a client with the configured timeout,
    /// redirects disabled, system proxy settings ignored and, unless the
    /// policy is [`HostPolicy::AllowPrivate`], a DNS resolver that refuses any
    /// name resolving to a non-public address (`guarded_dns_resolver`).
    /// wasm32 builds use reqwest's default browser client.
    ///
    /// When `Some`, [`host_policy`](Self::host_policy) still refuses
    /// non-public names before any request is made, but **the caller owns the
    /// connect-time half**: DNS answers, redirects and proxies are whatever
    /// that client does. On native targets, build it with
    /// `.dns_resolver(guarded_dns_resolver())`,
    /// `.redirect(reqwest::redirect::Policy::none())` and `.no_proxy()` to
    /// keep the default protection.
    pub http_client: Option<reqwest::Client>,
}

#[cfg(feature = "network")]
impl Default for ResolveOptions {
    fn default() -> Self {
        Self {
            timeout: None,
            eager_witness_download: false,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            host_policy: HostPolicy::PublicOnly,
            http_client: None,
        }
    }
}

#[cfg(feature = "network")]
impl ResolveOptions {
    /// Set [`host_policy`](Self::host_policy).
    pub fn with_host_policy(mut self, host_policy: HostPolicy) -> Self {
        self.host_policy = host_policy;
        self
    }

    /// Set [`http_client`](Self::http_client). The caller then owns the
    /// connect-time checks (DNS answers, redirects, proxies).
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }
}

/// Per-fetch settings derived from [`ResolveOptions`].
#[cfg(feature = "network")]
#[derive(Clone, Copy)]
struct FetchOptions {
    max_bytes: u64,
    host_policy: HostPolicy,
    /// Per-request timeout, used with a caller-supplied client.
    request_timeout: Option<Duration>,
}

/// The HTTP client used when `ResolveOptions::http_client` is `None`.
#[cfg(all(
    feature = "network",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
fn default_client(timeout: Duration, host_policy: HostPolicy) -> Result<Client, DIDWebVHError> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        // The DID chooses the host; a redirect would let that host choose
        // another one.
        .redirect(reqwest::redirect::Policy::none())
        // A proxy resolves the target name itself, where the DNS guard
        // cannot see the answer.
        .no_proxy();
    if host_policy != HostPolicy::AllowPrivate {
        builder = builder.dns_resolver(guarded_dns_resolver());
    }
    builder.build().map_err(|e| DIDWebVHError::NetworkError {
        url: String::new(),
        status_code: None,
        message: format!("Failed to build HTTP client: {e}"),
    })
}

/// HTTP client helpers for fetching DID log entries and witness proofs.
#[cfg(feature = "network")]
pub struct DIDWebVH;

#[cfg(feature = "network")]
impl DIDWebVH {
    /// Fetches a file from the given URL, enforcing a maximum response body size.
    ///
    /// The size limit is checked in two ways:
    /// 1. If the server provides a `Content-Length` header, the response is rejected
    ///    immediately when the advertised size exceeds `max_bytes`.
    /// 2. The body is read in chunks, and the cumulative size is checked against
    ///    `max_bytes` as data arrives. This catches cases where `Content-Length` is
    ///    absent or inaccurate (e.g. chunked transfer encoding).
    async fn download_file(
        client: Client,
        url: Url,
        fetch: FetchOptions,
    ) -> Result<String, DIDWebVHError> {
        let max_bytes = fetch.max_bytes;
        let url_str = url.to_string();
        let mut request = client.get(url);
        if let Some(timeout) = fetch.request_timeout {
            request = request.timeout(timeout);
        }
        let mut response = request.send().await.map_err(|e| {
            if let Some(blocked) = blocked_resolution_in_chain(&e) {
                return DIDWebVHError::BlockedHost(blocked.to_string());
            }
            DIDWebVHError::NetworkError {
                url: url_str.clone(),
                status_code: None,
                message: format!("Request failed: {e}"),
            }
        })?;

        if response.status() != StatusCode::OK {
            let status = response.status().as_u16();
            warn!("url ({url_str}): HTTP Status code = {status}");
            return Err(DIDWebVHError::NetworkError {
                url: url_str,
                status_code: Some(status),
                message: format!("HTTP {status}"),
            });
        }

        // Early rejection based on Content-Length header
        if let Some(content_length) = response.content_length()
            && content_length > max_bytes
        {
            return Err(DIDWebVHError::ResponseTooLarge {
                url: url_str,
                max_bytes,
            });
        }

        // Read body in chunks, enforcing the size limit as data arrives
        let mut body = Vec::new();
        let mut total_bytes: u64 = 0;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| DIDWebVHError::NetworkError {
                url: url_str.clone(),
                status_code: Some(200),
                message: format!("Failed to read response body: {e}"),
            })?
        {
            total_bytes += chunk.len() as u64;
            if total_bytes > max_bytes {
                return Err(DIDWebVHError::ResponseTooLarge {
                    url: url_str,
                    max_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }

        String::from_utf8(body).map_err(|e| DIDWebVHError::NetworkError {
            url: url_str,
            status_code: Some(200),
            message: format!("Response body is not valid UTF-8: {e}"),
        })
    }

    /// Builds the policy-checked URL for `file_name` (the log or the witness
    /// proofs) and fetches it.
    async fn get_file(
        url: WebVHURL,
        file_name: &'static str,
        client: Client,
        fetch: FetchOptions,
    ) -> Result<String, DIDWebVHError> {
        let file_url = match url.get_fetch_url(file_name, fetch.host_policy) {
            Ok(url) => url,
            Err(e @ DIDWebVHError::BlockedHost(_)) => return Err(e),
            Err(e) => {
                warn!("Invalid URL for DID: {e}");
                return Err(DIDWebVHError::InvalidMethodIdentifier(format!(
                    "Couldn't generate a valid URL from the DID: {e}"
                )));
            }
        };

        Self::download_file(client, file_url, fetch).await
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

    /// Parse raw JSONL log entry lines into a vec of [`LogEntryState`].
    ///
    /// Each line in `raw` must be a valid JSON-serialized log entry.
    /// Returns an error if any line fails to parse.
    pub fn parse_log_entries(raw: &str) -> Result<Vec<LogEntryState>, DIDWebVHError> {
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

    /// Check whether any log entry has a non-empty witness parameter.
    pub fn needs_witness_proofs(log_entries: &[LogEntryState]) -> bool {
        log_entries.iter().any(|e| {
            e.log_entry
                .get_parameters()
                .witness
                .as_ref()
                .is_some_and(|w| !w.is_empty())
        })
    }

    /// Parse a raw witness proofs JSON string into a [`WitnessProofCollection`].
    pub fn parse_witness_proofs(raw: &str) -> Result<WitnessProofCollection, DIDWebVHError> {
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
            return Err(DIDWebVHError::NotFound(format!(
                "No LogEntries found for DID: {did}",
            )));
        }
        Ok(())
    }

    /// Resolve a `did:webvh` DID from raw JSONL log data and optional witness proofs.
    ///
    /// This method performs the same cryptographic verification as [`resolve()`](Self::resolve)
    /// and [`resolve_file()`](Self::resolve_file), but accepts the log data as in-memory strings
    /// rather than fetching from a network endpoint or reading from the filesystem.
    ///
    /// This is useful for client-side verification of DID documents received from a
    /// cache server, where the raw log is transmitted alongside the resolved document
    /// to enable independent verification without an additional network round-trip.
    ///
    /// # Arguments
    /// * `did` — The DID to resolve (may include query parameters like `?versionId=...`).
    /// * `log_entries` — Raw JSONL string containing one log entry per line.
    /// * `witness_proofs` — Optional raw JSON string containing witness proofs.
    ///
    /// # Examples
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use didwebvh_rs::DIDWebVHState;
    ///
    /// let raw_log = r#"{"versionId":"1-abc...","parameters":{...},...}"#;
    /// let mut state = DIDWebVHState::default();
    /// let (log_entry, metadata) = state
    ///     .resolve_log("did:webvh:abc:example.com", raw_log, None)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn resolve_log(
        &mut self,
        did: &str,
        log_entries: &str,
        witness_proofs: Option<&str>,
    ) -> Result<(&LogEntry, MetaData), DIDWebVHError> {
        let _span = span!(Level::DEBUG, "resolve_log", DID = did);
        async move {
            let parsed_did_url = WebVHURL::parse_did_url(did)?;

            let parsed_entries = Self::parse_log_entries(log_entries)?;
            Self::validate_log_entries(&parsed_entries, did)?;

            let witness_collection = if let Some(raw_witnesses) = witness_proofs {
                Self::parse_witness_proofs(raw_witnesses)?
            } else {
                WitnessProofCollection::default()
            };

            self.log_entries = parsed_entries;
            self.witness_proofs = witness_collection;
            self.validated = false;
            self.expires = DateTime::default();

            self.resolve_state(&parsed_did_url)
        }
        .instrument(_span)
        .await
    }

    /// Like [`resolve_log()`](Self::resolve_log), but returns owned (cloned) values
    /// so the caller does not borrow `self`.
    pub async fn resolve_log_owned(
        &mut self,
        did: &str,
        log_entries: &str,
        witness_proofs: Option<&str>,
    ) -> Result<(LogEntry, MetaData), DIDWebVHError> {
        let (entry, metadata) = self.resolve_log(did, log_entries, witness_proofs).await?;
        Ok((entry.clone(), metadata))
    }
}

#[cfg(feature = "network")]
impl DIDWebVHState {
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
    /// * `options` — Network options (timeout, eager witness download, max response size,
    ///   host policy, HTTP client). Use [`ResolveOptions::default()`] for secure defaults
    ///   (10 s timeout, 200 KB limit, public hosts only).
    ///
    /// # Host policy
    ///
    /// With the default [`HostPolicy::PublicOnly`], a DID whose host is
    /// `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa` or a
    /// single label fails with [`DIDWebVHError::BlockedHost`] before any
    /// request is made, and (on native targets, with the default client) so
    /// does a host that resolves to a non-public address. Set
    /// [`ResolveOptions::host_policy`] to [`HostPolicy::AllowPrivate`] to
    /// resolve such DIDs, for example `did:webvh:{SCID}:localhost%3A8000` in
    /// development.
    ///
    /// # Returned `LogEntry` vs. resolution-time DID Document
    ///
    /// The returned [`LogEntry`] carries `state` exactly as it was signed and
    /// hashed — i.e. **without** the implicit `#files` / `#whois` services. To
    /// obtain the resolution-time DID Document with the implicit services
    /// injected (matching the `didDocument` shape returned by
    /// `didwebvh-ts`'s `resolveDIDFromLog`), call
    /// [`crate::log_entry::LogEntryMethods::get_did_document`] on the
    /// returned entry. That method clones `state` and appends the
    /// implicit services on the clone, so the LogEntry's stored `state` is
    /// never mutated and the hash chain remains intact.
    ///
    /// **Never** feed the document returned by `get_did_document()` back into
    /// a new LogEntry's `state` — doing so would bake the implicit services
    /// into the canonical bytes and break interop with every other
    /// implementation.
    pub async fn resolve(
        &mut self,
        did: &str,
        options: ResolveOptions,
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
                // Refuse a host the policy does not allow before any client is
                // built or request made. Each fetch below repeats the check.
                parsed_did_url.get_fetch_url(LOG_FILE, options.host_policy)?;

                // If building for WASM then don't use tokio::spawn
                // This means sequential retrieval of files
                #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
                let (log_entries, witness_proofs) = {
                    trace!("timeout is not available in WASM builds! {:#?}", options.timeout);
                    // The browser's fetch follows redirects (reqwest's wasm
                    // client has no switch for it) and does not expose DNS, so
                    // only the name and literal checks apply here.
                    let client = options.http_client.clone().unwrap_or_else(reqwest::Client::new);
                    let fetch = FetchOptions {
                        max_bytes: options.max_response_bytes,
                        host_policy: options.host_policy,
                        request_timeout: None,
                    };

                    let raw_entries =
                        DIDWebVH::get_file(parsed_did_url.clone(), LOG_FILE, client.clone(), fetch).await?;
                    let log_entries = Self::parse_log_entries(&raw_entries)?;
                    Self::validate_log_entries(&log_entries, did)?;

                    let needs_witnesses = Self::needs_witness_proofs(&log_entries);
                    let witness_proofs = if options.eager_witness_download || needs_witnesses {
                        let raw_result =
                            DIDWebVH::get_file(parsed_did_url.clone(), WITNESS_FILE, client.clone(), fetch)
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
                    let (client, request_timeout) = if let Some(client) = &options.http_client {
                        (client.clone(), options.timeout)
                    } else {
                        // Set network timeout values. Will default to 10 seconds for any reasons
                        let network_timeout = options.timeout.unwrap_or(Duration::from_secs(10));
                        (default_client(network_timeout, options.host_policy)?, None)
                    };
                    let fetch = FetchOptions {
                        max_bytes: options.max_response_bytes,
                        host_policy: options.host_policy,
                        request_timeout,
                    };

                    if options.eager_witness_download {
                        // Eager path: download both files concurrently
                        let r1 = tokio::spawn(DIDWebVH::get_file(
                            parsed_did_url.clone(),
                            LOG_FILE,
                            client.clone(),
                            fetch,
                        ));
                        let r2 = tokio::spawn(DIDWebVH::get_file(
                            parsed_did_url.clone(),
                            WITNESS_FILE,
                            client.clone(),
                            fetch,
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
                        let raw_entries = tokio::spawn(DIDWebVH::get_file(
                            parsed_did_url.clone(),
                            LOG_FILE,
                            client.clone(),
                            fetch,
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
                            let raw_result = DIDWebVH::get_file(
                                parsed_did_url.clone(),
                                WITNESS_FILE,
                                client.clone(),
                                fetch,
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
        options: ResolveOptions,
    ) -> Result<(LogEntry, MetaData), DIDWebVHError> {
        let (entry, metadata) = self.resolve(did, options).await?;
        Ok((entry.clone(), metadata))
    }
}

impl DIDWebVHState {
    fn resolve_state(
        &mut self,
        parsed_did_url: &WebVHURL,
    ) -> Result<(&LogEntry, MetaData), DIDWebVHError> {
        let _span = span!(Level::DEBUG, "resolve_state").entered();
        // A resolver MUST reject a truncated log — a partial resolution is
        // worse than no resolution because the caller cannot tell the
        // difference. `assert_complete` surfaces the truncation as a
        // `ValidationError`.
        self.validate()?.assert_complete()?;

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
    use super::{HostPolicy, ResolveOptions};
    use crate::{DIDWebVHError, DIDWebVHState, test_utils::StubResolver};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    /// The mock-server tests serve DIDs from `localhost`, which the default
    /// host policy refuses; they opt in to the development policy.
    fn dev_options() -> ResolveOptions {
        ResolveOptions::default().with_host_policy(HostPolicy::AllowPrivate)
    }

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
        let result = webvh.resolve(&did, dev_options()).await;
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
        let result = webvh
            .resolve(
                &did,
                ResolveOptions {
                    eager_witness_download: true,
                    ..dev_options()
                },
            )
            .await;
        assert!(result.is_ok(), "eager resolve failed: {result:?}");
    }

    /// Resolve a specific versionId served from a local mock server.
    #[tokio::test]
    async fn resolve_mock_specific_version() {
        use crate::log_entry::LogEntryMethods;

        let (_server, did) = setup_mock_resolve().await;

        // First resolve to get the versionId
        let mut webvh = DIDWebVHState::default();
        let (entry, _) = webvh.resolve(&did, dev_options()).await.unwrap();
        let version_id = entry.get_version_id().to_string();

        // Resolve again with ?versionId=...
        let mut webvh2 = DIDWebVHState::default();
        let did_with_version = format!("{did}?versionId={version_id}");
        let result = webvh2.resolve(&did_with_version, dev_options()).await;
        assert!(result.is_ok(), "versionId resolve failed: {result:?}");
    }

    /// Resolve with ?versionTime query from a local mock server.
    #[tokio::test]
    async fn resolve_mock_specific_time() {
        use crate::log_entry::LogEntryMethods;

        let (_server, did) = setup_mock_resolve().await;

        // Resolve to get a valid versionTime
        let mut webvh = DIDWebVHState::default();
        let (entry, _) = webvh.resolve(&did, dev_options()).await.unwrap();
        let version_time = entry.get_version_time_string();

        // Resolve again with ?versionTime=...
        let mut webvh2 = DIDWebVHState::default();
        let did_with_time = format!("{did}?versionTime={version_time}");
        let result = webvh2.resolve(&did_with_time, dev_options()).await;
        assert!(result.is_ok(), "versionTime resolve failed: {result:?}");
    }

    // ===== Network failure tests =====
    //
    // These tests use wiremock to simulate HTTP failures without hitting real servers.
    // Under `HostPolicy::AllowPrivate` (`dev_options()`), DIDs pointing to
    // `localhost` use `http://` (not HTTPS), allowing local mock servers.

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
        let result = webvh.resolve(&did, dev_options()).await;

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
        let result = webvh.resolve(&did, dev_options()).await;

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
        let result = webvh.resolve(&did, dev_options()).await;

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
        let result = webvh.resolve(&did, dev_options()).await;

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
            .resolve(
                &did,
                ResolveOptions {
                    timeout: Some(Duration::from_secs(1)),
                    ..dev_options()
                },
            )
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
            .resolve(
                did,
                ResolveOptions {
                    timeout: Some(std::time::Duration::from_secs(2)),
                    ..dev_options()
                },
            )
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
        let result = webvh.resolve(&did, dev_options()).await;

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

    // ===== resolve_log tests =====

    /// Helper: create a DID with log entries and return (did_string, jsonl_string)
    async fn setup_resolve_log_data() -> (String, String) {
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

        (did, jsonl)
    }

    /// Resolve a DID from raw JSONL log data (no network needed for verification).
    #[tokio::test]
    async fn resolve_log_from_str() {
        let (did, jsonl) = setup_resolve_log_data().await;

        let mut webvh = DIDWebVHState::default();
        let result = webvh.resolve_log(&did, &jsonl, None).await;
        assert!(result.is_ok(), "resolve_log failed: {result:?}");
    }

    /// Resolve a DID from raw JSONL log data and verify the returned document
    /// matches what was resolved via network.
    #[tokio::test]
    async fn resolve_log_matches_network_resolve() {
        use crate::log_entry::LogEntryMethods;

        let (server, did) = setup_mock_resolve().await;
        // Also need witness endpoint for eager
        Mock::given(path("/.well-known/did-witness.json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        // Resolve via network
        let mut webvh_net = DIDWebVHState::default();
        let (net_entry, _) = webvh_net.resolve(&did, dev_options()).await.unwrap();
        let net_doc = net_entry.get_did_document().unwrap();

        // Get the raw log from the network-resolved state
        let log_entry = &webvh_net.log_entries()[0].log_entry;
        let jsonl = serde_json::to_string(log_entry).unwrap();

        // Resolve via resolve_log
        let mut webvh_log = DIDWebVHState::default();
        let (log_entry, _) = webvh_log.resolve_log(&did, &jsonl, None).await.unwrap();
        let log_doc = log_entry.get_did_document().unwrap();

        assert_eq!(
            net_doc, log_doc,
            "Documents from network and log resolution should match"
        );
    }

    /// resolve_log_owned returns owned values without borrowing self.
    #[tokio::test]
    async fn resolve_log_owned_works() {
        let (did, jsonl) = setup_resolve_log_data().await;

        let mut webvh = DIDWebVHState::default();
        let result = webvh.resolve_log_owned(&did, &jsonl, None).await;
        assert!(result.is_ok(), "resolve_log_owned failed: {result:?}");
    }

    /// resolve_log rejects empty log data.
    #[tokio::test]
    async fn resolve_log_empty_log() {
        let mut webvh = DIDWebVHState::default();
        let result = webvh
            .resolve_log("did:webvh:testscid:example.com", "", None)
            .await;

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

    /// resolve_log rejects malformed JSONL.
    #[tokio::test]
    async fn resolve_log_malformed_jsonl() {
        let mut webvh = DIDWebVHState::default();
        let result = webvh
            .resolve_log("did:webvh:testscid:example.com", "not valid json", None)
            .await;

        match result {
            Err(DIDWebVHError::LogEntryError(_)) => {} // expected
            other => panic!("Expected LogEntryError, got: {other:?}"),
        }
    }

    /// resolve_log with tampered log data should fail validation.
    #[tokio::test]
    async fn resolve_log_tampered_data_fails() {
        let (did, jsonl) = setup_resolve_log_data().await;

        // Tamper with the JSONL by modifying a character in the proof/signature
        // This should cause validation to fail
        let tampered = jsonl.replacen("z", "y", 1);
        if tampered == jsonl {
            // If no 'z' was found, skip the test
            return;
        }

        let mut webvh = DIDWebVHState::default();
        let result = webvh.resolve_log(&did, &tampered, None).await;
        assert!(
            result.is_err(),
            "resolve_log should fail with tampered data"
        );
    }

    // ===== Response size limit tests =====

    /// Tests that a response with a body exceeding the limit is rejected.
    #[tokio::test]
    async fn resolve_rejects_large_response_body() {
        let server = MockServer::start().await;
        // Create a body larger than DEFAULT_MAX_RESPONSE_BYTES (200 KB)
        let large_body = "x".repeat(210 * 1024);
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string(&large_body))
            .mount(&server)
            .await;

        let did = mock_did(&server, "testscidlarge");
        let mut webvh = DIDWebVHState::default();
        let result = webvh.resolve(&did, dev_options()).await;

        match result {
            Err(DIDWebVHError::ResponseTooLarge { max_bytes, .. }) => {
                assert_eq!(max_bytes, super::DEFAULT_MAX_RESPONSE_BYTES);
            }
            other => panic!("Expected ResponseTooLarge, got: {other:?}"),
        }
    }

    /// Tests that a custom max_response_bytes limit is enforced.
    #[tokio::test]
    async fn resolve_custom_size_limit() {
        let (_server, did) = setup_mock_resolve().await;

        // Use an extremely small limit that the valid response will exceed
        let mut webvh = DIDWebVHState::default();
        let result = webvh
            .resolve(
                &did,
                ResolveOptions {
                    max_response_bytes: 10, // 10 bytes — too small for any DID log
                    ..dev_options()
                },
            )
            .await;

        match result {
            Err(DIDWebVHError::ResponseTooLarge { max_bytes, .. }) => {
                assert_eq!(max_bytes, 10);
            }
            other => panic!("Expected ResponseTooLarge, got: {other:?}"),
        }
    }

    /// Tests that normal-sized responses pass the default size limit.
    #[tokio::test]
    async fn resolve_normal_response_passes_size_check() {
        let (_server, did) = setup_mock_resolve().await;

        let mut webvh = DIDWebVHState::default();
        let result = webvh.resolve(&did, dev_options()).await;
        assert!(
            result.is_ok(),
            "Normal response should pass size check: {result:?}"
        );
    }

    // ===== Host policy (egress) tests =====

    /// A TCP listener on 127.0.0.1 that counts accepted connections.
    async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(socket);
            }
        });
        (port, accepted)
    }

    /// By default, loopback and other non-public names are refused before
    /// any connection is attempted, on both download paths.
    #[tokio::test]
    async fn default_policy_refuses_localhost_without_connecting() {
        let (port, accepted) = counting_listener().await;
        for host in [
            "localhost",
            "LOCALHOST",
            "localhost.",
            "local%68ost",
            "svc.localhost",
            "printer.local",
            "metadata.google.internal",
            "metadata",
        ] {
            for eager_witness_download in [false, true] {
                let did = format!("did:webvh:QmScid:{host}%3A{port}");
                let mut webvh = DIDWebVHState::default();
                let result = webvh
                    .resolve(
                        &did,
                        ResolveOptions {
                            eager_witness_download,
                            ..ResolveOptions::default()
                        },
                    )
                    .await;
                assert!(
                    matches!(result, Err(DIDWebVHError::BlockedHost(_))),
                    "{did} (eager={eager_witness_download}): {result:?}"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 0);
    }

    /// The same localhost DID is refused by default (the server sees nothing)
    /// and resolves over plain http with `HostPolicy::AllowPrivate`.
    #[tokio::test]
    async fn allow_private_opt_in_resolves_localhost_over_http() {
        let (server, did) = setup_mock_resolve().await;

        let mut webvh = DIDWebVHState::default();
        let refused = webvh.resolve(&did, ResolveOptions::default()).await;
        assert!(
            matches!(refused, Err(DIDWebVHError::BlockedHost(_))),
            "{refused:?}"
        );
        assert!(server.received_requests().await.unwrap().is_empty());

        let mut webvh = DIDWebVHState::default();
        let result = webvh
            .resolve(
                &did,
                ResolveOptions {
                    host_policy: HostPolicy::AllowPrivate,
                    ..ResolveOptions::default()
                },
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url.scheme(), "http");
        assert_eq!(requests[0].url.path(), "/.well-known/did.jsonl");
    }

    /// A 3xx is surfaced as an error; its target receives no request.
    #[tokio::test]
    async fn redirects_are_not_followed() {
        let target = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&target)
            .await;
        let redirector = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(302).insert_header(
                "Location",
                format!("{}/.well-known/did.jsonl", target.uri()),
            ))
            .mount(&redirector)
            .await;

        let did = mock_did(&redirector, "testscidredirect");
        let mut webvh = DIDWebVHState::default();
        let result = webvh.resolve(&did, dev_options()).await;
        assert!(
            matches!(
                result,
                Err(DIDWebVHError::NetworkError {
                    status_code: Some(302),
                    ..
                })
            ),
            "{result:?}"
        );
        assert!(target.received_requests().await.unwrap().is_empty());
    }

    /// A name whose answers mix a public and a private address is refused as
    /// a whole, and nothing connects.
    #[tokio::test]
    async fn guarded_client_refuses_mixed_public_private_answer() {
        let (port, accepted) = counting_listener().await;
        let stub = StubResolver::new(&["93.184.216.34", "127.0.0.1"]);
        let lookups = stub.lookups.clone();
        let client = reqwest::Client::builder()
            .dns_resolver(super::guarded_dns_resolver_with(Arc::new(stub)))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();

        let did = format!("did:webvh:QmScid:mixed.example%3A{port}");
        let mut webvh = DIDWebVHState::default();
        let result = webvh
            .resolve(&did, ResolveOptions::default().with_http_client(client))
            .await;
        assert!(
            matches!(result, Err(DIDWebVHError::BlockedHost(_))),
            "{result:?}"
        );
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
        assert_eq!(accepted.load(Ordering::SeqCst), 0);
    }

    /// The client built when no `http_client` is supplied carries the DNS
    /// guard under `PublicOnly` and not under `AllowPrivate`.
    #[tokio::test]
    async fn default_client_installs_dns_guard_for_public_only() {
        let client = super::default_client(Duration::from_secs(2), HostPolicy::PublicOnly).unwrap();
        let err = client
            .get("http://localhost:1/")
            .send()
            .await
            .expect_err("must be refused");
        assert!(
            crate::host_policy::blocked_resolution_in_chain(&err).is_some(),
            "{err:?}"
        );

        let client =
            super::default_client(Duration::from_secs(2), HostPolicy::AllowPrivate).unwrap();
        let err = client
            .get("http://localhost:1/")
            .send()
            .await
            .expect_err("nothing listens on port 1");
        assert!(
            crate::host_policy::blocked_resolution_in_chain(&err).is_none(),
            "{err:?}"
        );
    }

    /// With a caller-supplied client the name check still applies, but DNS
    /// answers are the caller's responsibility: a client without the guard
    /// connects wherever its resolver points.
    #[tokio::test]
    async fn caller_supplied_client_owns_the_dns_half() {
        let (port, accepted) = counting_listener().await;
        let client = reqwest::Client::builder()
            .dns_resolver(
                Arc::new(StubResolver::new(&["127.0.0.1"])) as Arc<dyn reqwest::dns::Resolve>
            )
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let options = ResolveOptions::default().with_http_client(client);

        let mut webvh = DIDWebVHState::default();
        let refused = webvh
            .resolve(
                &format!("did:webvh:QmScid:localhost%3A{port}"),
                options.clone(),
            )
            .await;
        assert!(
            matches!(refused, Err(DIDWebVHError::BlockedHost(_))),
            "{refused:?}"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 0);

        let mut webvh = DIDWebVHState::default();
        let result = webvh
            .resolve(
                &format!("did:webvh:QmScid:unguarded.example%3A{port}"),
                options,
            )
            .await;
        assert!(
            matches!(result, Err(DIDWebVHError::NetworkError { .. })),
            "{result:?}"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }
}
