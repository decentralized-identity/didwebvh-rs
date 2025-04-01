//! Module for HTTP client functionality.
//! 
//! This module provides a trait for HTTP client operations and a default implementation
//! using reqwest.

use crate::error::{ResolverError, Result};
use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use std::time::Duration;

/// Trait defining the HTTP client interface for fetching resources.
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Fetch a resource from the given URL.
    ///
    /// # Arguments
    /// * `url` - The URL to fetch.
    /// * `accept` - Optional accept header value.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The fetched resource as bytes.
    /// * `Err(ResolverError)` - Any error that occurred during the fetch.
    async fn get(&self, url: &str, accept: Option<String>) -> Result<Vec<u8>>;
}

/// Default HTTP client implementation using reqwest.
pub struct DefaultHttpClient {
    client: Client,
    timeout: Duration,
}

impl DefaultHttpClient {
    /// Create a new DefaultHttpClient with the default configuration.
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(30))
    }

    /// Create a new DefaultHttpClient with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        // Configure client with appropriate defaults for DID resolution
        let client = Client::builder()
            .timeout(timeout)
            .user_agent("didwebvh-resolver/0.1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self { client, timeout }
    }
}

#[async_trait]
impl HttpClient for DefaultHttpClient {
    async fn get(&self, url: &str, accept: Option<String>) -> Result<Vec<u8>> {
        let mut request = self.client.get(url);
        
        // Add accept header if provided
        if let Some(accept_value) = accept {
            request = request.header(reqwest::header::ACCEPT, accept_value);
        }
        
        // Execute request
        let response = request.send().await.map_err(|e| {
            if e.is_timeout() {
                ResolverError::Http(format!("Request to {} timed out after {:?}", url, self.timeout))
            } else if e.is_connect() {
                ResolverError::Http(format!("Connection failed for {}: {}", url, e))
            } else {
                ResolverError::Http(format!("HTTP request failed for {}: {}", url, e))
            }
        })?;
        
        // Check status code
        let status = response.status();
        if !status.is_success() {
            return match status {
                StatusCode::NOT_FOUND => {
                    Err(ResolverError::Http(format!("Resource not found at {}", url)))
                }
                _ => {
                    Err(ResolverError::Http(format!(
                        "HTTP error {} when fetching {}: {}",
                        status.as_u16(),
                        url,
                        status.canonical_reason().unwrap_or("Unknown error")
                    )))
                }
            };
        }
        
        // Get response body
        let bytes = response.bytes().await.map_err(|e| {
            ResolverError::Http(format!("Failed to read response body from {}: {}", url, e))
        })?;
        
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use mockall::predicate::*;
    use mockall::*;

    // Create a mock HTTP client for testing
    mock! {
        pub HttpClientMock {}
        #[async_trait]
        impl HttpClient for HttpClientMock {
            async fn get(&self, url: &str, accept: Option<String>) -> Result<Vec<u8>>;
        }
    }

    #[tokio::test]
    async fn test_default_http_client_success() {
        // This test requires an internet connection and will hit a real API
        // Consider skipping in CI environments
        let client = DefaultHttpClient::new();
        let result = client.get("https://httpbin.org/get", None).await;
        
        assert!(result.is_ok(), "Expected HTTP request to succeed");
        let data = result.unwrap();
        assert!(!data.is_empty(), "Expected non-empty response");
    }

    #[tokio::test]
    async fn test_default_http_client_not_found() {
        let client = DefaultHttpClient::new();
        let result = client.get("https://httpbin.org/status/404", None).await;
        
        assert!(result.is_err(), "Expected HTTP 404 error");
        match result {
            Err(ResolverError::Http(msg)) => {
                assert!(msg.contains("not found"), "Expected 'not found' error message");
            }
            _ => panic!("Expected HTTP error"),
        }
    }

    #[tokio::test]
    async fn test_default_http_client_server_error() {
        let client = DefaultHttpClient::new();
        let result = client.get("https://httpbin.org/status/500", None).await;
        
        assert!(result.is_err(), "Expected HTTP 500 error");
        match result {
            Err(ResolverError::Http(msg)) => {
                assert!(msg.contains("500"), "Expected error message to contain status code");
            }
            _ => panic!("Expected HTTP error"),
        }
    }

    #[tokio::test]
    async fn test_default_http_client_with_accept_header() {
        let client = DefaultHttpClient::new();
        let result = client.get(
            "https://httpbin.org/headers", 
            Some("application/json".to_string())
        ).await;
        
        assert!(result.is_ok(), "Expected HTTP request to succeed");
        
        // Fix the borrowing issue by storing the unwrapped result first
        let bytes = result.unwrap();
        let data = String::from_utf8_lossy(&bytes);
        
        assert!(data.contains("application/json"), 
                "Expected response to contain the accept header we sent");
    }

    #[tokio::test]
    async fn test_default_http_client_with_redirect() {
        let client = DefaultHttpClient::new();
        let result = client.get("https://httpbin.org/redirect/1", None).await;
        
        assert!(result.is_ok(), "Expected HTTP request with redirect to succeed");
        let data = result.unwrap();
        assert!(!data.is_empty(), "Expected non-empty response after redirect");
    }

    #[tokio::test]
    async fn test_client_with_mock_for_did_log() {
        let mut mock_client = MockHttpClientMock::new();
        
        // Set up the mock to expect a specific DID log URL
        let expected_url = "https://example.com/.well-known/did.jsonl";
        let mock_response = b"{\"versionId\": \"1-abc123\", \"versionTime\": \"2024-01-01T00:00:00Z\"}".to_vec();
        
        mock_client
            .expect_get()
            .with(eq(expected_url), eq(None))
            .times(1)
            .returning(move |_, _| Ok(mock_response.clone()));
        
        // Use the mock client
        let result = mock_client.get(expected_url, None).await;
        
        assert!(result.is_ok(), "Expected mock HTTP request to succeed");
        let data = result.unwrap();
        assert!(!data.is_empty(), "Expected non-empty response from mock");
        
        // Convert to string and verify content
        let content = String::from_utf8_lossy(&data);
        assert!(content.contains("1-abc123"), "Expected DID log content in response");
    }
}
