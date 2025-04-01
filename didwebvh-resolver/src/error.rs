//! Error types for the didwebvh-resolver crate.

use thiserror::Error;

/// Main error type for the didwebvh-resolver crate.
#[derive(Error, Debug)]
pub enum ResolverError {
    /// Errors related to DID parsing and validation
    #[error("DID parsing error: {0}")]
    DIDParsing(String),

    /// Errors related to DID resolution
    #[error("DID resolution error: {0}")]
    Resolution(String),
    
    /// Errors related to DID log parsing and validation
    #[error("DID log error: {0}")]
    LogProcessing(String),
    
    /// Errors related to verification of DID log entries
    #[error("Verification error: {0}")]
    Verification(String),
    
    /// Errors related to HTTP operations
    #[error("HTTP error: {0}")]
    Http(String),
    
    /// Errors related to JSON processing
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    /// Errors related to URL parsing and manipulation
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),
    
    /// Errors related to timestamp parsing and processing
    #[error("Time error: {0}")]
    Time(String),
    
    /// Other general errors
    #[error("General error: {0}")]
    General(String),
}

/// Error type for the DID resolution process as defined in the DID Core specification.
/// These are errors that must be communicated in the resolution metadata.
#[derive(Error, Debug)]
pub enum ResolutionError {
    /// DID not found
    #[error("DID not found")]
    NotFound,
    
    /// DID is invalid
    #[error("Invalid DID: {0}")]
    InvalidDID(String),
    
    /// DID method not supported
    #[error("Method not supported")]
    MethodNotSupported,
    
    /// DID resolution failed due to an internal error
    #[error("Internal error: {0}")]
    InternalError(String),
    
    /// DID document is invalid
    #[error("Invalid DID document: {0}")]
    InvalidDIDDocument(String),
    
    /// DID log verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

/// Result type for resolver operations
pub type Result<T> = std::result::Result<T, ResolverError>;

/// Result type for resolution operations
pub type ResolutionResult<T> = std::result::Result<T, ResolutionError>;