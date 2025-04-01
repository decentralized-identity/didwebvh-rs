//! A Rust implementation of the did:webvh resolver.
//!
//! This crate provides functionality to resolve did:webvh DIDs
//! according to the did:webvh specification.

// Re-export main types
pub mod error;
pub mod types;
pub mod url;
pub mod utils;
pub mod http;
pub mod log;
pub mod resolver;
pub mod crypto;

pub use error::{ResolverError, ResolutionError, Result, ResolutionResult};
pub use url::DIDUrl;
pub use http::{HttpClient, DefaultHttpClient};
pub use resolver::WebVHResolver;
pub use types::{
    DIDResolutionResult, DIDDocumentMetadata, DIDResolutionMetadata,
    ResolutionOptions, DIDLogEntry, Parameters, Proof, WitnessConfig, Witness,
};