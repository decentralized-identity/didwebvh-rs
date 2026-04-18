//! Shared clap `ValueEnum` for picking a cryptographic suite in examples.
//!
//! Kept under `examples/common/` rather than the library crate because
//! `clap::ValueEnum` isn't something a library should impose on downstream
//! consumers. Each example pulls this in with
//! `#[path = "common/suite.rs"] mod suite;`.
//!
//! Classical suites are always available. PQC suites (`ml-dsa-44`,
//! `slh-dsa-128`) are gated on the `experimental-pqc` Cargo feature —
//! the clap variant literally does not exist without the feature, so
//! passing `--key-type ml-dsa-44` on a build without the feature fails
//! at argument parsing with a clear "invalid value" rather than a
//! cryptic runtime error.

use affinidi_secrets_resolver::secrets::KeyType;
use clap::ValueEnum;

/// Cryptographic suites that examples can generate keys for.
///
/// Maps 1:1 onto [`KeyType`] via [`Suite::key_type`]. Strings match the
/// didwebvh / Data Integrity cryptosuite naming where sensible.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
#[allow(clippy::enum_variant_names)] // PQC names repeat for a reason.
pub enum Suite {
    /// Ed25519 — signing only. Classical default.
    #[default]
    #[value(name = "ed25519")]
    Ed25519,
    /// NIST P-256. Signing + ECDH.
    #[value(name = "p-256")]
    P256,
    /// NIST P-384. Signing + ECDH, higher security margin.
    #[value(name = "p-384")]
    P384,
    /// secp256k1. Bitcoin / Ethereum ecosystems.
    #[value(name = "secp256k1")]
    Secp256k1,
    /// ML-DSA-44 (FIPS 204). Post-quantum signing.
    ///
    /// Experimental — not yet in the didwebvh 1.0 spec. Interop-test only.
    #[cfg(feature = "experimental-pqc")]
    #[value(name = "ml-dsa-44")]
    MlDsa44,
    /// SLH-DSA-SHA2-128s (FIPS 205). Post-quantum signing, stateless hash-based.
    ///
    /// Experimental — not yet in the didwebvh 1.0 spec. Interop-test only.
    #[cfg(feature = "experimental-pqc")]
    #[value(name = "slh-dsa-128")]
    SlhDsa128,
}

impl Suite {
    /// Convert to the underlying [`KeyType`] the library works with.
    #[must_use]
    pub fn key_type(self) -> KeyType {
        match self {
            Self::Ed25519 => KeyType::Ed25519,
            Self::P256 => KeyType::P256,
            Self::P384 => KeyType::P384,
            Self::Secp256k1 => KeyType::Secp256k1,
            #[cfg(feature = "experimental-pqc")]
            Self::MlDsa44 => KeyType::MlDsa44,
            #[cfg(feature = "experimental-pqc")]
            Self::SlhDsa128 => KeyType::SlhDsaSha2_128s,
        }
    }
}
