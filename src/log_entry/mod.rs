/*!
*   Webvh utilizes Log Entries for each version change of the DID Document.
*/
use crate::{
    DIDWebVHError, Version,
    log_entry::{spec_1_0::LogEntry1_0, spec_1_0_pre::LogEntry1_0Pre},
    parameters::Parameters,
    witness::Witnesses,
};
use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
use base58::ToBase58;
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use serde_json_canonicalizer::to_string;
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, io::Write};
use tracing::debug;

pub mod read;
pub mod spec_1_0;
pub mod spec_1_0_pre;

/// Encodes a SHA-256 digest as a multihash byte array.
/// Multihash format: [hash_function_code, digest_length, ...digest_bytes]
/// SHA-256 code = 0x12, digest length = 0x20 (32 bytes)
pub(crate) fn encode_sha256_multihash(digest: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + digest.len());
    buf.push(0x12); // SHA-256 hash function code
    buf.push(0x20); // 32 bytes digest length
    buf.extend_from_slice(digest);
    buf
}

/// Resolved Document MetaData
/// Returned as resolved Document MetaData on a successful resolve
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetaData {
    /// The `<version_number>-<hash>` identifier for this log entry.
    pub version_id: String,
    /// RFC 3339 timestamp when this version was created.
    pub version_time: String,
    /// RFC 3339 timestamp when the DID was first created.
    pub created: String,
    /// RFC 3339 timestamp of the most recent update.
    pub updated: String,
    /// Self-Certifying Identifier (SCID) for the DID.
    pub scid: String,
    /// Whether the DID is portable (can change its web address).
    pub portable: bool,
    /// Whether the DID has been deactivated.
    pub deactivated: bool,
    /// Active witness configuration, if any.
    pub witness: Option<Witnesses>,
    /// Watcher endpoints configured for this DID.
    pub watchers: Option<Vec<String>>,
}

/// Extracts raw public key bytes from a data integrity proof.
pub trait PublicKey {
    /// Decode the verification method into raw public key bytes.
    fn get_public_key_bytes(&self) -> Result<Vec<u8>, DIDWebVHError>;
}

/// Enforces the didwebvh 1.0 shape constraints on a witness proof before
/// cryptographic verification: cryptosuite must be `eddsa-jcs-2022` (unless
/// the caller widened the allowed set via [`WitnessVerifyOptions`]), and
/// `proofPurpose` must be `assertionMethod`. Returns an error mentioning
/// the exact violation — the spec is unambiguous here, so silent acceptance
/// would hide real interop bugs.
///
/// [`WitnessVerifyOptions`]: crate::witness::WitnessVerifyOptions
pub(crate) fn enforce_witness_proof_shape(
    proof: &DataIntegrityProof,
    options: &crate::witness::WitnessVerifyOptions,
) -> Result<(), DIDWebVHError> {
    if !options.suite_is_allowed(proof.cryptosuite) {
        return Err(DIDWebVHError::WitnessProofError(format!(
            "witness proof uses cryptosuite {:?}, but the didwebvh 1.0 spec \
             requires eddsa-jcs-2022 (add to WitnessVerifyOptions::extra_allowed_suites \
             to accept non-spec suites explicitly)",
            proof.cryptosuite
        )));
    }
    if proof.proof_purpose != "assertionMethod" {
        return Err(DIDWebVHError::WitnessProofError(format!(
            "witness proof has proofPurpose '{}', but the didwebvh 1.0 spec \
             requires 'assertionMethod'",
            proof.proof_purpose
        )));
    }
    Ok(())
}

impl PublicKey for DataIntegrityProof {
    fn get_public_key_bytes(&self) -> Result<Vec<u8>, DIDWebVHError> {
        // Delegate to the upstream resolver: it knows every multicodec
        // registered for public keys (Ed25519, secp256k1, P-256/384/521,
        // and — with feature gates — the ML-DSA / SLH-DSA variants) and
        // validates the decoded length. Centralising the logic upstream
        // means new key types added in affinidi-data-integrity flow
        // through here without a didwebvh-rs patch.
        Ok(
            affinidi_data_integrity::did_vm::resolve_did_key(&self.verification_method)
                .map_err(|e| {
                    DIDWebVHError::InvalidMethodIdentifier(format!(
                        "could not resolve did:key verificationMethod: {e}"
                    ))
                })?
                .public_key_bytes,
        )
    }
}

/// Each version of the DID gets a new log entry
/// [Log Entries](https://identity.foundation/didwebvh/v1.0/#the-did-log-file)
#[non_exhaustive]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum LogEntry {
    /// Official v1.0 specification
    Spec1_0(LogEntry1_0),

    /// Interim 1.0 spec where nulls were used instead of empty arrays and objects
    Spec1_0Pre(LogEntry1_0Pre),
}

/// Common accessors shared by all log entry versions.
pub trait LogEntryMethods {
    /// LogEntry Parameters versionTime
    fn get_version_time_string(&self) -> String;

    /// LogEntry Parameters versionTime
    fn get_version_time(&self) -> DateTime<FixedOffset>;

    /// Returns the versionId for this log entry.
    fn get_version_id(&self) -> &str;

    /// Set the versionId to an updated value.
    fn set_version_id(&mut self, version_id: &str);

    /// Get Parameters
    fn get_parameters(&self) -> Parameters;

    /// Add a proof for this log entry.
    fn add_proof(&mut self, proof: DataIntegrityProof);

    /// Get proofs for this log entry.
    fn get_proofs(&self) -> &[DataIntegrityProof];

    /// Resets all proofs for this LogEntry
    fn clear_proofs(&mut self);

    /// Returns the SCID if present in this log entry's parameters.
    fn get_scid(&self) -> Option<&str>;

    /// Get the raw DID Document state
    /// Does NOT include implied services
    fn get_state(&self) -> &Value;

    /// Returns a full DID Document including implied services
    fn get_did_document(&self) -> Result<Value, DIDWebVHError>;
}

/// Where-ever we need to create a LogEntry across versions
pub(crate) trait LogEntryCreate {
    fn create(
        version_id: String,
        version_time: DateTime<FixedOffset>,
        parameters: Parameters,
        state: Value,
    ) -> Result<LogEntry, DIDWebVHError>;
}

/// Shared helper: serialize versionTime with seconds-only precision
pub(crate) fn format_version_time<S>(
    date: &DateTime<FixedOffset>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Shared helper: split a versionId into (number, hash)
pub fn parse_version_id_fields(version_id: &str) -> Result<(u32, String), DIDWebVHError> {
    let Some((id, hash)) = version_id.split_once('-') else {
        return Err(DIDWebVHError::ValidationError(format!(
            "versionID ({version_id}) doesn't match format <int>-<hash>",
        )));
    };
    let id = id.parse::<u32>().map_err(|e| {
        DIDWebVHError::ValidationError(format!("Failed to parse version ID ({id}) as u32: {e}",))
    })?;
    Ok((id, hash.to_string()))
}

/// Implements the common inherent methods and `LogEntryMethods` trait for a log entry struct.
///
/// The struct must have fields: `version_id`, `version_time`, `parameters`, `state`, `proof`.
/// The parameters type must implement `Into<Parameters>` and `Clone`.
macro_rules! impl_log_entry_common {
    ($type:ty) => {
        impl $type {
            /// Calculates a Log Entry hash
            pub fn generate_log_entry_hash(&self) -> Result<String, DIDWebVHError> {
                let jcs = serde_json_canonicalizer::to_string(self).map_err(|e| {
                    DIDWebVHError::SCIDError(format!(
                        "Couldn't generate JCS from LogEntry. Reason: {e}",
                    ))
                })?;
                tracing::debug!("JCS for LogEntry hash: {}", jcs);

                let digest = <sha2::Sha256 as sha2::Digest>::digest(jcs.as_bytes());
                let multihash_bytes = crate::log_entry::encode_sha256_multihash(digest.as_slice());
                Ok(base58::ToBase58::to_base58(multihash_bytes.as_slice()))
            }

            /// Verifies a witness data integrity proof against this log entry's versionId.
            pub fn validate_witness_proof(
                &self,
                witness_proof: &affinidi_data_integrity::DataIntegrityProof,
                options: &crate::witness::WitnessVerifyOptions,
            ) -> Result<bool, DIDWebVHError> {
                use crate::log_entry::PublicKey;
                crate::log_entry::enforce_witness_proof_shape(witness_proof, options)?;
                witness_proof
                    .verify_with_public_key(
                        &serde_json::json!({"versionId": &self.version_id}),
                        witness_proof.get_public_key_bytes()?.as_slice(),
                        affinidi_data_integrity::VerifyOptions::new(),
                    )
                    .map_err(|e| {
                        DIDWebVHError::LogEntryError(format!(
                            "Data Integrity Proof verification failed: {e}"
                        ))
                    })?;
                Ok(true)
            }

            /// Splits the version number and the version hash for a DID versionId
            pub fn get_version_id_fields(&self) -> Result<(u32, String), DIDWebVHError> {
                crate::log_entry::parse_version_id_fields(&self.version_id)
            }

            /// Splits the version number and the version hash for a DID versionId
            pub fn parse_version_id_fields(
                version_id: &str,
            ) -> Result<(u32, String), DIDWebVHError> {
                crate::log_entry::parse_version_id_fields(version_id)
            }
        }

        impl crate::log_entry::LogEntryMethods for $type {
            fn get_version_time_string(&self) -> String {
                self.version_time
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            }

            fn get_version_time(&self) -> chrono::DateTime<chrono::FixedOffset> {
                self.version_time
            }

            fn get_version_id(&self) -> &str {
                &self.version_id
            }

            fn set_version_id(&mut self, version_id: &str) {
                self.version_id = version_id.to_string();
            }

            fn get_parameters(&self) -> crate::parameters::Parameters {
                self.parameters.clone().into()
            }

            fn add_proof(&mut self, proof: affinidi_data_integrity::DataIntegrityProof) {
                self.proof.push(proof);
            }

            fn get_proofs(&self) -> &[affinidi_data_integrity::DataIntegrityProof] {
                &self.proof
            }

            fn clear_proofs(&mut self) {
                self.proof.clear();
            }

            fn get_scid(&self) -> Option<&str> {
                self.parameters.scid.as_deref().map(String::as_str)
            }

            fn get_state(&self) -> &serde_json::Value {
                &self.state
            }

            fn get_did_document(&self) -> Result<serde_json::Value, DIDWebVHError> {
                let services = self.state.get("service");
                let mut new_state = self.state.clone();
                if let Some(id) = self.state.get("id")
                    && let Some(id) = id.as_str()
                {
                    crate::resolve::implicit::update_implicit_services(
                        services, &mut new_state, id,
                    )?;
                    Ok(new_state)
                } else {
                    Err(DIDWebVHError::ValidationError(
                        "DID Document is missing 'id' field or it's not a string".to_string(),
                    ))
                }
            }
        }
    };
}

pub(crate) use impl_log_entry_common;

impl LogEntry {
    /// Reading in a LogEntry and converting it requires custom logic.
    /// `deserialize_string` handles detecting the version and deserializing the LogEntry correctly
    /// Attributes:
    /// - input: The input string to deserialize
    /// - version: If you want to override the default latest version, specify the previous
    ///   LogEntry version here
    pub fn deserialize_string(
        input: &str,
        version: Option<Version>,
    ) -> Result<LogEntry, DIDWebVHError> {
        // Step 1: Parse the String to generic JSON Values
        let values: Value = serde_json::from_str(input).map_err(|e| {
            DIDWebVHError::LogEntryError(format!("Couldn't deserialize LogEntry. Reason: {e}"))
        })?;

        // Step 2: Detect method version
        let version = if let Some(parameters) = values.get("parameters") {
            if let Some(method) = parameters.get("method") {
                if let Some(method) = method.as_str() {
                    Version::try_from(method).unwrap_or(version.unwrap_or_default())
                } else {
                    version.unwrap_or_default()
                }
            } else {
                version.unwrap_or_default()
            }
        } else {
            version.unwrap_or_default()
        };

        // Step 3: Deserialize using the LogEntry method version

        match version {
            Version::V1_0 => {
                // There is a pre-ratified difference in the v1.0 spec where nulls were used
                // instead of empty arrays and objects
                let Some(parameters) = values.get("parameters") else {
                    return Err(DIDWebVHError::LogEntryError(
                        "No parameters exist in the LogEntry!".to_string(),
                    ));
                };

                // Check if there are JSON nulls in the parameters
                let mut pre_version = false;
                if let Some(v) = parameters.get("updateKeys")
                    && v.is_null()
                {
                    pre_version = true;
                }
                if let Some(v) = parameters.get("nextKeyHashes")
                    && v.is_null()
                {
                    pre_version = true;
                }
                if let Some(v) = parameters.get("witness")
                    && v.is_null()
                {
                    pre_version = true;
                }
                if let Some(v) = parameters.get("watchers")
                    && v.is_null()
                {
                    pre_version = true;
                }
                if let Some(v) = parameters.get("ttl")
                    && v.is_null()
                {
                    pre_version = true;
                }

                if pre_version {
                    Ok(LogEntry::Spec1_0Pre(
                        serde_json::from_value::<LogEntry1_0Pre>(values).map_err(|e| {
                            DIDWebVHError::LogEntryError(format!("Failed to parse LogEntry: {e}"))
                        })?,
                    ))
                } else {
                    Ok(LogEntry::Spec1_0(
                        serde_json::from_value::<LogEntry1_0>(values).map_err(|e| {
                            DIDWebVHError::LogEntryError(format!("Failed to parse LogEntry: {e}"))
                        })?,
                    ))
                }
            }
            _ => Err(DIDWebVHError::LogEntryError(format!(
                "Version ({version}) is not supported!"
            ))),
        }
    }

    /// Get the WebVH Specification version for this LogEntry
    pub fn get_webvh_version(&self) -> Version {
        match self {
            LogEntry::Spec1_0(_) => Version::V1_0,
            LogEntry::Spec1_0Pre(_) => Version::V1_0Pre,
        }
    }

    /// Converts a string into the correct version when version is known
    pub fn from_string_to_known_version(
        input: &str,
        version: Version,
    ) -> Result<LogEntry, DIDWebVHError> {
        match version {
            Version::V1_0 => serde_json::from_str::<LogEntry1_0>(input)
                .map(LogEntry::Spec1_0)
                .map_err(|e| {
                    DIDWebVHError::LogEntryError(format!("Failed to parse LogEntry: {e}"))
                }),
            Version::V1_0Pre => serde_json::from_str::<LogEntry1_0Pre>(input)
                .map(LogEntry::Spec1_0Pre)
                .map_err(|e| {
                    DIDWebVHError::LogEntryError(format!("Failed to parse LogEntry: {e}"))
                }),
        }
    }

    /// Append a valid LogEntry to a file
    pub fn save_to_file(&self, file_path: &str) -> Result<(), DIDWebVHError> {
        let append = if self.get_version_id_fields()?.0 == 1 {
            false // Don't append to the file if this is the first version
        } else {
            true // Append to the file for all subsequent versions
        };

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(!append)
            .append(append)
            .open(file_path)
            .map_err(|e| {
                DIDWebVHError::LogEntryError(format!("Couldn't open file {file_path}: {e}"))
            })?;

        file.write_all(
            serde_json::to_string(self)
                .map_err(|e| {
                    DIDWebVHError::LogEntryError(format!(
                        "Couldn't serialize LogEntry to JSON. Reason: {e}",
                    ))
                })?
                .as_bytes(),
        )
        .map_err(|e| {
            DIDWebVHError::LogEntryError(format!(
                "Couldn't append LogEntry to file({file_path}). Reason: {e}",
            ))
        })?;
        file.write_all("\n".as_bytes()).map_err(|e| {
            DIDWebVHError::LogEntryError(format!(
                "Couldn't append LogEntry to file({file_path}). Reason: {e}",
            ))
        })?;

        Ok(())
    }

    /// Generates a SCID from a preliminary LogEntry
    /// This only needs to be called once when the DID is first created.
    pub(crate) fn generate_first_scid(&self) -> Result<String, DIDWebVHError> {
        self.generate_log_entry_hash().map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate SCID from preliminary LogEntry. Reason: {e}",
            ))
        })
    }

    /// Calculates a Log Entry hash
    pub fn generate_log_entry_hash(&self) -> Result<String, DIDWebVHError> {
        let jcs = to_string(self).map_err(|e| {
            DIDWebVHError::SCIDError(format!("Couldn't generate JCS from LogEntry. Reason: {e}",))
        })?;
        debug!("JCS for LogEntry hash: {}", jcs);

        let digest = Sha256::digest(jcs.as_bytes());
        let multihash_bytes = encode_sha256_multihash(digest.as_slice());
        Ok(multihash_bytes.to_base58())
    }

    /// Validates a witness proof against the log entry
    pub fn validate_witness_proof(
        &self,
        witness_proof: &DataIntegrityProof,
        options: &crate::witness::WitnessVerifyOptions,
    ) -> Result<bool, DIDWebVHError> {
        enforce_witness_proof_shape(witness_proof, options)?;
        // Verify the Data Integrity Proof against the Signing Document
        witness_proof
            .verify_with_public_key(
                &json!({"versionId": self.get_version_id()}),
                witness_proof.get_public_key_bytes()?.as_slice(),
                VerifyOptions::new(),
            )
            .map_err(|e| {
                DIDWebVHError::LogEntryError(format!(
                    "Data Integrity Proof verification failed: {e}"
                ))
            })?;

        Ok(true)
    }

    /// Splits the version number and the version hash for a DID versionId
    pub fn get_version_id_fields(&self) -> Result<(u32, String), DIDWebVHError> {
        match self {
            LogEntry::Spec1_0(log_entry) => parse_version_id_fields(&log_entry.version_id),
            LogEntry::Spec1_0Pre(log_entry) => parse_version_id_fields(&log_entry.version_id),
        }
    }

    /// Splits the version number and the version hash for a DID versionId
    pub fn parse_version_id_fields(version_id: &str) -> Result<(u32, String), DIDWebVHError> {
        parse_version_id_fields(version_id)
    }

    /// Create a new LogEntry depending on the WebVH Version
    pub(crate) fn create(
        version_id: String,
        version_time: DateTime<FixedOffset>,
        parameters: Parameters,
        state: Value,
        webvh_version: Version,
    ) -> Result<LogEntry, DIDWebVHError> {
        match webvh_version {
            Version::V1_0 => LogEntry1_0::create(version_id, version_time, parameters, state),
            Version::V1_0Pre => Err(DIDWebVHError::LogEntryError(
                "WebVH Version must be 1.0 or higher".to_string(),
            )),
        }
    }
}

impl LogEntryMethods for LogEntry {
    fn get_version_time_string(&self) -> String {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_version_time_string(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_version_time_string(),
        }
    }

    fn get_version_id(&self) -> &str {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_version_id(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_version_id(),
        }
    }

    fn set_version_id(&mut self, version_id: &str) {
        match self {
            LogEntry::Spec1_0(log_entry) => {
                log_entry.set_version_id(version_id);
            }
            LogEntry::Spec1_0Pre(log_entry) => {
                log_entry.set_version_id(version_id);
            }
        }
    }

    fn get_parameters(&self) -> Parameters {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_parameters(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_parameters(),
        }
    }

    fn add_proof(&mut self, proof: DataIntegrityProof) {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.add_proof(proof),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.add_proof(proof),
        }
    }

    fn get_proofs(&self) -> &[DataIntegrityProof] {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_proofs(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_proofs(),
        }
    }

    fn clear_proofs(&mut self) {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.clear_proofs(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.clear_proofs(),
        }
    }

    fn get_scid(&self) -> Option<&str> {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_scid(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_scid(),
        }
    }

    fn get_version_time(&self) -> DateTime<FixedOffset> {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_version_time(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_version_time(),
        }
    }

    fn get_state(&self) -> &Value {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_state(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_state(),
        }
    }

    fn get_did_document(&self) -> Result<Value, DIDWebVHError> {
        match self {
            LogEntry::Spec1_0(log_entry) => log_entry.get_did_document(),
            LogEntry::Spec1_0Pre(log_entry) => log_entry.get_did_document(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Version, parameters::spec_1_0::Parameters1_0};
    use affinidi_data_integrity::{DataIntegrityProof, crypto_suites::CryptoSuite};
    use chrono::Utc;
    use serde_json::json;

    // ===== PublicKey trait tests =====

    /// Tests that extracting a public key from a proof whose verification method
    /// does not start with "did:key:" returns an error.
    /// Expected: Returns an error mentioning "did:key:".
    /// This matters because WebVH log entry proofs must use did:key verification
    /// methods; rejecting other DID methods prevents invalid key extraction.
    #[test]
    fn test_public_key_not_did_key_error() {
        let proof = DataIntegrityProof {
            type_: "test".to_string(),
            created: None,
            context: None,
            cryptosuite: CryptoSuite::EddsaJcs2022,
            proof_purpose: "test".to_string(),
            proof_value: None,
            verification_method: "did:web:example.com#key-1".to_string(),
        };
        let err = proof.get_public_key_bytes().unwrap_err();
        assert!(err.to_string().contains("did:key:"));
    }

    /// Tests that a did:key verification method missing the fragment separator (#)
    /// returns an "Invalid verification method" error.
    /// Expected: Returns an error indicating the verification method format is invalid.
    /// This matters because the public key is extracted from the fragment portion
    /// after the '#'; without it, key extraction cannot proceed safely.
    #[test]
    fn test_public_key_missing_hash_error() {
        let proof = DataIntegrityProof {
            type_: "test".to_string(),
            created: None,
            context: None,
            cryptosuite: CryptoSuite::EddsaJcs2022,
            proof_purpose: "test".to_string(),
            proof_value: None,
            verification_method: "did:key:z6MktestNoHash".to_string(),
        };
        let err = proof.get_public_key_bytes().unwrap_err();
        // resolve_did_key fails to decode the multibase body because
        // "z6MktestNoHash" is not a valid base58btc multicodec payload.
        assert!(
            matches!(err, DIDWebVHError::InvalidMethodIdentifier(_)),
            "expected InvalidMethodIdentifier, got {err:?}"
        );
    }

    /// Tests that a well-formed did:key verification method with a valid ed25519
    /// multikey successfully extracts non-empty public key bytes.
    /// Expected: Returns a non-empty byte vector representing the public key.
    /// This matters because valid key extraction is the prerequisite for
    /// verifying data integrity proofs on log entries.
    #[test]
    fn test_public_key_valid() {
        // Use a real ed25519 multikey
        let secret = affinidi_secrets_resolver::secrets::Secret::generate_ed25519(None, None);
        let pk = secret.get_public_keymultibase().unwrap();
        let proof = DataIntegrityProof {
            type_: "test".to_string(),
            created: None,
            context: None,
            cryptosuite: CryptoSuite::EddsaJcs2022,
            proof_purpose: "assertionMethod".to_string(),
            proof_value: None,
            verification_method: format!("did:key:{pk}#{pk}"),
        };
        let bytes = proof.get_public_key_bytes().unwrap();
        assert!(!bytes.is_empty());
    }

    // ===== deserialize_string() tests =====

    /// Tests that deserializing a non-JSON string returns an error.
    /// Expected: Returns a deserialization error.
    /// This matters because log entries are transmitted as JSON; malformed input
    /// must be caught early to prevent downstream processing of invalid data.
    #[test]
    fn test_deserialize_invalid_json_error() {
        let result = LogEntry::deserialize_string("not json", None);
        assert!(result.is_err());
    }

    /// Tests that valid JSON lacking a "parameters" field fails deserialization
    /// for the V1_0 spec variant.
    /// Expected: Returns an error because the parameters block is required.
    /// This matters because every WebVH log entry must carry parameters (method,
    /// scid, updateKeys, etc.) to be a valid entry in the DID log.
    #[test]
    fn test_deserialize_missing_parameters_error() {
        // Valid JSON but no parameters field — for V1_0, it checks for parameters
        let json = r#"{"versionId":"1-abc","versionTime":"2024-01-01T00:00:00Z","state":{}}"#;
        let result = LogEntry::deserialize_string(json, None);
        assert!(result.is_err());
    }

    /// Tests that a properly serialized Spec1_0 log entry round-trips through
    /// deserialize_string and is recognized as the Spec1_0 variant.
    /// Expected: Returns Ok with a LogEntry::Spec1_0 variant.
    /// This matters because correct version detection ensures log entries are
    /// parsed with the right schema, maintaining interoperability.
    #[test]
    fn test_deserialize_v1_0_ok() {
        let json = serde_json::to_string(&LogEntry::Spec1_0(LogEntry1_0 {
            version_id: "1-abc".to_string(),
            version_time: Utc::now().fixed_offset(),
            parameters: Parameters1_0::default(),
            state: json!({"id": "did:webvh:scid:example.com"}),
            proof: vec![],
        }))
        .unwrap();
        let result = LogEntry::deserialize_string(&json, None).unwrap();
        assert!(matches!(result, LogEntry::Spec1_0(_)));
    }

    /// Tests that JSON with null-valued parameter fields (e.g. "updateKeys": null)
    /// is detected as the pre-ratification Spec1_0Pre variant rather than Spec1_0.
    /// Expected: Returns Ok with a LogEntry::Spec1_0Pre variant.
    /// This matters because the pre-ratified spec used JSON nulls instead of empty
    /// arrays/objects; distinguishing the two ensures backward compatibility with
    /// DIDs created before the spec was finalized.
    #[test]
    fn test_deserialize_detects_pre_version_nulls() {
        // JSON with null values in parameters should trigger Spec1_0Pre
        let json = r#"{"versionId":"1-abc","versionTime":"2024-01-01T00:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"test","updateKeys":null},"state":{}}"#;
        let result = LogEntry::deserialize_string(json, None).unwrap();
        assert!(matches!(result, LogEntry::Spec1_0Pre(_)));
    }

    // ===== from_string_to_known_version() tests =====

    /// Tests that from_string_to_known_version correctly parses a string as
    /// the Spec1_0 variant when Version::V1_0 is explicitly specified.
    /// Expected: Returns Ok with a LogEntry::Spec1_0 variant.
    /// This matters because when the version is already known (e.g. from a
    /// previous log entry), skipping auto-detection is more efficient and avoids
    /// ambiguity.
    #[test]
    fn test_from_string_v1_0() {
        let json = serde_json::to_string(&LogEntry::Spec1_0(LogEntry1_0 {
            version_id: "1-abc".to_string(),
            version_time: Utc::now().fixed_offset(),
            parameters: Parameters1_0::default(),
            state: json!({}),
            proof: vec![],
        }))
        .unwrap();
        let result = LogEntry::from_string_to_known_version(&json, Version::V1_0).unwrap();
        assert!(matches!(result, LogEntry::Spec1_0(_)));
    }

    /// Tests that from_string_to_known_version correctly parses a string with
    /// null-valued parameters as the Spec1_0Pre variant when Version::V1_0Pre
    /// is explicitly specified.
    /// Expected: Returns Ok with a LogEntry::Spec1_0Pre variant.
    /// This matters because pre-ratified log entries use a different serialization
    /// format (nulls vs empty collections) and must be parsed with the correct
    /// deserializer to avoid data loss.
    #[test]
    fn test_from_string_v1_0_pre() {
        // Spec1_0Pre uses null serialization, construct manually
        let json = r#"{"versionId":"1-abc","versionTime":"2024-01-01T00:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"test","updateKeys":null,"nextKeyHashes":null,"witness":null,"watchers":null,"deactivated":null,"ttl":null},"state":{}}"#;
        let result = LogEntry::from_string_to_known_version(json, Version::V1_0Pre).unwrap();
        assert!(matches!(result, LogEntry::Spec1_0Pre(_)));
    }

    // ===== get_did_document() tests =====

    /// Tests that get_did_document adds implicit services (whois, files) alongside
    /// any explicit services defined in the DID document state.
    /// Expected: The returned document contains 3 services (1 custom + 2 implicit).
    /// This matters because the WebVH spec requires certain implied services to be
    /// present in the resolved DID document even when they are not stored in the
    /// log entry state.
    #[test]
    fn test_get_did_document_with_services() {
        let entry = LogEntry::Spec1_0(LogEntry1_0 {
            version_id: "1-abc".to_string(),
            version_time: Utc::now().fixed_offset(),
            parameters: Parameters1_0::default(),
            state: json!({
                "id": "did:webvh:scid123:example.com",
                "service": [{
                    "id": "did:webvh:scid123:example.com#custom",
                    "type": "Custom",
                    "serviceEndpoint": "https://example.com"
                }]
            }),
            proof: vec![],
        });
        let doc = entry.get_did_document().unwrap();
        let services = doc["service"].as_array().unwrap();
        // Should have original + whois + files = 3
        assert_eq!(services.len(), 3);
    }

    /// Tests that get_did_document returns an error when the DID document state
    /// is missing the required "id" field.
    /// Expected: Returns an error referencing the missing "id".
    /// This matters because the DID document id is essential for constructing
    /// implied service endpoints; without it, the document cannot be resolved.
    #[test]
    fn test_get_did_document_missing_id_error() {
        let entry = LogEntry::Spec1_0(LogEntry1_0 {
            version_id: "1-abc".to_string(),
            version_time: Utc::now().fixed_offset(),
            parameters: Parameters1_0::default(),
            state: json!({"noId": true}),
            proof: vec![],
        });
        let err = entry.get_did_document().unwrap_err();
        assert!(err.to_string().contains("id"));
    }

    // ===== save_to_file() and generate_log_entry_hash() tests =====

    /// Tests that a log entry can be saved to a JSONL file and loaded back with
    /// identical content, verifying the file I/O round-trip.
    /// Expected: The loaded entry has the same versionId and exactly one entry.
    /// This matters because the DID log file is the persistent representation of
    /// all version history; data must survive serialization without corruption.
    #[test]
    fn test_save_and_load_roundtrip() {
        let entry = LogEntry::Spec1_0(LogEntry1_0 {
            version_id: "1-abc".to_string(),
            version_time: Utc::now().fixed_offset(),
            parameters: Parameters1_0::default(),
            state: json!({"id": "did:webvh:scid:example.com"}),
            proof: vec![],
        });
        let unique_name = format!(
            "didwebvh_test_save_roundtrip_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique_name);
        let path_str = path.to_str().unwrap();
        entry.save_to_file(path_str).unwrap();
        let loaded = LogEntry::load_from_file(path_str).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].get_version_id(), "1-abc");
        let _ = std::fs::remove_file(path);
    }

    /// Tests that generate_log_entry_hash produces the same hash when called
    /// multiple times on the same log entry.
    /// Expected: Two consecutive hash calls return identical strings.
    /// This matters because the entry hash is used in the versionId and SCID;
    /// non-deterministic hashing would make log entry verification impossible.
    #[test]
    fn test_generate_hash_deterministic() {
        let entry = LogEntry::Spec1_0(LogEntry1_0 {
            version_id: "1-abc".to_string(),
            version_time: Utc::now().fixed_offset(),
            parameters: Parameters1_0::default(),
            state: json!({"id": "did:webvh:scid:example.com"}),
            proof: vec![],
        });
        let hash1 = entry.generate_log_entry_hash().unwrap();
        let hash2 = entry.generate_log_entry_hash().unwrap();
        assert_eq!(hash1, hash2);
    }

    // ===== create() tests =====

    /// Tests that attempting to create a new log entry with the pre-ratification
    /// version (V1_0Pre) returns an error.
    /// Expected: Returns an error indicating version must be 1.0 or higher.
    /// This matters because new DIDs must only be created using the ratified spec;
    /// the pre-ratification format exists solely for backward-compatible reading.
    #[test]
    fn test_create_v1_0_pre_error() {
        let result = LogEntry::create(
            "1-test".to_string(),
            Utc::now().fixed_offset(),
            Parameters::default(),
            json!({}),
            Version::V1_0Pre,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("1.0 or higher"));
    }

    // ===== parse_version_id_fields() tests =====

    /// Tests that a well-formed versionId string "3-abc123" is correctly split
    /// into the numeric version (3) and the hash component ("abc123").
    /// Expected: Returns (3, "abc123").
    /// This matters because the versionId encodes both the sequence number and
    /// the entry hash; correct parsing is required for version chain validation.
    #[test]
    fn test_parse_version_id_valid() {
        let (num, hash) = parse_version_id_fields("3-abc123").unwrap();
        assert_eq!(num, 3);
        assert_eq!(hash, "abc123");
    }

    /// Tests that a versionId string without a dash separator returns an error.
    /// Expected: Returns an error referencing "versionID" format.
    /// This matters because the "<number>-<hash>" format is mandated by the spec;
    /// strings that do not follow this pattern indicate a corrupted or malformed log.
    #[test]
    fn test_parse_version_id_missing_dash() {
        let err = parse_version_id_fields("noDash").unwrap_err();
        assert!(err.to_string().contains("versionID"));
    }

    /// Tests that a versionId whose numeric portion is not a valid u32 returns
    /// an error.
    /// Expected: Returns an error about failing to parse the version ID.
    /// This matters because the version number must be a positive integer for
    /// sequential ordering of log entries; non-numeric values break chain validation.
    #[test]
    fn test_parse_version_id_non_numeric() {
        let err = parse_version_id_fields("abc-hash").unwrap_err();
        assert!(err.to_string().contains("Failed to parse version ID"));
    }

    // ===== get_webvh_version() test =====

    /// Tests that get_webvh_version correctly reports Version::V1_0 for a
    /// Spec1_0 log entry variant.
    /// Expected: Returns Version::V1_0.
    /// This matters because the version tag determines which serialization rules
    /// and validation logic apply when processing subsequent log entries.
    #[test]
    fn test_get_webvh_version() {
        let entry_1_0 = LogEntry::Spec1_0(LogEntry1_0 {
            version_id: "1-abc".to_string(),
            version_time: Utc::now().fixed_offset(),
            parameters: Parameters1_0::default(),
            state: json!({}),
            proof: vec![],
        });
        assert_eq!(entry_1_0.get_webvh_version(), Version::V1_0);
    }
}
