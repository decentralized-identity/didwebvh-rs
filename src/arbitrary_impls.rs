//! Hand-written [`arbitrary::Arbitrary`] implementations for the log-entry
//! types.
//!
//! The leaf types (`Version`, `Multibase`, `Witness`, `Witnesses`,
//! `Parameters`, `Parameters1_0`, `Parameters1_0Pre`) derive `Arbitrary`
//! directly. The `LogEntry*` types can't: they carry fields whose types live
//! in foreign crates (`chrono::DateTime`, `serde_json::Value`,
//! `affinidi_data_integrity::DataIntegrityProof`), so the orphan rule forbids
//! both `derive` and a blanket `impl Arbitrary for DateTime<…>`. Instead we
//! implement `Arbitrary` for our own log-entry structs and build the foreign
//! fields here with bounded local helpers.
//!
//! Design notes for fuzzing:
//! - `state` is a *bounded* arbitrary JSON value (capped depth/width). It is
//!   hashed into the entry hash / SCID, so we want it to vary — but unbounded
//!   recursion would let the fuzzer spend its budget building giant trees
//!   instead of exploring the verifier.
//! - `proof` is built from arbitrary parts (via the public
//!   [`DataIntegrityProof::new`]). Arbitrary bytes will essentially never form
//!   a valid signature, so this exercises the *structural* proof path
//!   (`enforce_witness_proof_shape`, did:key resolution, cryptosuite gating)
//!   that runs before signature crypto. Harnesses that need valid-then-tampered
//!   proofs should sign with controlled keys instead.
//!
//! All of this is gated behind the off-by-default `arbitrary` feature.

use affinidi_data_integrity::{DataIntegrityProof, crypto_suites::CryptoSuite};
use arbitrary::{Arbitrary, Unstructured};
use chrono::{DateTime, FixedOffset};
use serde_json::{Map, Number, Value};

use crate::log_entry::{LogEntry, spec_1_0::LogEntry1_0, spec_1_0_pre::LogEntry1_0Pre};

/// Maximum nesting depth for a generated `state` JSON value.
const JSON_MAX_DEPTH: u32 = 3;
/// Maximum element count for a generated JSON array or object.
const JSON_MAX_WIDTH: usize = 4;
/// Maximum number of proofs attached to a generated log entry.
const MAX_PROOFS: usize = 3;
/// One second short of year 10000 — the upper bound chrono can represent.
const MAX_EPOCH_SECS: i64 = 253_402_300_799;

/// Build a `DateTime<FixedOffset>` from arbitrary bytes, bounded to chrono's
/// representable range so construction never fails.
fn arbitrary_datetime(u: &mut Unstructured) -> arbitrary::Result<DateTime<FixedOffset>> {
    let secs = u.arbitrary::<i64>()?.rem_euclid(MAX_EPOCH_SECS);
    // FixedOffset is valid in (-86_400, 86_400) seconds.
    let offset_secs = (u.arbitrary::<i32>()? % 86_400).clamp(-86_399, 86_399);
    let offset =
        FixedOffset::east_opt(offset_secs).unwrap_or_else(|| FixedOffset::east_opt(0).unwrap());
    let utc = DateTime::from_timestamp(secs, 0)
        .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());
    Ok(utc.with_timezone(&offset))
}

/// A single JSON scalar (no recursion).
fn arbitrary_json_scalar(u: &mut Unstructured) -> arbitrary::Result<Value> {
    Ok(match u.int_in_range(0u8..=3)? {
        0 => Value::Null,
        1 => Value::Bool(u.arbitrary()?),
        2 => Value::Number(Number::from(u.arbitrary::<i64>()?)),
        _ => Value::String(u.arbitrary()?),
    })
}

/// A bounded arbitrary JSON value. `depth` caps nesting; once it hits zero (or
/// the input is exhausted) only scalars are produced.
fn arbitrary_json(u: &mut Unstructured, depth: u32) -> arbitrary::Result<Value> {
    if depth == 0 || u.is_empty() {
        return arbitrary_json_scalar(u);
    }
    match u.int_in_range(0u8..=5)? {
        0..=3 => arbitrary_json_scalar(u),
        4 => {
            let len = u.int_in_range(0..=JSON_MAX_WIDTH)?;
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(arbitrary_json(u, depth - 1)?);
            }
            Ok(Value::Array(arr))
        }
        _ => {
            let len = u.int_in_range(0..=JSON_MAX_WIDTH)?;
            let mut map = Map::new();
            for _ in 0..len {
                map.insert(u.arbitrary::<String>()?, arbitrary_json(u, depth - 1)?);
            }
            Ok(Value::Object(map))
        }
    }
}

/// Pick a cryptosuite the verifier will actually encounter. Only the two
/// always-compiled suites are used; the PQC/BBS variants are upstream
/// feature-gated and not relevant to the spec witness path.
fn arbitrary_cryptosuite(u: &mut Unstructured) -> arbitrary::Result<CryptoSuite> {
    Ok(if u.arbitrary()? {
        CryptoSuite::EddsaJcs2022
    } else {
        CryptoSuite::EddsaRdfc2022
    })
}

/// Build a single arbitrary `DataIntegrityProof` from its public parts.
fn arbitrary_proof(u: &mut Unstructured) -> arbitrary::Result<DataIntegrityProof> {
    Ok(DataIntegrityProof::new(
        arbitrary_cryptosuite(u)?,
        u.arbitrary::<String>()?,              // verification_method
        u.arbitrary::<String>()?,              // proof_purpose
        u.arbitrary::<Option<String>>()?,      // proof_value
        u.arbitrary::<Option<String>>()?,      // created
        u.arbitrary::<Option<Vec<String>>>()?, // context
    ))
}

/// Build a bounded vector of arbitrary proofs.
fn arbitrary_proofs(u: &mut Unstructured) -> arbitrary::Result<Vec<DataIntegrityProof>> {
    let len = u.int_in_range(0..=MAX_PROOFS)?;
    let mut proofs = Vec::with_capacity(len);
    for _ in 0..len {
        proofs.push(arbitrary_proof(u)?);
    }
    Ok(proofs)
}

impl<'a> Arbitrary<'a> for LogEntry1_0 {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(LogEntry1_0 {
            version_id: u.arbitrary()?,
            version_time: arbitrary_datetime(u)?,
            parameters: u.arbitrary()?,
            state: arbitrary_json(u, JSON_MAX_DEPTH)?,
            proof: arbitrary_proofs(u)?,
        })
    }
}

impl<'a> Arbitrary<'a> for LogEntry1_0Pre {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(LogEntry1_0Pre {
            version_id: u.arbitrary()?,
            version_time: arbitrary_datetime(u)?,
            parameters: u.arbitrary()?,
            state: arbitrary_json(u, JSON_MAX_DEPTH)?,
            proof: arbitrary_proofs(u)?,
        })
    }
}

impl<'a> Arbitrary<'a> for LogEntry {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(if u.arbitrary()? {
            LogEntry::Spec1_0(u.arbitrary()?)
        } else {
            LogEntry::Spec1_0Pre(u.arbitrary()?)
        })
    }
}
