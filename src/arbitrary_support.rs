//! Custom [`arbitrary::Arbitrary`] generators for fields whose types live in
//! foreign crates and so cannot derive `Arbitrary` directly.
//!
//! Only compiled with the off-by-default `arbitrary` feature. These are wired
//! into the `LogEntry1_0` / `LogEntry1_0Pre` derives via
//! `#[arbitrary(with = ...)]` so the whole log-entry / parameters graph can be
//! generated structurally for coverage-guided fuzzing of the chain verifier.
//!
//! See the `fuzz_validate` example for how to drive `DIDWebVHState::validate()`
//! from a `&[u8]` slice.

use affinidi_data_integrity::DataIntegrityProof;
use arbitrary::{Arbitrary, Result, Unstructured};
use chrono::{DateTime, FixedOffset};
use serde_json::{Map, Number, Value};

/// Generate a plausible `versionTime`.
///
/// chrono's `DateTime` does not implement `Arbitrary`, and the verifier only
/// cares that timestamps parse and order monotonically, so we draw a Unix
/// second in `[0, 2100-01-01)` and convert to a fixed-offset (UTC) datetime.
pub fn arb_version_time(u: &mut Unstructured) -> Result<DateTime<FixedOffset>> {
    // 0 ..= 2100-01-01T00:00:00Z
    let secs = u.int_in_range(0i64..=4_102_444_800)?;
    let dt = DateTime::from_timestamp(secs, 0).unwrap_or_default();
    Ok(dt.fixed_offset())
}

/// Generate a bounded, recursive `serde_json::Value` for the DID-document
/// `state` field.
///
/// Depth is capped so the fuzzer spends its budget on the chain logic rather
/// than on pathologically deep JSON, and so generation terminates.
pub fn arb_json_value(u: &mut Unstructured) -> Result<Value> {
    arb_json_value_depth(u, 4)
}

fn arb_json_value_depth(u: &mut Unstructured, depth: u32) -> Result<Value> {
    // At max depth, only emit scalars so recursion always terminates.
    if depth == 0 {
        return Ok(Value::String(String::arbitrary(u)?));
    }

    match u.int_in_range(0u8..=5)? {
        0 => Ok(Value::Null),
        1 => Ok(Value::Bool(bool::arbitrary(u)?)),
        2 => Ok(Value::Number(Number::from(i64::arbitrary(u)?))),
        3 => Ok(Value::String(String::arbitrary(u)?)),
        4 => {
            let len = u.int_in_range(0usize..=4)?;
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(arb_json_value_depth(u, depth - 1)?);
            }
            Ok(Value::Array(arr))
        }
        _ => {
            let len = u.int_in_range(0usize..=4)?;
            let mut map = Map::with_capacity(len);
            for _ in 0..len {
                map.insert(String::arbitrary(u)?, arb_json_value_depth(u, depth - 1)?);
            }
            Ok(Value::Object(map))
        }
    }
}

/// Generate the `proof` vector for a log entry.
///
/// `affinidi_data_integrity::DataIntegrityProof` lives in a foreign crate and
/// has no `Arbitrary` impl, and a *valid* proof requires signing the canonical
/// log-entry bytes — which can only be done after the rest of the entry is
/// built. We therefore emit an empty proof set here; a fuzz harness that wants
/// to exercise the signature-verification path should sign the generated entry
/// itself (or mutate a seed-corpus entry that already carries proofs).
///
/// This still exercises everything up to and including the "is a proof
/// present / does it authorize this update" gate, plus all of SCID derivation,
/// entry-hash linkage, and parameter-transition validation.
pub fn arb_no_proofs(_u: &mut Unstructured) -> Result<Vec<DataIntegrityProof>> {
    Ok(Vec::new())
}
