use std::sync::Arc;

use crate::ConfigInfo;
use affinidi_data_integrity::DataIntegrityProof;
use anyhow::{Result, bail};
use console::style;
use didwebvh_rs::{
    DIDWebVHError,
    log_entry_state::LogEntryState,
    witness::{Witnesses, proofs::WitnessProofCollection},
};
use serde_json::json;

/// Witnesses a LogEntry with the active LogEntries
pub fn witness_log_entry(
    witness_proofs: &mut WitnessProofCollection,
    log_entry: &LogEntryState,
    witnesses: &Option<Arc<Witnesses>>,
    secrets: &ConfigInfo,
) -> Result<Option<()>> {
    let Some(witnesses) = witnesses else {
        println!(
            "{}",
            style("Witnesses are not being used for this LogEntry. No witnessing is required")
                .color256(69)
        );
        return Ok(None);
    };

    let (threshold, witness_nodes) = match &**witnesses {
        Witnesses::Value {
            threshold,
            witnesses,
        } => (threshold, witnesses),
        _ => bail!("No valid witness paremeter config found!"),
    };

    println!(
        "{}{}{}",
        style("Witnessing enabled. Requires at least (").color256(69),
        style(threshold).color256(45),
        style(") proofs from witnesses").color256(69)
    );

    for witness in witness_nodes {
        // Get secret for Witness
        let Some(secret) = secrets.witnesses.get(&witness.id) else {
            bail!("Couldn't find secret for witness ({})!", witness.id)
        };

        // Generate Signature
        let proof = DataIntegrityProof::sign_jcs_data(
            &json!({"versionId": &log_entry.get_version_id()}),
            None,
            secret,
            None,
        )
        .map_err(|e| {
            DIDWebVHError::SCIDError(format!(
                "Couldn't generate Data Integrity Proof for LogEntry. Reason: {e}",
            ))
        })?;

        // Save proof to collection
        witness_proofs
            .add_proof(&log_entry.get_version_id(), &proof, false)
            .map_err(|e| DIDWebVHError::WitnessProofError(format!("Error adding proof: {e}",)))?;

        println!(
            "{}{}{}{}{}",
            style("Witness (").color256(69),
            style(&witness.id).color256(45),
            style("): Successfully witnessed LogEntry (").color256(69),
            style(&log_entry.get_version_id()).color256(45),
            style(")").color256(69),
        );
    }
    // Strip out any duplicate records where we can
    witness_proofs.write_optimise_records()?;

    println!(
        "{}{}{}{}",
        style("Witnessing completed: ").color256(69),
        style(witness_proofs.get_proof_count(&log_entry.get_version_id())).color256(45),
        style("/").color256(69),
        style(threshold).color256(45),
    );

    Ok(Some(()))
}
