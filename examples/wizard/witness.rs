use crate::ConfigInfo;
use anyhow::Result;
use console::style;
use didwebvh_rs::{
    log_entry_state::LogEntryState,
    witness::{Witnesses, proofs::WitnessProofCollection},
};
use std::sync::Arc;

/// Witnesses a LogEntry with the active LogEntries
pub fn witness_log_entry(
    witness_proofs: &mut WitnessProofCollection,
    log_entry: &LogEntryState,
    witnesses: &Option<Arc<Witnesses>>,
    secrets: &ConfigInfo,
) -> Result<Option<()>> {
    let Some(witnesses_ref) = witnesses else {
        println!(
            "{}",
            style("Witnesses are not being used for this LogEntry. No witnessing is required")
                .color256(69)
        );
        return Ok(None);
    };

    let threshold = match &**witnesses_ref {
        Witnesses::Value { threshold, .. } => threshold,
        _ => {
            anyhow::bail!("No valid witness paremeter config found!");
        }
    };

    println!(
        "{}{}{}",
        style("Witnessing enabled. Requires at least (").color256(69),
        style(threshold).color256(45),
        style(") proofs from witnesses").color256(69)
    );

    let signed = didwebvh_rs::create::sign_witness_proofs(
        witness_proofs,
        log_entry,
        witnesses,
        &secrets.witnesses,
    )?;

    if signed {
        println!(
            "{}{}{}{}",
            style("Witnessing completed: ").color256(69),
            style(witness_proofs.get_proof_count(&log_entry.get_version_id())).color256(45),
            style("/").color256(69),
            style(threshold).color256(45),
        );
        Ok(Some(()))
    } else {
        Ok(None)
    }
}
