/*!
*   Validating LogEntries using Witness Proofs
*/

use crate::{
    DIDWebVHError, log_entry_state::LogEntryState, witness::proofs::WitnessProofCollection,
};
use tracing::{debug, warn};

impl WitnessProofCollection {
    /// Validates if a LogEntry was correctly witnessed
    /// highest_version_number is required so we don't mistakenly use future witness proofs
    /// for unpublished LogEntries
    pub fn validate_log_entry(
        &mut self,
        log_entry: &LogEntryState,
        highest_version_number: u32,
    ) -> Result<(), DIDWebVHError> {
        // Determine witnesses for this LogEntry
        let Some(witnesses) = &log_entry.validated_parameters.active_witness else {
            // There are no active witnesses for this LogEntry
            return Ok(());
        };

        let Some(witness_nodes) = witnesses.witnesses() else {
            // There are no active witnesses for this LogEntry
            return Ok(());
        };

        // Get the version_number for this LogEntry
        let version_number = log_entry.log_entry.get_version_id_fields()?.0;

        // For each witness, check if there is a proof available
        let mut valid_proofs = 0;
        for w in witness_nodes {
            let key = w.id.split_at(8);
            let Some((_, oldest_id, proof)) =
                self.witness_version.get(&[&w.id, "#", key.1].concat())
            else {
                // No proof available for this witness, threshold will catch if too few proofs
                debug!("No Witness proofs exist for witness ({})", w.id);
                continue;
            };

            debug!(
                "oldest_id ({}) >  highest_version_number ({})",
                oldest_id, highest_version_number
            );
            if oldest_id > &highest_version_number {
                // This proof is for a future LogEntry, skip it
                debug!(
                    "LogEntry ({}): Skipping witness proof from {} (oldest: {oldest_id}, highest: {})",
                    log_entry.get_version_id(),
                    w.id,
                    highest_version_number
                );
                continue;
            }

            debug!(
                "oldest_id ({}) >  version_number ({})",
                oldest_id, version_number
            );
            if oldest_id > &version_number {
                // This proof is older than the current LogEntry, skip it
                debug!(
                    "LogEntry ({}): Skipping witness proof from {} (oldest: {oldest_id})",
                    log_entry.get_version_id(),
                    w.id,
                );
                // Still counts as a valid proof
                valid_proofs += 1;
                continue;
            } else {
                // witness proof is for this verion of the LogEntry
                // Validate the LogEntry against the proof
                log_entry
                    .log_entry
                    .validate_witness_proof(proof)
                    .map_err(|e| {
                        DIDWebVHError::WitnessProofError(format!(
                            "LogEntry ({}): Witness proof validation failed: {}",
                            log_entry.get_version_id(),
                            e
                        ))
                    })?;
                valid_proofs += 1;
                debug!(
                    "LogEntry ({}): Witness proof ({}) verified ok",
                    log_entry.get_version_id(),
                    w.id
                );
            }
        }

        let Some(threshold) = witnesses.threshold() else {
            // No threshold set, so we consider this as a state error
            return Err(DIDWebVHError::ValidationError(
                "Witness threshold not defined when witnessing seems to be enabled!".to_string(),
            ));
        };

        if valid_proofs < threshold {
            // Not enough valid proofs to consider this LogEntry as witnessed
            warn!(
                "LogEntry ({}): Witness threshold ({threshold}) not met. Only ({valid_proofs} valid proofs!",
                log_entry.get_version_id(),
            );
            Err(DIDWebVHError::WitnessProofError(format!(
                "Witness proof threshold ({threshold}) was not met. Only ({valid_proofs}) proofs were validated",
            )))
        } else {
            debug!(
                "LogEntry ({}): Witness proofs fully passed",
                log_entry.get_version_id()
            );
            Ok(())
        }
    }
}
