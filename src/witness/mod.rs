/*!
*   Handling of witnessing changes to the log entries
*/

use crate::DIDWebVHError;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

pub mod proofs;
pub mod validate;

/// Witness nodes
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum Witnesses {
    Value {
        threshold: u32,
        witnesses: Vec<Witness>,
    },
    // WARN: This must always go last, otherwise it will become the default as it matches on
    // anything
    Empty {},
}

impl Witnesses {
    /// Are any witnesses configured?
    pub fn is_empty(&self) -> bool {
        match self {
            Witnesses::Empty {} => true,
            Witnesses::Value { witnesses, .. } => witnesses.is_empty(),
        }
    }

    /// Checks Witnesses parameters for errors
    pub fn validate(&self) -> Result<(), DIDWebVHError> {
        if self.is_empty() {
            return Err(DIDWebVHError::ValidationError(
                "Witnesses are enabled, but no witness nodes are specified! Can not be empty!"
                    .to_string(),
            ));
        }

        match self {
            Witnesses::Value {
                threshold,
                witnesses,
            } => {
                if threshold < &1 {
                    return Err(DIDWebVHError::ValidationError(
                        "Witness threshold must be 1 or more".to_string(),
                    ));
                } else if witnesses.len() < *threshold as usize {
                    return Err(DIDWebVHError::ValidationError(format!(
                        "Number of Witnesses ({}) is less than the threshold ({})",
                        witnesses.len(),
                        threshold
                    )));
                }
            }
            _ => {
                return Err(DIDWebVHError::ValidationError(
                    "Empty Witness Parameter config found, but it wasn't detected. INTERNAL ERROR STATE"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Returns witnesses if they exist
    pub fn witnesses(&self) -> Option<&[Witness]> {
        match self {
            Witnesses::Empty {} => None,
            Witnesses::Value { witnesses, .. } => Some(witnesses),
        }
    }

    /// Returns threshold if it exists
    pub fn threshold(&self) -> Option<u32> {
        match self {
            Witnesses::Empty {} => None,
            Witnesses::Value { threshold, .. } => Some(*threshold),
        }
    }
}

/// Single Witness Node
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Witness {
    pub id: String,
}

impl Display for Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl Witness {
    /// Returns the witness ID as a did:key
    /// use [as_did_key] if you wan the DID#Key value
    pub fn as_did(&self) -> String {
        ["did:key:", &self.id].concat()
    }

    /// Returns the witness ID as a did:key:z6...#z6...
    /// Use [as_did] if you want just the base DID
    pub fn as_did_key(&self) -> String {
        [&self.as_did(), "#", &self.id].concat()
    }
}
