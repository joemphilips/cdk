//! Output conflict detail of a refused multi-party CTF settlement.
//!
//! When a request is refused because an output is signed, or is pending in
//! another operation, the error response lists each such output and its
//! state. The list holds only `B_` values that the submitter sent, so it
//! discloses nothing about the other operation.

use serde::{Deserialize, Deserializer, Serialize};

use crate::nuts::PublicKey;

/// The state of an output that blocks a settlement request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OutputConflictState {
    /// The mint signed the output.
    Signed,
    /// Another operation holds the output unsigned.
    Pending,
}

/// One output of a refused request and the state that blocks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutputConflict {
    /// The blinded message of the output.
    #[serde(rename = "B_")]
    pub blinded_secret: PublicKey,
    /// The state of the output.
    pub state: OutputConflictState,
}

/// The conflicting outputs of one refused request, in request order.
///
/// The list is never empty: a refusal without a conflict has no detail.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct OutputConflicts(Vec<OutputConflict>);

impl OutputConflicts {
    /// Wrap a conflict list, or return `None` when it is empty.
    pub fn new(conflicts: Vec<OutputConflict>) -> Option<Self> {
        (!conflicts.is_empty()).then_some(Self(conflicts))
    }

    /// The conflicting outputs in request order.
    pub fn outputs(&self) -> &[OutputConflict] {
        &self.0
    }

    /// Whether an output is pending. A list with only signed outputs is
    /// refused as "outputs already signed"; any pending output makes it
    /// "outputs are pending".
    pub fn any_pending(&self) -> bool {
        self.0
            .iter()
            .any(|conflict| conflict.state == OutputConflictState::Pending)
    }
}

impl<'de> Deserialize<'de> for OutputConflicts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let conflicts = Vec::<OutputConflict>::deserialize(deserializer)?;
        Self::new(conflicts)
            .ok_or_else(|| serde::de::Error::custom("output conflict list must not be empty"))
    }
}
