//! Stored form of the conflict list of a refused multi-party CTF settlement.

use crate::database::Error;
use crate::nuts::nut_ctf::settlement::{OutputConflict, OutputConflictState, OutputConflicts};
use crate::nuts::PublicKey;

const NO_CONFLICT: u8 = 0;
const PENDING: u8 = 1;
const SIGNED: u8 = 2;

/// The state of every output of a refused request, in request order.
///
/// Each output takes two bits: 0 for no conflict, 1 for pending, 2 for
/// signed. Output `i` uses bits `2i` and `2i + 1`, counted from the least
/// significant bit of the first byte. The record holds no `B_`: the request
/// digest binds the outputs, so an identical request rebuilds the list from
/// its own outputs. A request with `n` outputs stores `ceil(n / 4)` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputConflictRecord {
    output_count: usize,
    packed_states: Vec<u8>,
}

impl OutputConflictRecord {
    /// Record the state of each request output. Returns `None` when no output conflicts.
    pub fn from_states(states: &[Option<OutputConflictState>]) -> Option<Self> {
        let mut packed_states = vec![0; packed_len(states.len())];
        let mut conflict = false;
        for (index, state) in states.iter().enumerate() {
            let value = match state {
                None => NO_CONFLICT,
                Some(OutputConflictState::Pending) => PENDING,
                Some(OutputConflictState::Signed) => SIGNED,
            };
            conflict |= value != NO_CONFLICT;
            packed_states[index / 4] |= value << (2 * (index % 4));
        }
        conflict.then_some(Self {
            output_count: states.len(),
            packed_states,
        })
    }

    /// Decode a stored record.
    ///
    /// The length must match the output count, every state must be defined,
    /// the unused bits must be zero, and at least one output must conflict.
    pub fn from_stored(output_count: u64, packed_states: Vec<u8>) -> Result<Self, Error> {
        let output_count = usize::try_from(output_count)
            .map_err(|_| invalid("output count exceeds this platform"))?;
        if packed_states.len() != packed_len(output_count) {
            return Err(invalid("state length does not match the output count"));
        }
        let mut conflict = false;
        for index in 0..packed_states.len() * 4 {
            let value = state_value(&packed_states, index);
            if index >= output_count {
                if value != NO_CONFLICT {
                    return Err(invalid("unused state bits are set"));
                }
                continue;
            }
            if value > SIGNED {
                return Err(invalid("undefined output state"));
            }
            conflict |= value != NO_CONFLICT;
        }
        if !conflict {
            return Err(invalid("record has no conflicting output"));
        }
        Ok(Self {
            output_count,
            packed_states,
        })
    }

    /// The number of outputs of the refused request.
    pub fn output_count(&self) -> usize {
        self.output_count
    }

    /// The packed states, two bits for each output.
    pub fn packed_states(&self) -> &[u8] {
        &self.packed_states
    }

    /// Rebuild the conflict list from the outputs of the identical request, in request order.
    pub fn conflicts(&self, blinded_secrets: &[PublicKey]) -> Result<OutputConflicts, Error> {
        if blinded_secrets.len() != self.output_count {
            return Err(invalid("request output count does not match the record"));
        }
        let conflicts = blinded_secrets
            .iter()
            .enumerate()
            .filter_map(|(index, blinded_secret)| {
                let state = match state_value(&self.packed_states, index) {
                    PENDING => OutputConflictState::Pending,
                    SIGNED => OutputConflictState::Signed,
                    _ => return None,
                };
                Some(OutputConflict {
                    blinded_secret: *blinded_secret,
                    state,
                })
            })
            .collect();
        OutputConflicts::new(conflicts).ok_or_else(|| invalid("record has no conflicting output"))
    }
}

fn packed_len(output_count: usize) -> usize {
    output_count.div_ceil(4)
}

fn state_value(packed_states: &[u8], index: usize) -> u8 {
    (packed_states[index / 4] >> (2 * (index % 4))) & 0b11
}

fn invalid(reason: &str) -> Error {
    Error::Internal(format!("invalid output conflict record: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nuts::SecretKey;

    fn keys(count: usize) -> Vec<PublicKey> {
        (0..count)
            .map(|_| SecretKey::generate().public_key())
            .collect()
    }

    #[test]
    fn states_pack_two_bits_for_each_output_in_request_order() {
        let record = OutputConflictRecord::from_states(&[
            Some(OutputConflictState::Pending),
            None,
            Some(OutputConflictState::Signed),
            None,
            Some(OutputConflictState::Signed),
        ])
        .expect("two conflicts");

        // Outputs 0..4 in byte 0: 01, 00, 10, 00. Output 4 in byte 1: 10.
        assert_eq!(record.output_count(), 5);
        assert_eq!(record.packed_states(), &[0b0010_0001, 0b0000_0010]);

        let outputs = keys(5);
        assert_eq!(
            record
                .conflicts(&outputs)
                .expect("same output count")
                .outputs(),
            &[
                OutputConflict {
                    blinded_secret: outputs[0],
                    state: OutputConflictState::Pending,
                },
                OutputConflict {
                    blinded_secret: outputs[2],
                    state: OutputConflictState::Signed,
                },
                OutputConflict {
                    blinded_secret: outputs[4],
                    state: OutputConflictState::Signed,
                },
            ]
        );
    }

    #[test]
    fn a_request_without_conflicts_has_no_record() {
        assert!(OutputConflictRecord::from_states(&[None, None]).is_none());
        assert!(OutputConflictRecord::from_states(&[]).is_none());
    }

    #[test]
    fn the_record_size_is_bounded_by_the_output_count_not_the_list() {
        let states = vec![Some(OutputConflictState::Signed); 8192];
        let record = OutputConflictRecord::from_states(&states).expect("every output conflicts");
        assert_eq!(record.packed_states().len(), 2048);
    }

    #[test]
    fn stored_records_round_trip_and_reject_malformed_states() {
        let record = OutputConflictRecord::from_states(&[None, Some(OutputConflictState::Pending)])
            .expect("one conflict");
        assert_eq!(
            OutputConflictRecord::from_stored(2, record.packed_states().to_vec())
                .expect("stored record"),
            record
        );

        for (output_count, packed, case) in [
            (2, vec![0b0000_0100, 0], "length"),
            (2, vec![0b0000_1100], "undefined state 3"),
            (2, vec![0b0001_0100], "unused bits"),
            (2, vec![0], "no conflict"),
        ] {
            assert!(
                OutputConflictRecord::from_stored(output_count, packed).is_err(),
                "{case}"
            );
        }
        assert!(record.conflicts(&keys(3)).is_err(), "other output count");
    }
}
