-- Cutoff rejections are counted and deleted by their cutoff. A committed
-- settlement has no cutoff, stays for ever and is not in this index.
-- Additive only: no table changes.
CREATE INDEX idx_ctf_settlement_replays_rejection_cutoff
    ON ctf_settlement_replays(cutoff)
    WHERE outcome_kind = 'rejected_after_cutoff';
