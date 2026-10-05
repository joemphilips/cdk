-- Use status, registration timestamp and ID for filtered listing seeks.
CREATE INDEX IF NOT EXISTS idx_conditions_status_created
    ON conditions (attestation_status, created_at, condition_id);
