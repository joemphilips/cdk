-- The melt outflow budget sums the melt quotes paid in the last hour and day.
CREATE INDEX IF NOT EXISTS idx_melt_quote_paid_time ON melt_quote(paid_time);
