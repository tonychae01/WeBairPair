ALTER TABLE pairing_runs ADD COLUMN unmatched_email TEXT;
ALTER TABLE pairing_runs ADD COLUMN unmatched_sent INTEGER NOT NULL DEFAULT 0
  CHECK (unmatched_sent IN (0, 1));
