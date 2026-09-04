CREATE TABLE users (
  email TEXT PRIMARY KEY,
  opted_in INTEGER NOT NULL DEFAULT 0 CHECK (opted_in IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_paired_at TEXT,
  last_unmatched_at TEXT
);

CREATE TABLE verification_tokens (
  token_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('opt_in', 'opt_out')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX verification_tokens_email_idx ON verification_tokens(email);
CREATE INDEX verification_tokens_expiry_idx ON verification_tokens(expires_at);

CREATE TABLE verification_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX verification_requests_email_time_idx
  ON verification_requests(email, created_at);
CREATE INDEX verification_requests_ip_time_idx
  ON verification_requests(ip_hash, created_at);

CREATE TABLE pairing_runs (
  month TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('sending', 'completed')),
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE pairings (
  month TEXT NOT NULL,
  email_a TEXT NOT NULL,
  email_b TEXT NOT NULL,
  sent_a INTEGER NOT NULL DEFAULT 0 CHECK (sent_a IN (0, 1)),
  sent_b INTEGER NOT NULL DEFAULT 0 CHECK (sent_b IN (0, 1)),
  PRIMARY KEY (month, email_a, email_b)
);

CREATE INDEX pairings_email_a_idx ON pairings(email_a);
CREATE INDEX pairings_email_b_idx ON pairings(email_b);
