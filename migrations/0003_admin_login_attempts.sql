CREATE TABLE admin_login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_hash TEXT NOT NULL,
  attempted_at TEXT NOT NULL
);

CREATE INDEX admin_login_attempts_ip_time_idx
  ON admin_login_attempts(ip_hash, attempted_at);
