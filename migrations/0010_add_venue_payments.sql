CREATE TABLE venue_payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  amount_usd REAL NOT NULL CHECK (amount_usd >= 0),
  paid_at TEXT NOT NULL DEFAULT (datetime('now')),
  note TEXT
);

CREATE INDEX venue_payments_device_id_idx ON venue_payments(device_id);
