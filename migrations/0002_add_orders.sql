CREATE TABLE orders (
  id TEXT PRIMARY KEY,
  checkout_code TEXT NOT NULL UNIQUE,
  campaign_name TEXT NOT NULL,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  customer_email TEXT,
  daily_rate_usd REAL NOT NULL,
  total_usd REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending_payment'
    CHECK (status IN ('pending_payment', 'paid', 'scheduled', 'cancelled')),
  stripe_checkout_session_id TEXT UNIQUE,
  stripe_payment_intent_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  daily_rate_usd REAL NOT NULL,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  UNIQUE (order_id, device_id)
);

CREATE TABLE advertisements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  r2_key TEXT NOT NULL UNIQUE,
  byte_size INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX order_items_order_id_idx ON order_items(order_id);
CREATE INDEX order_items_device_id_idx ON order_items(device_id);
CREATE INDEX advertisements_order_id_idx ON advertisements(order_id);
