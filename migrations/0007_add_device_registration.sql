ALTER TABLE devices ADD COLUMN setup_status TEXT NOT NULL DEFAULT 'new'
  CHECK (setup_status IN ('new', 'active', 'disabled'));

ALTER TABLE devices ADD COLUMN device_token_hash TEXT;
ALTER TABLE devices ADD COLUMN registered_at TEXT;
