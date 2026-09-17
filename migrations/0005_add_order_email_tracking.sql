ALTER TABLE orders ADD COLUMN success_email_sent INTEGER NOT NULL DEFAULT 0;
ALTER TABLE orders ADD COLUMN failure_email_sent INTEGER NOT NULL DEFAULT 0;
ALTER TABLE orders ADD COLUMN last_stripe_event_id TEXT;
