ALTER TABLE order_items ADD COLUMN status TEXT NOT NULL DEFAULT 'pending_payment'
  CHECK (status IN ('pending_payment', 'scheduled', 'cleared'));

ALTER TABLE order_items ADD COLUMN cleared_at TEXT;

UPDATE order_items
   SET status = 'scheduled'
 WHERE status = 'pending_payment'
   AND order_id IN (SELECT id FROM orders WHERE status IN ('paid', 'scheduled'));

CREATE INDEX order_items_schedule_idx ON order_items(device_id, status, start_date, end_date);
