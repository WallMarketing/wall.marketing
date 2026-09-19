CREATE TABLE venue_applications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_name TEXT NOT NULL,
  address TEXT NOT NULL,
  suburb TEXT NOT NULL,
  country TEXT NOT NULL,
  contact_name TEXT NOT NULL,
  contact_email TEXT NOT NULL,
  contact_phone TEXT NOT NULL,
  business_number TEXT,
  bank_account_name TEXT,
  bank_account_number TEXT,
  bsb TEXT,
  revenue_share_percent REAL NOT NULL DEFAULT 25,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'reviewed', 'declined')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX venue_applications_status_idx ON venue_applications(status, created_at);
