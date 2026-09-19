CREATE TABLE site_profiles (
  site_key TEXT PRIMARY KEY,
  site_name TEXT,
  address TEXT,
  suburb TEXT,
  country TEXT,
  revenue_share_percent REAL NOT NULL DEFAULT 0 CHECK (revenue_share_percent >= 0 AND revenue_share_percent <= 100),
  contact_name TEXT,
  contact_email TEXT,
  contact_phone TEXT,
  company_name TEXT,
  business_number TEXT,
  bank_account_name TEXT,
  bsb TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
