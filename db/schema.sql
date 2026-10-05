-- Neighbourhood Watch — D1 schema
-- Load with: npx wrangler d1 execute <db-name> --file=db/schema.sql

CREATE TABLE IF NOT EXISTS reports (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  lat              REAL NOT NULL,
  lng              REAL NOT NULL,
  category         TEXT NOT NULL,          -- suspicious | fire | flood | electrical | water | other
  ref_nr           TEXT,                   -- municipal reference number, only relevant for electrical/water
  incident_at      TEXT,                   -- ISO datetime — when it actually happened (user-editable)
  message          TEXT NOT NULL,
  image_key        TEXT,                   -- B2 file name, nullable
  reporter_contact TEXT,                   -- optional name, from the on-device saved-name field
  status           TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected
  rejection_reason TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),  -- submission time
  reviewed_by      TEXT,
  reviewed_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_reports_status   ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_category ON reports(category);
CREATE INDEX IF NOT EXISTS idx_reports_created  ON reports(created_at);

-- Speeds up the admin history list (ordered and filtered by review time)
CREATE INDEX IF NOT EXISTS idx_reports_reviewed ON reports(reviewed_at);
