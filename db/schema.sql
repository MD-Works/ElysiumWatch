-- ============================================================
-- PAS — Perimeter Alert System
-- D1 Schema v1.1
-- Run: wrangler d1 execute pas-db --remote --file=schema.sql
-- ============================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ── Admin auth ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS admins (
  id            TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Device registry ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS devices (
  id                  TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name                TEXT NOT NULL,
  location_label      TEXT NOT NULL DEFAULT '',
  status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','active','revoked')),
  pairing_token       TEXT UNIQUE,
  pairing_expires_at  TEXT,
  paired_at           TEXT,
  last_seen_at        TEXT,
  created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Per-device config (cloud-authoritative) ───────────────────
CREATE TABLE IF NOT EXISTS device_config (
  id                      TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  device_id               TEXT NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE,
  sensors_enabled         TEXT NOT NULL DEFAULT '{"camera":true,"audio":true,"gps":true,"accelerometer":true}',
  trigger_config          TEXT NOT NULL DEFAULT '{"motion_threshold":15,"sound_db":65,"geofence_m":100,"impact_g":2.5}',
  mode                    TEXT NOT NULL DEFAULT 'normal'
                            CHECK (mode IN ('normal','night','audio_only','gps_only','silent')),
  stream_quality          TEXT NOT NULL DEFAULT 'mid'
                            CHECK (stream_quality IN ('low','mid','high')),
  reporting_interval_sec  INTEGER NOT NULL DEFAULT 30,
  local_override_allowed  INTEGER NOT NULL DEFAULT 0,
  updated_at              TEXT NOT NULL DEFAULT (datetime('now')),
  config_version          INTEGER NOT NULL DEFAULT 1   -- added v1.1: tracks config changes for node sync
);

-- ── Events ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
  id            TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  device_id     TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  type          TEXT NOT NULL
                  CHECK (type IN ('motion','sound','geofence','impact','manual')),
  severity      TEXT NOT NULL DEFAULT 'warning'
                  CHECK (severity IN ('info','warning','critical')),
  payload       TEXT NOT NULL DEFAULT '{}',
  snapshot_key  TEXT,
  acknowledged  INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Webhooks ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webhooks (
  id             TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  url            TEXT NOT NULL,
  secret         TEXT NOT NULL,
  enabled        INTEGER NOT NULL DEFAULT 1,
  events_filter  TEXT NOT NULL DEFAULT '["motion","sound","geofence","impact","manual"]',
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  webhook_id        TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event_id          TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  status            TEXT NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','success','failed')),
  response_code     INTEGER,
  attempts          INTEGER NOT NULL DEFAULT 0,
  last_attempted_at TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── WebRTC session audit log ──────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
  id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  device_id    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  initiated_by TEXT NOT NULL DEFAULT 'admin',
  started_at   TEXT NOT NULL DEFAULT (datetime('now')),
  ended_at     TEXT,
  end_reason   TEXT
);

-- ── Indexes ───────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_devices_status       ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_pairing      ON devices(pairing_token);
CREATE INDEX IF NOT EXISTS idx_events_device        ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_events_type          ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_created       ON events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_unacked       ON events(acknowledged) WHERE acknowledged = 0;
CREATE INDEX IF NOT EXISTS idx_deliveries_status    ON webhook_deliveries(status);
CREATE INDEX IF NOT EXISTS idx_deliveries_webhook   ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS idx_sessions_device      ON sessions(device_id);
