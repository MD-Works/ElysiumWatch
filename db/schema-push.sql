-- Migration: add push_subscriptions table for Web Push / VAPID
-- Run with:
--   npx wrangler d1 execute neighbourhood-watch-db --remote --file=db/schema-push.sql

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  endpoint    TEXT    NOT NULL UNIQUE,
  p256dh      TEXT    NOT NULL,
  auth        TEXT    NOT NULL,
  created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_push_subscriptions_created ON push_subscriptions(created_at);
