-- قاعدة بيانات منصة مُحضِّر
-- D1 (SQLite)

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'teacher',
  school TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS plans (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  status TEXT DEFAULT 'مسودة',
  json TEXT NOT NULL,
  quality INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_plans_user ON plans(user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS curricula (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  tree TEXT NOT NULL
);