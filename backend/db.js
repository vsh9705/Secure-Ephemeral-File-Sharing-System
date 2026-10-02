// backend/db.js
const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = path.join(__dirname, 'fileshare.db');
const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS files (
    id              TEXT PRIMARY KEY,
    blob_path       TEXT NOT NULL,
    original_name   TEXT NOT NULL,
    mime_type       TEXT NOT NULL DEFAULT 'application/octet-stream',
    key_hash        TEXT NOT NULL,
    password_hash   TEXT,
    ttl_expires_at  INTEGER NOT NULL,
    accessed        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
  )
`);

// Persist download rate-limit timestamps so restarts and multiple backend
// processes cannot reset or bypass the per-IP window.
db.exec(`
  CREATE TABLE IF NOT EXISTS download_attempts (
    ip          TEXT NOT NULL,
    attempted_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_download_attempts_ip_time
    ON download_attempts (ip, attempted_at);
  CREATE INDEX IF NOT EXISTS idx_download_attempts_time
    ON download_attempts (attempted_at);
`);

module.exports = db;
