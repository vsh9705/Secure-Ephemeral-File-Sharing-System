// backend/server.js
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const argon2 = require('argon2');
const db = require('./db');
require('./cron');

const app = express();
const PORT = 3001;
const UPLOADS_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

app.use(cors({ origin: 'http://localhost:5173' }));

// Parse JSON bodies up to 100mb (encrypted files can be large)
app.use(express.json({ limit: '100mb' }));

// ─── Logging middleware ───────────────────────────────────────────────────────
// IMPORTANT for A7 (log inspection attack):
// We log req.url and req.path — the #fragment is NEVER present here.
// This is provable because browsers never send fragments to the server.
app.use((req, res, next) => {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${req.method} ${req.url}`);
  next();
});

// ─── POST /upload ─────────────────────────────────────────────────────────────
// Receives:
//   encrypted_blob  : base64 string  (AES-GCM ciphertext from browser)
//   key_hash        : hex string     (SHA-256 of encryption key — DP3)
//   password        : string?        (optional; immediately Argon2id hashed)
//   ttl_seconds     : integer        (e.g. 3600 for 1 hour)
//   original_name   : string         (filename to restore on download)
//   mime_type       : string         (file MIME type)
//
// Does NOT receive the raw key. Never. The key stays in the browser.
app.post('/upload', async (req, res) => {
  let blob_path;
  try {
    const { encrypted_blob, key_hash, password, ttl_seconds, original_name, mime_type } = req.body;

    // Validate required fields
    if (!encrypted_blob || typeof encrypted_blob !== 'string') {
      return res.status(400).json({ error: 'encrypted_blob is required' });
    }
    if (!key_hash || typeof key_hash !== 'string' || key_hash.length !== 64) {
      return res.status(400).json({ error: 'key_hash must be a 64-char hex SHA-256 digest' });
    }
    if (!ttl_seconds || typeof ttl_seconds !== 'number' || ttl_seconds < 1 || ttl_seconds > 604800) {
      return res.status(400).json({ error: 'ttl_seconds must be between 1 and 604800 (7 days)' });
    }
    if (password !== undefined && typeof password !== 'string') {
      return res.status(400).json({ error: 'password must be a string' });
    }

    // Hash the optional password before persistence. argon2.hash uses Argon2id
    // by default; the plaintext is never written to the database.
    const password_hash = password?.length ? await argon2.hash(password) : null;

    const file_id = crypto.randomUUID();
    blob_path = path.join(UPLOADS_DIR, `${file_id}.bin`);

    // Write ciphertext to disk
    const blobBuffer = Buffer.from(encrypted_blob, 'base64');
    fs.writeFileSync(blob_path, blobBuffer);

    const ttl_expires_at = Math.floor(Date.now() / 1000) + ttl_seconds;

    // Insert into DB — notice: no raw key, no raw password
    db.prepare(`
      INSERT INTO files (id, blob_path, original_name, mime_type, key_hash, password_hash, ttl_expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      file_id,
      blob_path,
      original_name || 'file',
      mime_type || 'application/octet-stream',
      key_hash,
      password_hash,
      ttl_expires_at
    );

    console.log(`[upload] Stored file ${file_id}, TTL=${ttl_seconds}s, password_protected=${!!password_hash}`);

    return res.status(200).json({ file_id });

  } catch (err) {
    // The blob and DB row cannot share a transaction. If persistence fails
    // after writing the blob, remove the unreferenced file.
    if (blob_path) {
      try { fs.unlinkSync(blob_path); } catch (_) {}
    }
    console.error('[upload] Error:', err.message);
    return res.status(500).json({ error: 'Upload failed' });
  }
});

// ─── GET /file-info/:id ───────────────────────────────────────────────────────
// Returns metadata about a file: whether it's password protected,
// whether it's already been accessed, and whether it's expired.
// Does NOT return the blob or any key material.
app.get('/file-info/:id', (req, res) => {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);

  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }

  const now = Math.floor(Date.now() / 1000);
  if (file.ttl_expires_at <= now) {
    return res.status(404).json({ error: 'File has expired' });
  }

  if (file.accessed) {
    return res.status(410).json({ error: 'File has already been accessed' });
  }

  return res.status(200).json({
    password_protected: !!file.password_hash,
    original_name: file.original_name,
    mime_type: file.mime_type,
    expires_at: file.ttl_expires_at,
  });
});

const recordDownloadAttempt = db.transaction((ip, now) => {
  const windowStart = now - 60000;
  db.prepare('DELETE FROM download_attempts WHERE attempted_at < ?').run(windowStart);
  const count = db.prepare(
    'SELECT COUNT(*) AS count FROM download_attempts WHERE ip = ? AND attempted_at >= ?'
  ).get(ip, windowStart).count;
  if (count >= 10) return false;
  db.prepare('INSERT INTO download_attempts (ip, attempted_at) VALUES (?, ?)').run(ip, now);
  return true;
});

function rateLimitDownload(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  try {
    if (!recordDownloadAttempt(ip, now)) {
      return res.status(429).json({ error: 'Too many attempts. Try again in a minute.' });
    }
    next();
  } catch (err) {
    console.error('[download] Rate-limit check failed:', err.message);
    return res.status(500).json({ error: 'Could not process download request' });
  }
}
// ─── POST /download/:id ───────────────────────────────────────────────────────
// Receives:
//   key_hash      : hex string   (SHA-256 of key — server verifies without seeing key)
//   password      : string?      (raw password, if file is password-protected)
//
// DP7 — claim, read, and remove the DB record in one synchronous transaction.
// The conditional update makes only one concurrent caller the winner.
app.post('/download/:id', rateLimitDownload, async (req, res) => {
  const { key_hash, password } = req.body;

  if (!key_hash || typeof key_hash !== 'string') {
    return res.status(400).json({ error: 'key_hash is required' });
  }

  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);

  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }

  const now = Math.floor(Date.now() / 1000);
  if (file.ttl_expires_at <= now) {
    return res.status(404).json({ error: 'File has expired' });
  }

  if (file.accessed) {
    return res.status(410).json({ error: 'File has already been accessed. One-time access only.' });
  }

  // DP5 — hash-based server verification
  // Server compares SHA-256(presented key) against stored key_hash
  // The raw key is never transmitted — only its hash
  if (key_hash !== file.key_hash) {
    return res.status(403).json({ error: 'Invalid key' });
  }

  // DP3 — password verification using Argon2id
  // If password-protected, verify without ever storing the plaintext
  if (file.password_hash) {
    if (!password) {
      return res.status(401).json({ error: 'Password required', password_required: true });
    }
    try {
      const valid = await argon2.verify(file.password_hash, password);
      if (!valid) {
        return res.status(403).json({ error: 'Incorrect password' });
      }
    } catch (err) {
      console.error('[download] Argon2 verify error:', err.message);
      return res.status(500).json({ error: 'Verification failed' });
    }
  }

  // Password verification above can yield to another request. Claim with a
  // conditional update only after all credentials have passed.
  const atomicDownload = db.transaction(() => {
    const claim = db.prepare(`
      UPDATE files SET accessed = 1
      WHERE id = ? AND accessed = 0 AND ttl_expires_at > ?
    `).run(file.id, Math.floor(Date.now() / 1000));
    if (claim.changes !== 1) return null;

    const record = db.prepare(
      'SELECT blob_path, original_name, mime_type FROM files WHERE id = ?'
    ).get(file.id);
    const blobBuffer = fs.readFileSync(record.blob_path);
    db.prepare('DELETE FROM files WHERE id = ?').run(file.id);
    return { record, blobBuffer };
  });

  let result;
  try {
    result = atomicDownload();
  } catch (err) {
    console.error('[download] Failed to claim/read file:', err.message);
    return res.status(500).json({ error: 'Could not read file blob' });
  }

  if (!result) {
    const current = db.prepare('SELECT ttl_expires_at FROM files WHERE id = ?').get(file.id);
    if (!current || current.ttl_expires_at <= Math.floor(Date.now() / 1000)) {
      return res.status(404).json({ error: 'File not found or expired' });
    }
    return res.status(410).json({ error: 'File has already been accessed. One-time access only.' });
  }

  const { record, blobBuffer } = result;
  // The database claim and record deletion have committed. Remove the blob.
  try {
    fs.unlinkSync(record.blob_path);
  } catch (err) {
    console.error(`[download] Failed to delete blob for ${file.id}:`, err.message);
  }

  console.log(`[download] Served and deleted: ${file.id}`);

  return res.status(200).json({
    encrypted_blob: blobBuffer.toString('base64'),
    original_name: record.original_name,
    mime_type: record.mime_type,
  });
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => {
  console.log(`[server] Running on http://localhost:${PORT}`);
});
