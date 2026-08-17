// backend/cron.js
// Runs every 60 seconds. Finds all files whose ttl_expires_at
// has passed and deletes both the DB record and the blob from disk.
// This implements DP8 — automatic destruction after TTL.

const cron = require('node-cron');
const fs = require('fs');
const db = require('./db');

function sweep() {
  const now = Math.floor(Date.now() / 1000);
  const expired = db.prepare(
    'SELECT id, blob_path FROM files WHERE ttl_expires_at <= ?'
  ).all(now);

  if (expired.length === 0) return;

  const deleteStmt = db.prepare('DELETE FROM files WHERE id = ?');

  for (const file of expired) {
    // Delete blob from disk
    try {
      if (fs.existsSync(file.blob_path)) {
        fs.unlinkSync(file.blob_path);
      }
    } catch (err) {
      console.error(`[cron] Failed to delete blob for ${file.id}:`, err.message);
    }

    // Delete DB record
    deleteStmt.run(file.id);
    console.log(`[cron] Expired and deleted: ${file.id}`);
  }
}

// Run every 60 seconds
cron.schedule('* * * * *', () => {
  try {
    sweep();
  } catch (err) {
    console.error('[cron] Sweep error:', err.message);
  }
});

console.log('[cron] TTL sweep scheduler started (every 60s)');