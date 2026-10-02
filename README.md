# ephemeral.share

A secure, zero-trust ephemeral file sharing system where the server never sees your encryption key or plaintext, and never persists a raw password.

Built as the implementation phase of a B.Tech final year project on *RAG-Driven Analysis of Secure Ephemeral File Sharing Systems* at LNMIIT, Jaipur.

---

## How it works

1. You pick a file. A 256-bit AES-GCM key is generated **in your browser**.
2. The file is encrypted **in your browser** before anything is sent to the server.
3. The server receives only ciphertext + a SHA-256 hash of the key. Never the key itself.
4. A share link is generated with the decryption key embedded in the **URL fragment** (`#`). Browsers never send fragments to servers — it is physically impossible for the key to appear in server logs.
5. The recipient opens the link, the file is downloaded as ciphertext, and decrypted **in their browser**.
6. The file is permanently deleted from the server after the first access. Replaying the link returns `410 Gone`.
7. If the TTL expires before anyone downloads it, a background job deletes it automatically.

---

## Security properties

| Property | Implementation |
|---|---|
| Key never leaves the client | Web Crypto API — key generated and used in browser only |
| Server stores no plaintext | AES-GCM encryption before upload |
| Server persists no raw secrets | SHA-256(key) and Argon2id(password) digests only |
| Key invisible to server logs | Decryption key in URL `#fragment` — HTTP semantics guarantee it is never transmitted |
| One-time access | Atomic SQLite transaction marks file accessed and deletes blob in one operation |
| Automatic expiry | `node-cron` TTL sweep deletes expired files every 60 seconds |
| Password protection | Argon2id hashing on receipt; online attempts are rate limited |

These properties map directly to 8 design principles synthesised from a corpus of 30 security research papers using a RAG pipeline (LangChain + FAISS + Llama 3.3 70B).

---

## Tech stack

**Backend**
- Node.js + Express
- SQLite via `better-sqlite3`
- Argon2id via `argon2`
- TTL sweep via `node-cron`

**Frontend**
- React + Vite
- Native Web Crypto API (AES-GCM 256-bit) — no crypto library
- Inter + JetBrains Mono (Google Fonts)

**No Docker. No cloud dependencies. Runs entirely on localhost.**

---

## Project structure

```
ephemeral-share/
├── backend/
│   ├── server.js          # Express server — all API routes
│   ├── db.js              # SQLite schema setup
│   ├── cron.js            # TTL sweep job
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── crypto.js      # All Web Crypto API logic
│   │   ├── App.jsx        # Client-side routing
│   │   ├── pages/
│   │   │   ├── Upload.jsx
│   │   │   └── Download.jsx
│   │   └── components/
│   │       ├── FileDropzone.jsx
│   │       ├── ShareLink.jsx
│   │       ├── ProgressBar.jsx
│   │       └── StatusBadge.jsx
│   └── package.json
└── attacks/               # Python attack simulation scripts
    ├── a1_db_dump.py
    ├── a2_blob_exfil.py
    ├── a3_replay.py
    ├── a4_bruteforce_key.py
    ├── a5_bruteforce_password.py
    ├── a6_ttl_bypass.py
    ├── a7_log_inspection.py
    └── a8_mitm_upload.py
```

---

## Running locally

**Prerequisites**
- Node.js 18+ — [nodejs.org](https://nodejs.org)
- Python 3.8+ (for attack scripts only)

**Terminal 1 — Backend**
```bash
cd backend
npm install
node server.js
# Running on http://localhost:3001
```

**Terminal 2 — Frontend**
```bash
cd frontend
npm install
npm run dev
# Running on http://localhost:5173
```

Open `http://localhost:5173` in your browser.

---

## API reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/upload` | Receive encrypted blob + key hash + TTL |
| `GET` | `/file-info/:id` | Check if file exists, is expired, or password-protected |
| `POST` | `/download/:id` | Verify key hash, serve blob, atomically delete |
| `GET` | `/health` | Server health check |

### POST /upload

```json
{
  "encrypted_blob": "<base64 AES-GCM ciphertext>",
  "key_hash":       "<64-char SHA-256 hex digest>",
  "password":       "<plaintext password — immediately Argon2id hashed>",
  "ttl_seconds":    3600,
  "original_name":  "report.pdf",
  "mime_type":      "application/pdf"
}
```

Returns `{ "file_id": "<uuid>" }`

### POST /download/:id

```json
{
  "key_hash": "<SHA-256 of key>",
  "password": "<plaintext password if required>"
}
```

Returns `{ "encrypted_blob": "<base64>", "original_name": "...", "mime_type": "..." }`

---

## Attack simulations

Eight adversarial test scripts validate that the security properties hold under attack. Run them from the `attacks/` directory while the backend is running.

```bash
cd attacks
pip install requests
python3 a1_db_dump.py
```

| Script | Attack | DP validated | Expected result |
|---|---|---|---|
| `a1_db_dump.py` | Full database dump | DP3 | Only hashes visible — files unreadable |
| `a2_blob_exfil.py` | Encrypted blob theft | DP2 | Pure ciphertext — no key to decrypt |
| `a3_replay.py` | Replay download request | DP7 | `410 Gone` on second attempt |
| `a4_bruteforce_key.py` | 1000 random keys | DP5 | All `403 Forbidden` |
| `a5_bruteforce_password.py` | Common password list | DP3 | ~1s per attempt — infeasible |
| `a6_ttl_bypass.py` | Access after expiry | DP8 | `404 Not Found` |
| `a7_log_inspection.py` | Server log key search | DP4 | Key absent from all logs |
| `a8_mitm_upload.py` | Intercept upload body | DP1, DP2 | No plaintext, no key in body |

---

## Database schema

```sql
CREATE TABLE files (
  id              TEXT PRIMARY KEY,   -- UUID, used in share URL
  blob_path       TEXT NOT NULL,      -- path to encrypted .bin file
  original_name   TEXT NOT NULL,      -- restored on download
  mime_type       TEXT NOT NULL,
  key_hash        TEXT NOT NULL,      -- SHA-256(key) — for verification only
  password_hash   TEXT,               -- Argon2id(password) — nullable
  ttl_expires_at  INTEGER NOT NULL,   -- Unix timestamp
  accessed        INTEGER DEFAULT 0,  -- 0 or 1 — enforces one-time access
  created_at      INTEGER DEFAULT (unixepoch())
);
```

No `raw_key` column exists. This is by design.

---

## Research background

This system is the implementation artifact of a B.Tech project that used Retrieval-Augmented Generation (RAG) as a systematic literature review methodology over a corpus of 30 peer-reviewed security papers.

The RAG pipeline (LangChain + FAISS + `all-MiniLM-L12-v2` embeddings + Llama 3.3 70B) executed 12 structured queries across 6 thematic clusters and synthesised 8 design principles for building minimal-trust ephemeral file sharing systems. This application implements all 8.

**Pipeline evaluation metrics:**
- Retrieval Precision@3 (P@3): 72.2%
- Topic Relevancy Alignment (TRA): 100%
- Hallucination Rate (HR): 5.6%

---
