import React, { useState } from 'react';
import FileDropzone from '../components/FileDropzone.jsx';
import ShareLink from '../components/ShareLink.jsx';
import ProgressBar from '../components/ProgressBar.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import {
  generateKey, exportKey, encryptFile,
  hashKey, buildShareURL, uint8ArrayToBase64
} from '../crypto.js';

const TTL_OPTIONS = [
  { label: '5 minutes',  value: 300 },
  { label: '1 hour',     value: 3600 },
  { label: '24 hours',   value: 86400 },
  { label: '7 days',     value: 604800 },
];

export default function Upload() {
  const [file, setFile]           = useState(null);
  const [ttl, setTtl]             = useState(3600);
  const [password, setPassword]   = useState('');
  const [status, setStatus]       = useState(null); // null | 'encrypting' | 'uploading' | 'done' | 'error'
  const [shareURL, setShareURL]   = useState('');
  const [errorMsg, setErrorMsg]   = useState('');

  async function handleUpload() {
    if (!file) return;
    setStatus('encrypting');
    setErrorMsg('');

    try {
      // DP1: Generate key in browser
      const cryptoKey = await generateKey();
      const rawKey = await exportKey(cryptoKey);

      // DP2: Encrypt file in browser before sending anywhere
      const encryptedBytes = await encryptFile(file, cryptoKey);
      const encryptedBase64 = uint8ArrayToBase64(encryptedBytes);

      // DP5: Compute SHA-256(key) — this is all the server will ever see of the key
      const keyHash = await hashKey(rawKey);

      // DP3: Hash password with Argon2id — but Argon2 can't run in browser natively
      // So we send the raw password and let the server hash it with argon2
      // The password is sent over localhost (acceptable for demo) and immediately hashed
      // In a production system this would use OPAQUE/PAKE
      setStatus('uploading');

      const body = {
        encrypted_blob: encryptedBase64,
        key_hash:       keyHash,
        ttl_seconds:    ttl,
        original_name:  file.name,
        mime_type:      file.type || 'application/octet-stream',
      };

      if (password.trim()) {
        body.password = password.trim();
      }

      const res = await fetch('http://localhost:3001/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Upload failed');
      }

      const { file_id } = await res.json();

      // DP4: Embed raw key in URL fragment — never goes to server
      const url = buildShareURL(file_id, rawKey);
      setShareURL(url);
      setStatus('done');

    } catch (err) {
      console.error(err);
      setErrorMsg(err.message || 'Something went wrong');
      setStatus('error');
    }
  }

  function reset() {
    setFile(null);
    setPassword('');
    setStatus(null);
    setShareURL('');
    setErrorMsg('');
    setTtl(3600);
  }

  const ttlLabel = TTL_OPTIONS.find(o => o.value === ttl)?.label || '';

  return (
    <main className="page-content">
      <div className="card">
        <div className="card-header">
          <h1>Send a file</h1>
          <p>Encrypted in your browser before it leaves your device. The server never sees your key.</p>
        </div>

        {status === 'done' ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <StatusBadge type="success" message="File encrypted and uploaded" />
            <ShareLink url={shareURL} ttlLabel={ttlLabel} />
            <button className="btn btn-secondary" onClick={reset} style={{ marginTop: '8px' }}>
              Send another file
            </button>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <FileDropzone file={file} onFile={setFile} />

            <div className="field">
              <label>Expires after</label>
              <select value={ttl} onChange={e => setTtl(Number(e.target.value))}>
                {TTL_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>

            <div className="field">
              <label>Password protection <span style={{ color: 'var(--text-subtle)', textTransform: 'none', fontSize: '11px', fontWeight: 400 }}>(optional)</span></label>
              <input
                type="password"
                placeholder="Leave blank for no password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                autoComplete="new-password"
              />
            </div>

            {(status === 'encrypting' || status === 'uploading') && (
              <ProgressBar
                label={status === 'encrypting' ? 'Encrypting in browser…' : 'Uploading ciphertext…'}
                sublabel={status === 'encrypting' ? 'AES-GCM 256-bit' : 'key never leaves your device'}
              />
            )}

            {status === 'error' && (
              <StatusBadge type="error" message={errorMsg} />
            )}

            <button
              className="btn btn-primary"
              onClick={handleUpload}
              disabled={!file || status === 'encrypting' || status === 'uploading'}
            >
              {status === 'encrypting' ? 'Encrypting…'
               : status === 'uploading' ? 'Uploading…'
               : 'Encrypt and upload'}
            </button>

            <div className="upload-footer">
              <div className="upload-footer-item">
                <span className="dot dot--green" />
                <span>Key generated locally</span>
              </div>
              <div className="upload-footer-item">
                <span className="dot dot--green" />
                <span>Encrypted before upload</span>
              </div>
              <div className="upload-footer-item">
                <span className="dot dot--green" />
                <span>One-time access</span>
              </div>
            </div>
          </div>
        )}
      </div>

      <style>{`
        .upload-footer {
          display: flex;
          gap: 16px;
          flex-wrap: wrap;
          padding-top: 4px;
        }
        .upload-footer-item {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 12px;
          color: var(--text-muted);
        }
        .dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          flex-shrink: 0;
        }
        .dot--green { background: var(--accent); }
      `}</style>
    </main>
  );
}