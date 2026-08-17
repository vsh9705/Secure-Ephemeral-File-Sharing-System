import React, { useState, useEffect } from 'react';
import StatusBadge from '../components/StatusBadge.jsx';
import ProgressBar from '../components/ProgressBar.jsx';
import {
  parseShareURL, base64ToKey, importKey,
  decryptBlob, hashKey
} from '../crypto.js';

function DownloadIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
      <polyline points="7 10 12 15 17 10"/>
      <line x1="12" y1="15" x2="12" y2="3"/>
    </svg>
  );
}

function LockIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  );
}

export default function Download({ onNavigate }) {
  const [phase, setPhase]         = useState('checking'); // checking | password | ready | downloading | done | error
  const [fileInfo, setFileInfo]   = useState(null);
  const [password, setPassword]   = useState('');
  const [errorMsg, setErrorMsg]   = useState('');
  const [parsed, setParsed]       = useState({ id: null, key: null });

  useEffect(() => {
    const p = parseShareURL();
    setParsed(p);

    if (!p.id || !p.key) {
      setErrorMsg('Invalid share link. Make sure you copied the full URL including the #fragment.');
      setPhase('error');
      return;
    }

    // Fetch file metadata
    fetch(`http://localhost:3001/file-info/${p.id}`)
      .then(r => r.json())
      .then(data => {
        if (data.error) {
          setErrorMsg(data.error);
          setPhase('error');
          return;
        }
        setFileInfo(data);
        setPhase(data.password_protected ? 'password' : 'ready');
      })
      .catch(() => {
        setErrorMsg('Could not reach the server. Make sure the backend is running.');
        setPhase('error');
      });
  }, []);

  async function handleDownload() {
    setPhase('downloading');
    setErrorMsg('');

    try {
      const rawKeyBuffer = base64ToKey(parsed.key);
      const keyHash = await hashKey(rawKeyBuffer);

      const body = { key_hash: keyHash };
      if (password) body.password = password;

      const res = await fetch(`http://localhost:3001/download/${parsed.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (res.status === 401) {
        setErrorMsg('Password required.');
        setPhase('password');
        return;
      }
      if (res.status === 403) {
        const d = await res.json();
        setErrorMsg(d.error || 'Incorrect password or key.');
        setPhase(fileInfo?.password_protected ? 'password' : 'error');
        return;
      }
      if (res.status === 410) {
        setErrorMsg('This file has already been accessed. One-time links cannot be reused.');
        setPhase('error');
        return;
      }
      if (!res.ok) {
        const d = await res.json();
        setErrorMsg(d.error || 'Download failed');
        setPhase('error');
        return;
      }

      const { encrypted_blob, original_name, mime_type } = await res.json();

      // DP6: Decrypt in browser — server only sent ciphertext
      const cryptoKey = await importKey(rawKeyBuffer);
      const plaintext = await decryptBlob(encrypted_blob, cryptoKey);

      // Trigger browser download
      const blob = new Blob([plaintext], { type: mime_type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = original_name || 'download';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setPhase('done');

    } catch (err) {
      console.error(err);
      setErrorMsg(err.message || 'Decryption failed');
      setPhase('error');
    }
  }

  return (
    <main className="page-content">
      <div className="card">
        <div className="card-header">
          <h1>Receive a file</h1>
          <p>Decrypted locally in your browser. The server only stores ciphertext.</p>
        </div>

        {phase === 'checking' && (
          <ProgressBar label="Verifying link…" sublabel="contacting server" />
        )}

        {phase === 'error' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <StatusBadge type="error" message={errorMsg} />
            <button className="btn btn-secondary" onClick={() => onNavigate('/')}>
              Send a file instead
            </button>
          </div>
        )}

        {phase === 'password' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="pw-banner">
              <LockIcon />
              <span>This file is password protected</span>
            </div>
            {errorMsg && <StatusBadge type="error" message={errorMsg} />}
            <div className="field">
              <label>Password</label>
              <input
                type="password"
                placeholder="Enter the password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleDownload()}
                autoFocus
              />
            </div>
            <button className="btn btn-primary" onClick={handleDownload} disabled={!password}>
              <DownloadIcon />
              Decrypt and download
            </button>
          </div>
        )}

        {phase === 'ready' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {fileInfo && (
              <div className="file-meta">
                <div className="file-meta-row">
                  <span className="file-meta-label">File</span>
                  <span className="file-meta-value mono">{fileInfo.original_name}</span>
                </div>
                <div className="file-meta-row">
                  <span className="file-meta-label">Access</span>
                  <span className="file-meta-value">One-time only — downloading will delete it</span>
                </div>
              </div>
            )}
            <button className="btn btn-primary" onClick={handleDownload}>
              <DownloadIcon />
              Decrypt and download
            </button>
          </div>
        )}

        {phase === 'downloading' && (
          <ProgressBar label="Decrypting in browser…" sublabel="AES-GCM 256-bit" />
        )}

        {phase === 'done' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <StatusBadge type="success" message="File decrypted and downloaded" />
            <div className="done-note">
              This link is now permanently invalidated. The file has been deleted from the server.
            </div>
            <button className="btn btn-secondary" onClick={() => onNavigate('/')}>
              Send a file
            </button>
          </div>
        )}
      </div>

      <style>{`
        .pw-banner {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 12px 14px;
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: var(--radius);
          font-size: 13px;
          color: var(--text-muted);
        }
        .file-meta {
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: var(--radius);
          overflow: hidden;
        }
        .file-meta-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 11px 14px;
          gap: 16px;
        }
        .file-meta-row + .file-meta-row {
          border-top: 1px solid var(--border);
        }
        .file-meta-label {
          font-size: 12px;
          color: var(--text-muted);
          flex-shrink: 0;
        }
        .file-meta-value {
          font-size: 13px;
          color: var(--text);
          text-align: right;
          word-break: break-all;
        }
        .done-note {
          font-size: 13px;
          color: var(--text-muted);
          line-height: 1.6;
          padding: 12px 14px;
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: var(--radius);
        }
      `}</style>
    </main>
  );
}