import React, { useState } from 'react';

function CopyIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2"/>
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  );
}

function ShieldIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  );
}

// Parses share URL into base + fragment for display
function parseURL(url) {
  const hashIdx = url.indexOf('#');
  if (hashIdx === -1) return { base: url, fragment: '' };
  return {
    base: url.slice(0, hashIdx),
    fragment: url.slice(hashIdx),
  };
}

export default function ShareLink({ url, ttlLabel }) {
  const [copied, setCopied] = useState(false);
  const { base, fragment } = parseURL(url);

  async function copy() {
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback
      const el = document.createElement('textarea');
      el.value = url;
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  return (
    <div className="share-wrap animate-in">
      <div className="share-header">
        <div className="share-dot" />
        <span className="share-label">Share link ready</span>
        {ttlLabel && (
          <span className="share-ttl">Expires in {ttlLabel}</span>
        )}
      </div>

      <div className="share-box">
        <div className="share-url">
          <span className="share-url-base">{base}</span>
          <span className="share-url-fragment">{fragment}</span>
        </div>
        <button
          className={`share-copy-btn ${copied ? 'share-copy-btn--copied' : ''}`}
          onClick={copy}
          title="Copy link"
        >
          {copied ? <CheckIcon /> : <CopyIcon />}
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>

      <div className="share-note">
        <ShieldIcon />
        <span>
          The decryption key is in the <code>#fragment</code> — it is never sent to the server.
          One-time access only.
        </span>
      </div>

      <style>{`
        .share-wrap {
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: var(--radius-lg);
          overflow: hidden;
        }
        .share-header {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 12px 16px;
          border-bottom: 1px solid var(--border);
          background: var(--accent-dim);
        }
        .share-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: var(--accent);
          flex-shrink: 0;
          box-shadow: 0 0 6px var(--accent);
        }
        .share-label {
          font-size: 12px;
          font-weight: 500;
          color: var(--accent);
          flex: 1;
        }
        .share-ttl {
          font-size: 11px;
          color: var(--text-muted);
          font-family: var(--mono);
        }
        .share-box {
          display: flex;
          align-items: stretch;
          gap: 0;
        }
        .share-url {
          flex: 1;
          padding: 14px 16px;
          font-family: var(--mono);
          font-size: 11.5px;
          line-height: 1.6;
          word-break: break-all;
          min-width: 0;
          color: var(--text-muted);
        }
        .share-url-base {
          color: var(--text-muted);
        }
        .share-url-fragment {
          color: var(--accent);
          font-weight: 500;
        }
        .share-copy-btn {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 4px;
          padding: 14px 18px;
          border: none;
          border-left: 1px solid var(--border);
          background: transparent;
          color: var(--text-muted);
          cursor: pointer;
          font-family: var(--font);
          font-size: 11px;
          font-weight: 500;
          transition: all var(--transition);
          flex-shrink: 0;
          min-width: 68px;
        }
        .share-copy-btn:hover {
          background: var(--surface-2);
          color: var(--text);
        }
        .share-copy-btn--copied {
          color: var(--accent);
        }
        .share-copy-btn--copied:hover {
          color: var(--accent);
          background: var(--accent-dim);
        }
        .share-note {
          display: flex;
          align-items: flex-start;
          gap: 8px;
          padding: 12px 16px;
          border-top: 1px solid var(--border);
          color: var(--text-muted);
          font-size: 12px;
          line-height: 1.55;
        }
        .share-note svg {
          flex-shrink: 0;
          margin-top: 1px;
        }
        .share-note code {
          font-family: var(--mono);
          font-size: 11px;
          color: var(--accent);
          background: var(--accent-dim);
          padding: 1px 5px;
          border-radius: 3px;
        }
      `}</style>
    </div>
  );
}