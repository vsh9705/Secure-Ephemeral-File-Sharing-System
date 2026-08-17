import React, { useState, useRef } from 'react';
import { formatBytes } from '../crypto.js';

function FileIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
    </svg>
  );
}

function UploadIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="16 16 12 12 8 16"/>
      <line x1="12" y1="12" x2="12" y2="21"/>
      <path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/>
    </svg>
  );
}

function XIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
      <line x1="18" y1="6" x2="6" y2="18"/>
      <line x1="6" y1="6" x2="18" y2="18"/>
    </svg>
  );
}

export default function FileDropzone({ file, onFile }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);

  function handleDrop(e) {
    e.preventDefault();
    setDragging(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped) onFile(dropped);
  }

  function handleDragOver(e) {
    e.preventDefault();
    setDragging(true);
  }

  function handleDragLeave() {
    setDragging(false);
  }

  function handleChange(e) {
    const selected = e.target.files[0];
    if (selected) onFile(selected);
  }

  if (file) {
    return (
      <div className="dropzone dropzone--file animate-in">
        <div className="dropzone-file-icon">
          <FileIcon />
        </div>
        <div className="dropzone-file-info">
          <span className="dropzone-file-name">{file.name}</span>
          <span className="dropzone-file-size">{formatBytes(file.size)}</span>
        </div>
        <button
          className="btn btn-ghost dropzone-clear"
          onClick={() => onFile(null)}
          title="Remove file"
        >
          <XIcon />
        </button>
      </div>
    );
  }

  return (
    <div
      className={`dropzone ${dragging ? 'dropzone--active' : ''}`}
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onClick={() => inputRef.current?.click()}
      role="button"
      tabIndex={0}
      onKeyDown={e => e.key === 'Enter' && inputRef.current?.click()}
    >
      <input
        ref={inputRef}
        type="file"
        style={{ display: 'none' }}
        onChange={handleChange}
      />
      <div className={`dropzone-icon ${dragging ? 'dropzone-icon--active' : ''}`}>
        <UploadIcon />
      </div>
      <p className="dropzone-label">
        {dragging ? 'Drop to encrypt' : 'Drop a file here'}
      </p>
      <p className="dropzone-sub">or click to browse · any file type · encrypted before upload</p>

      <style>{`
        .dropzone {
          border: 1.5px dashed var(--border-hover);
          border-radius: var(--radius-lg);
          background: var(--surface);
          padding: 36px 24px;
          cursor: pointer;
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 10px;
          transition: all 200ms ease;
          user-select: none;
          outline: none;
        }
        .dropzone:hover,
        .dropzone:focus-visible {
          border-color: var(--accent);
          background: var(--accent-dim);
        }
        .dropzone--active {
          border-color: var(--accent);
          background: var(--accent-dim);
          box-shadow: 0 0 0 4px var(--accent-glow);
        }
        .dropzone--file {
          flex-direction: row;
          padding: 16px 18px;
          cursor: default;
          border-style: solid;
          border-color: var(--border);
          gap: 14px;
          align-items: center;
        }
        .dropzone--file:hover {
          border-color: var(--border);
          background: var(--surface);
          box-shadow: none;
        }
        .dropzone-icon {
          color: var(--text-muted);
          transition: color 200ms ease;
          display: flex;
        }
        .dropzone-icon--active { color: var(--accent); }
        .dropzone:hover .dropzone-icon { color: var(--accent); }
        .dropzone-label {
          font-size: 14px;
          font-weight: 500;
          color: var(--text);
          margin: 0;
        }
        .dropzone-sub {
          font-size: 12px;
          color: var(--text-muted);
          text-align: center;
          margin: 0;
        }
        .dropzone-file-icon {
          color: var(--accent);
          display: flex;
          flex-shrink: 0;
        }
        .dropzone-file-info {
          flex: 1;
          min-width: 0;
          display: flex;
          flex-direction: column;
          gap: 2px;
        }
        .dropzone-file-name {
          font-size: 14px;
          font-weight: 500;
          color: var(--text);
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }
        .dropzone-file-size {
          font-size: 12px;
          color: var(--text-muted);
          font-family: var(--mono);
        }
        .dropzone-clear {
          flex-shrink: 0;
          padding: 6px;
          border-radius: var(--radius-sm);
        }
      `}</style>
    </div>
  );
}