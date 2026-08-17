import React from 'react';

function CheckIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  );
}

function AlertIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="12" y1="8" x2="12" y2="12"/>
      <line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>
  );
}

function SpinnerIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" style={{ animation: 'spin 0.8s linear infinite' }}>
      <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
    </svg>
  );
}

const VARIANTS = {
  success: { icon: <CheckIcon />, cls: 'badge--success' },
  error:   { icon: <AlertIcon />, cls: 'badge--error' },
  loading: { icon: <SpinnerIcon />, cls: 'badge--loading' },
  warning: { icon: <AlertIcon />, cls: 'badge--warning' },
};

export default function StatusBadge({ type = 'success', message }) {
  const v = VARIANTS[type] || VARIANTS.success;
  return (
    <div className={`badge animate-in ${v.cls}`}>
      {v.icon}
      <span>{message}</span>
      <style dangerouslySetInnerHTML={{ __html: `
        .badge { display:flex; align-items:center; gap:8px; padding:10px 14px; border-radius:var(--radius); font-size:13px; border:1px solid transparent; }
        .badge--success { background:rgba(0,200,150,0.08); border-color:rgba(0,200,150,0.2); color:var(--accent); }
        .badge--error { background:var(--error-dim); border-color:rgba(255,77,77,0.2); color:var(--error); }
        .badge--loading { background:var(--surface); border-color:var(--border); color:var(--text-muted); }
        .badge--warning { background:rgba(245,166,35,0.08); border-color:rgba(245,166,35,0.2); color:var(--warning); }
      `}} />
    </div>
  );
}