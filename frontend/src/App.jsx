import React, { useState, useEffect } from 'react';
import Upload from './pages/Upload.jsx';
import Download from './pages/Download.jsx';

// Simple hash-based client-side router.
// /download#id=...&key=... → Download page
// everything else → Upload page
function getPage() {
  const path = window.location.pathname;
  if (path === '/download') return 'download';
  return 'upload';
}

function LockIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="7" width="10" height="8" rx="2"/>
      <path d="M5 7V5a3 3 0 0 1 6 0v2"/>
    </svg>
  );
}

export default function App() {
  const [page, setPage] = useState(getPage);

  useEffect(() => {
    const onPopState = () => setPage(getPage());
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  function navigate(to) {
    window.history.pushState({}, '', to);
    setPage(getPage());
  }

  return (
    <div className="app-shell">
      <nav className="nav">
        <div className="nav-brand" onClick={() => navigate('/')}>
          <div className="nav-brand-icon">
            <LockIcon />
          </div>
          <span className="nav-brand-name">ephemeral<span>.</span>share</span>
        </div>
        <button
          className="nav-link"
          onClick={() => navigate(page === 'upload' ? '/download' : '/')}
        >
          {page === 'upload' ? 'Receive a file' : 'Send a file'}
        </button>
      </nav>

      {page === 'upload' ? (
        <Upload onNavigate={navigate} />
      ) : (
        <Download onNavigate={navigate} />
      )}
    </div>
  );
}