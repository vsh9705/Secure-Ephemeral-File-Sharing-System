import React from 'react';

export default function ProgressBar({ label, sublabel }) {
  return (
    <div className="progress-wrap">
      <div className="progress-top">
        <span className="progress-label">{label}</span>
        {sublabel && <span className="progress-sublabel">{sublabel}</span>}
      </div>
      <div className="progress-track">
        <div className="progress-bar" />
      </div>

      <style>{`
        .progress-wrap {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }
        .progress-top {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .progress-label {
          font-size: 13px;
          color: var(--text-muted);
        }
        .progress-sublabel {
          font-size: 12px;
          color: var(--text-subtle);
          font-family: var(--mono);
        }
        .progress-track {
          height: 2px;
          background: var(--border);
          border-radius: 2px;
          overflow: hidden;
        }
        .progress-bar {
          height: 100%;
          width: 40%;
          background: var(--accent);
          border-radius: 2px;
          animation: progressSlide 1.4s ease-in-out infinite;
        }
        @keyframes progressSlide {
          0%   { transform: translateX(-100%); width: 40%; }
          50%  { width: 60%; }
          100% { transform: translateX(280%); width: 40%; }
        }
      `}</style>
    </div>
  );
}