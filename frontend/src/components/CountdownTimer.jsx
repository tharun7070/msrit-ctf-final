import { useEffect, useState } from 'react';

function pad(n) {
  return String(n).padStart(2, '0');
}

export default function CountdownTimer({ endTime }) {
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  if (!endTime) {
    return (
      <div
        style={{
          fontFamily: 'var(--font-long)',
          color: '#aaa',
          fontSize: '0.9rem',
          letterSpacing: '0.15em',
          textAlign: 'center',
        }}
      >
        COMPETITION TIMING SET BY ORGANIZER
      </div>
    );
  }

  const end = new Date(endTime).getTime();
  const diff = end - now;

  if (diff > 0) {
    const totalSecs = Math.floor(diff / 1000);
    const hh = Math.floor(totalSecs / 3600);
    const mm = Math.floor((totalSecs % 3600) / 60);
    const ss = totalSecs % 60;

    return (
      <div style={{ textAlign: 'center' }}>
        <div
          style={{
            fontFamily: 'var(--font-long)',
            color: '#ff6eb0',
            fontSize: '0.75rem',
            letterSpacing: '0.3em',
            marginBottom: '0.5rem',
          }}
        >
          HEIST IN PROGRESS
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center', alignItems: 'center' }}>
          {[hh, mm, ss].map((val, idx) => (
            <span key={idx} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span
                className="countdown-digit"
                style={{
                  fontFamily: 'var(--font-long)',
                  fontSize: 'clamp(1.5rem, 3vw, 2.2rem)',
                  color: '#00e5ff',
                  textShadow: '0 0 15px #00e5ff',
                  background: '#0a0812',
                  border: '1px solid #00e5ff44',
                  borderRadius: '6px',
                  padding: '0.2em 0.5em',
                  minWidth: '2.5em',
                  textAlign: 'center',
                  display: 'inline-block',
                }}
              >
                {pad(val)}
              </span>
              {idx < 2 && (
                <span style={{ color: '#00e5ff', fontSize: '1.5rem', fontFamily: 'var(--font-long)' }}>:</span>
              )}
            </span>
          ))}
        </div>
        <div style={{ color: '#555', fontSize: '0.65rem', letterSpacing: '0.3em', marginTop: '0.4rem', fontFamily: 'var(--font-sans)' }}>
          HH : MM : SS
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        fontFamily: 'var(--font-long)',
        color: '#39ff14',
        fontSize: '1rem',
        letterSpacing: '0.2em',
        textAlign: 'center',
        textShadow: '0 0 10px #39ff14',
      }}
    >
      HEIST COMPLETE
    </div>
  );
}
