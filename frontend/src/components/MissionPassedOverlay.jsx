import { useEffect, useRef } from 'react';
import gsap from 'gsap';

export default function MissionPassedOverlay({ mission, cash, onClose }) {
  const overlayRef = useRef(null);
  const contentRef = useRef(null);
  const timerRef = useRef(null);

  useEffect(() => {
    // GSAP entry animation
    if (contentRef.current) {
      gsap.fromTo(
        contentRef.current,
        { scale: 0.3, opacity: 0, y: 60 },
        { scale: 1, opacity: 1, y: 0, duration: 0.6, ease: 'back.out(1.5)' }
      );
    }

    // Auto-close after 8 seconds
    timerRef.current = setTimeout(() => {
      if (onClose) onClose();
    }, 8000);

    return () => {
      clearTimeout(timerRef.current);
    };
  }, [onClose]);

  const handleClose = () => {
    if (contentRef.current) {
      gsap.to(contentRef.current, {
        scale: 0.8,
        opacity: 0,
        duration: 0.3,
        ease: 'power2.in',
        onComplete: () => { if (onClose) onClose(); },
      });
    } else {
      if (onClose) onClose();
    }
  };

  return (
    <div
      ref={overlayRef}
      className="mission-passed-overlay"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.85)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        backdropFilter: 'blur(4px)',
      }}
      onClick={handleClose}
    >
      <div
        ref={contentRef}
        style={{
          background: 'linear-gradient(145deg, #1c1829ee, #0d0b18ee)',
          border: '2px solid #39ff1480',
          borderRadius: '12px',
          padding: '3rem 2.5rem',
          maxWidth: '520px',
          width: '90vw',
          textAlign: 'center',
          boxShadow: '0 0 60px #39ff1444, 0 0 120px #39ff1422',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* MISSION PASSED title */}
        <div
          className="mission-passed-title"
          style={{
            fontFamily: 'var(--font-long)',
            fontSize: 'clamp(2rem, 6vw, 3.5rem)',
            color: '#39ff14',
            textShadow: '0 0 20px #39ff14, 0 0 50px #39ff14aa',
            letterSpacing: '0.08em',
            lineHeight: 1.1,
            marginBottom: '1.2rem',
            animation: 'missionPassedGlow 1.5s ease-in-out infinite alternate',
          }}
        >
          MISSION PASSED!
        </div>

        {/* Mission name */}
        {mission && (
          <div
            style={{
              fontFamily: 'var(--font-round-bold)',
              fontSize: '1.1rem',
              color: '#fff',
              marginBottom: '1.5rem',
              opacity: 0.9,
              letterSpacing: '0.05em',
            }}
          >
            {mission}
          </div>
        )}

        {/* Divider */}
        <div
          style={{
            height: '1px',
            background: 'linear-gradient(90deg, transparent, #39ff14, transparent)',
            margin: '1rem 0 1.5rem',
          }}
        />

        {/* Cash earned */}
        {cash !== undefined && cash !== null && (
          <div
            className="cash-display"
            style={{
              fontFamily: 'var(--font-long)',
              fontSize: 'clamp(2rem, 5vw, 3rem)',
              color: '#39ff14',
              textShadow: '0 0 15px #39ff14cc',
              marginBottom: '2rem',
              letterSpacing: '0.05em',
            }}
          >
            +${cash.toLocaleString()}
          </div>
        )}

        {/* Buttons */}
        <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
          <button
            className="btn-heist"
            onClick={handleClose}
            style={{ minWidth: '160px' }}
          >
            NEXT MISSION
          </button>
          <button
            className="btn-outline-heist"
            onClick={() => {
              clearTimeout(timerRef.current);
              window.location.href = '/missions';
            }}
            style={{ minWidth: '160px' }}
          >
            RETURN TO BOARD
          </button>
        </div>

        <div
          style={{
            marginTop: '1.2rem',
            color: '#888',
            fontSize: '0.75rem',
            fontFamily: 'var(--font-sans)',
            letterSpacing: '0.1em',
          }}
        >
          Auto-closing in 8 seconds...
        </div>
      </div>

      <style>{`
        @keyframes missionPassedGlow {
          from { text-shadow: 0 0 20px #39ff14, 0 0 50px #39ff14aa; }
          to   { text-shadow: 0 0 40px #39ff14, 0 0 80px #39ff14, 0 0 120px #39ff1466; }
        }
      `}</style>
    </div>
  );
}
