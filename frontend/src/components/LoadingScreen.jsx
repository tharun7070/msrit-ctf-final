export default function LoadingScreen() {
  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: '#0a0812',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
      }}
    >
      <div
        style={{
          fontFamily: 'var(--font-long)',
          fontSize: 'clamp(1.8rem, 5vw, 3.5rem)',
          color: '#ff6eb0',
          letterSpacing: '0.15em',
          textShadow: '0 0 30px #ff6eb0, 0 0 60px #ff6eb088, 0 0 90px #ff6eb044',
          marginBottom: '1.5rem',
          animation: 'fta-pulse 2s ease-in-out infinite',
        }}
      >
        FLAG THEFT AUTO
      </div>

      <div
        style={{
          fontFamily: 'var(--font-long)',
          fontSize: '1rem',
          color: '#00e5ff',
          letterSpacing: '0.4em',
          marginBottom: '2.5rem',
          opacity: 0.8,
        }}
      >
        LOADING...
      </div>

      <div className="spinner" />

      <style>{`
        @keyframes fta-pulse {
          0%, 100% { text-shadow: 0 0 30px #ff6eb0, 0 0 60px #ff6eb088; opacity: 1; }
          50% { text-shadow: 0 0 50px #ff6eb0, 0 0 100px #ff6eb0aa, 0 0 140px #ff6eb044; opacity: 0.85; }
        }
      `}</style>
    </div>
  );
}
