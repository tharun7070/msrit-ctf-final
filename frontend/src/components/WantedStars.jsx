export default function WantedStars({ solved = 0, total = 1 }) {
  const filled = Math.round((solved / (total || 1)) * 5);

  return (
    <div className="flex gap-1 items-center">
      {Array.from({ length: 5 }, (_, i) => (
        <span
          key={i}
          className="wanted-star"
          style={{
            color: i < filled ? '#ffd700' : '#555',
            fontSize: '1.5rem',
            lineHeight: 1,
            textShadow: i < filled ? '0 0 8px #ffd700aa' : 'none',
            transition: 'color 0.3s',
          }}
        >
          {i < filled ? '★' : '☆'}
        </span>
      ))}
      <span style={{ color: '#aaa', fontSize: '0.8rem', marginLeft: '0.4rem', fontFamily: 'var(--font-sans)' }}>
        {solved}/{total}
      </span>
    </div>
  );
}
