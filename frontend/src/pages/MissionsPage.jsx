import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useChallenges } from '../hooks/useChallenges';
import { LEVEL_COLORS } from '../data/challengeMeta';
import NavBar from '../sections/NavBar';

// ── helpers ──────────────────────────────────────────────────────────────────

const DIFF_COLOR = {
  Easy:   { strip: '#39FF14', pill: 'rgba(57,255,20,0.15)',  text: '#39FF14'  },
  Medium: { strip: '#FF8C00', pill: 'rgba(255,140,0,0.15)',  text: '#FF8C00'  },
  Hard:   { strip: '#FF4040', pill: 'rgba(255,64,64,0.15)',  text: '#FF4040'  },
};

function diffForCard(mission) {
  const lvl = mission.level
    || (mission.fta_id?.startsWith('E') ? 'Easy'
      : mission.fta_id?.startsWith('M') ? 'Medium' : 'Hard');
  return { lvl, colors: DIFF_COLOR[lvl] || DIFF_COLOR.Easy };
}

const ACT_ROMAN = { Easy: 'I', Medium: 'II', Hard: 'III' };
const ACT_RING  = { Easy: '#39FF14', Medium: '#FF8C00', Hard: '#FF4040' };

// ── chip config ───────────────────────────────────────────────────────────────

const CHIPS = [
  { id: 'ALL',      label: 'ALL',      activeStyle: { background: '#fff',    color: '#000'    } },
  { id: 'EASY',     label: 'EASY',     activeStyle: { background: '#39FF14', color: '#000'    } },
  { id: 'MEDIUM',   label: 'MEDIUM',   activeStyle: { background: '#FF8C00', color: '#000'    } },
  { id: 'HARD',     label: 'HARD',     activeStyle: { background: '#FF4040', color: '#fff'    } },
  { id: 'SOLVED',   label: 'SOLVED',   activeStyle: { background: '#00E5FF', color: '#000'    } },
  { id: 'UNSOLVED', label: 'UNSOLVED', activeStyle: { background: '#888',    color: '#fff'    } },
];

// ── subcomponents ─────────────────────────────────────────────────────────────

function MissionCard({ mission, isSolved, navigate }) {
  const [hovered, setHovered] = useState(false);
  const { lvl, colors } = diffForCard(mission);

  return (
    <div
      key={mission.ctfd_id || mission.name}
      onClick={() => navigate(`/mission/${mission.ctfd_id}`)}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: '#0d0d1a',
        border: '1px solid rgba(255,255,255,0.1)',
        borderLeft: isSolved ? '4px solid #39FF14' : '1px solid rgba(255,255,255,0.1)',
        borderRadius: '1rem',
        overflow: 'hidden',
        cursor: 'pointer',
        display: 'flex',
        flexDirection: 'column',
        transition: 'all 0.2s ease',
        transform: hovered ? 'scale(1.02)' : 'scale(1)',
        boxShadow: hovered
          ? '0 0 30px rgba(255,110,176,0.2)'
          : isSolved
            ? '0 0 12px rgba(57,255,20,0.08)'
            : 'none',
        ...(isSolved && { backgroundColor: 'rgba(57,255,20,0.03)' }),
      }}
    >
      {/* Top colour strip */}
      <div style={{ height: '6px', background: colors.strip, flexShrink: 0 }} />

      {/* Body */}
      <div style={{ padding: '1.25rem', flex: 1, display: 'flex', flexDirection: 'column' }}>

        {/* Row 1: fta_id pill + reward */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6rem' }}>
          <span
            className="font-mono text-xs font-bold uppercase"
            style={{
              background: colors.pill,
              color: colors.text,
              border: `1px solid ${colors.strip}50`,
              padding: '2px 10px',
              borderRadius: '999px',
            }}
          >
            {mission.fta_id || mission.category}
          </span>
          <span
            className="font-long text-xl font-bold"
            style={{ color: '#39FF14' }}
          >
            ${mission.reward || mission.value || 50}
          </span>
        </div>

        {/* Title */}
        <h3
          className="font-round-bold text-xl uppercase"
          style={{
            color: hovered ? '#FF6EB0' : '#fff',
            transition: 'color 0.2s',
            lineHeight: 1.2,
            marginBottom: '0.5rem',
          }}
        >
          {mission.name}
        </h3>

        {/* Location */}
        <p className="font-mono text-xs" style={{ color: '#9ca3af', marginBottom: '0.25rem' }}>
          📍 {mission.location || 'Los Santos Underground'}
        </p>

        {/* Focus / category */}
        <p className="font-mono text-xs" style={{ color: '#6b7280' }}>
          FOCUS: {mission.topic || mission.category}
        </p>

        {/* File count badge */}
        {mission.files && mission.files.length > 0 && (
          <span
            className="font-mono text-xs"
            style={{
              marginTop: '0.5rem',
              display: 'inline-block',
              background: 'rgba(255,255,255,0.07)',
              border: '1px solid rgba(255,255,255,0.12)',
              color: '#9ca3af',
              padding: '1px 8px',
              borderRadius: '999px',
              width: 'fit-content',
            }}
          >
            {mission.files.length} FILE{mission.files.length !== 1 ? 'S' : ''}
          </span>
        )}

        {/* Footer */}
        <div
          style={{
            marginTop: 'auto',
            paddingTop: '0.75rem',
            borderTop: '1px solid rgba(255,255,255,0.1)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          {isSolved ? (
            <span className="font-mono text-sm font-bold" style={{ color: '#39FF14' }}>
              ✓ MISSION PASSED
            </span>
          ) : (
            <span
              className="font-mono text-sm"
              style={{
                color: '#FF6EB0',
                textDecoration: hovered ? 'underline' : 'none',
                transition: 'text-decoration 0.2s',
              }}
            >
              OPEN CONTRACT →
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

// ── main page ─────────────────────────────────────────────────────────────────

export default function MissionsPage() {
  const { challenges, solvedIds, loading, error } = useChallenges();
  const [filter, setFilter] = useState('ALL');
  const [search, setSearch]   = useState('');
  const [searchFocused, setSearchFocused] = useState(false);
  const navigate = useNavigate();

  // ── existing filtering logic (unchanged) ──────────────────────────────────
  const filteredChallenges = challenges.filter(c => {
    const lvl = (c.level || (c.fta_id?.startsWith('E') ? 'Easy' : c.fta_id?.startsWith('M') ? 'Medium' : 'Hard')).toLowerCase();
    const isSolved = solvedIds.has(c.ctfd_id) || solvedIds.has(c.id);

    if (filter === 'EASY'     && lvl !== 'easy')   return false;
    if (filter === 'MEDIUM'   && lvl !== 'medium') return false;
    if (filter === 'HARD'     && lvl !== 'hard')   return false;
    if (filter === 'SOLVED'   && !isSolved)        return false;
    if (filter === 'UNSOLVED' && isSolved)         return false;

    if (search.trim()) {
      const q = search.toLowerCase();
      const matchName  = c.name?.toLowerCase().includes(q);
      const matchCat   = c.category?.toLowerCase().includes(q);
      const matchLoc   = c.location?.toLowerCase().includes(q);
      const matchTopic = c.topic?.toLowerCase().includes(q);
      const matchId    = c.fta_id?.toLowerCase().includes(q);
      if (!matchName && !matchCat && !matchLoc && !matchTopic && !matchId) return false;
    }

    return true;
  });

  // ── existing act grouping logic (unchanged) ────────────────────────────────
  const acts = [
    {
      name: 'ACT I — THE STREET JOB',
      level: 'Easy',
      desc: '10 Starter Jobs · $50 Each · $500 Total',
      items: filteredChallenges.filter(c => (c.level?.toLowerCase() === 'easy') || c.fta_id?.startsWith('E')),
    },
    {
      name: 'ACT II — THE BIG HEIST',
      level: 'Medium',
      desc: '5 Complex Operations · $100 Each · $500 Total',
      items: filteredChallenges.filter(c => (c.level?.toLowerCase() === 'medium') || c.fta_id?.startsWith('M')),
    },
    {
      name: 'ACT III — THE FINAL GETAWAY',
      level: 'Hard',
      desc: '5 Mastermind Contracts · $160 Each · $800 Total',
      items: filteredChallenges.filter(c => (c.level?.toLowerCase() === 'hard') || c.fta_id?.startsWith('H')),
    },
  ];

  const totalSolved = solvedIds.size;
  const totalCount  = challenges.length || 20;

  // ── render ─────────────────────────────────────────────────────────────────
  return (
    <div className="app-bg min-h-screen text-white pb-24">
      <NavBar />

      <main className="max-w-7xl mx-auto pt-28 px-4 sm:px-6 lg:px-8 space-y-10">

        {/* ── 1. HERO STRIP ──────────────────────────────────────────────── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <span className="font-mono text-xs uppercase tracking-widest" style={{ color: '#FF6EB0' }}>
            TARGET ACQUISITION TERMINAL
          </span>

          <h1
            className="font-long text-6xl uppercase"
            style={{
              background: 'linear-gradient(90deg, #FF6EB0, #00E5FF)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
              lineHeight: 1.1,
            }}
          >
            MISSION CONTRACTS
          </h1>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
            <p className="font-mono text-sm" style={{ color: '#9ca3af' }}>
              {totalCount} ACTIVE TARGETS · $2,200 BOUNTY
            </p>

            {/* Cleared counter — neon green pill */}
            <span
              className="font-mono text-xs font-bold uppercase"
              style={{
                background: 'rgba(57,255,20,0.12)',
                border: '1px solid #39FF14',
                color: '#39FF14',
                padding: '3px 14px',
                borderRadius: '999px',
                boxShadow: '0 0 10px rgba(57,255,20,0.3)',
              }}
            >
              ✓ {totalSolved} / {totalCount} CLEARED
            </span>
          </div>
        </div>

        {/* ── 2. CATEGORY CHIPS ──────────────────────────────────────────── */}
        <div style={{ overflowX: 'auto', paddingBottom: '4px' }}>
          <div style={{ display: 'flex', gap: '0.6rem', minWidth: 'max-content' }}>
            {CHIPS.map(chip => {
              const isActive = filter === chip.id;
              return (
                <button
                  key={chip.id}
                  onClick={() => setFilter(chip.id)}
                  className="font-mono font-bold text-sm"
                  style={{
                    padding: '0.6rem 1.5rem',
                    borderRadius: '999px',
                    border: isActive ? 'none' : '1px solid rgba(255,255,255,0.15)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    ...(isActive
                      ? {
                          ...chip.activeStyle,
                          boxShadow: '0 0 18px rgba(255,255,255,0.25)',
                        }
                      : {
                          background: 'rgba(255,255,255,0.05)',
                          color: '#9ca3af',
                        }),
                  }}
                >
                  {chip.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* ── 3. SEARCH BAR ──────────────────────────────────────────────── */}
        <div style={{ position: 'relative' }}>
          <span
            style={{
              position: 'absolute',
              left: '1.1rem',
              top: '50%',
              transform: 'translateY(-50%)',
              fontSize: '1.1rem',
              pointerEvents: 'none',
            }}
          >
            🔍
          </span>
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            onFocus={() => setSearchFocused(true)}
            onBlur={() => setSearchFocused(false)}
            placeholder="Search contracts, location, category..."
            className="font-mono text-sm w-full"
            style={{
              background: '#0d0d1a',
              border: searchFocused
                ? '1.5px solid #FF6EB0'
                : '1.5px solid rgba(255,255,255,0.1)',
              borderRadius: '0.75rem',
              padding: '0.85rem 1.2rem 0.85rem 2.8rem',
              color: '#fff',
              outline: 'none',
              boxShadow: searchFocused ? '0 0 20px rgba(255,110,176,0.15)' : 'none',
              transition: 'all 0.2s ease',
              width: '100%',
              boxSizing: 'border-box',
            }}
          />
        </div>

        {/* ── LOADING STATE ──────────────────────────────────────────────── */}
        {loading && challenges.length === 0 && (
          <div className="flex-center py-20 flex-col gap-4">
            <div className="spinner" />
            <span className="font-mono text-sm uppercase tracking-widest" style={{ color: '#9ca3af' }}>
              QUERYING DISPATCH NETWORK...
            </span>
          </div>
        )}

        {/* ── ERROR STATE ────────────────────────────────────────────────── */}
        {error && challenges.length === 0 && (
          <div
            className="font-mono text-sm text-center"
            style={{
              background: 'rgba(185,28,28,0.3)',
              border: '1px solid rgba(239,68,68,0.5)',
              color: '#fca5a5',
              padding: '1rem',
              borderRadius: '0.5rem',
            }}
          >
            ⚠ FAILED TO LOAD TARGETS FROM CTFD: {error}
          </div>
        )}

        {/* ── 4. ACT SECTIONS ────────────────────────────────────────────── */}
        {acts.map(act => {
          if (act.items.length === 0) return null;
          const roman     = ACT_ROMAN[act.level];
          const ringColor = ACT_RING[act.level];
          const clearedCount = act.items.filter(c => solvedIds.has(c.ctfd_id) || solvedIds.has(c.id)).length;

          return (
            <section key={act.name} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>

              {/* Act header */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '1rem',
                  borderBottom: '1px solid rgba(255,255,255,0.08)',
                  paddingBottom: '1rem',
                }}
              >
                {/* Left: roman circle + act name + desc */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <div
                    className="font-long font-bold"
                    style={{
                      width: '3rem',
                      height: '3rem',
                      borderRadius: '50%',
                      border: `2px solid ${ringColor}`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: ringColor,
                      fontSize: '1rem',
                      flexShrink: 0,
                      boxShadow: `0 0 14px ${ringColor}50`,
                    }}
                  >
                    {roman}
                  </div>
                  <div>
                    <h2 className="font-long text-3xl uppercase" style={{ color: '#FFD700', lineHeight: 1.1 }}>
                      {act.name}
                    </h2>
                    <p className="font-mono text-xs" style={{ color: '#6b7280', marginTop: '2px' }}>
                      {act.desc}
                    </p>
                  </div>
                </div>

                {/* Right: cleared counter */}
                <div
                  className="font-mono text-sm"
                  style={{
                    background: 'rgba(255,255,255,0.05)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    padding: '0.4rem 1rem',
                    borderRadius: '0.5rem',
                    color: clearedCount === act.items.length ? '#39FF14' : '#9ca3af',
                    whiteSpace: 'nowrap',
                  }}
                >
                  <span style={{ color: '#39FF14', fontWeight: 'bold' }}>{clearedCount}</span>
                  <span style={{ color: '#6b7280' }}> / {act.items.length} CLEARED</span>
                </div>
              </div>

              {/* Card grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {act.items.map(mission => {
                  const isSolved = solvedIds.has(mission.ctfd_id) || solvedIds.has(mission.id);
                  return (
                    <MissionCard
                      key={mission.ctfd_id || mission.name}
                      mission={mission}
                      isSolved={isSolved}
                      navigate={navigate}
                    />
                  );
                })}
              </div>
            </section>
          );
        })}

        {/* ── EMPTY STATE ────────────────────────────────────────────────── */}
        {filteredChallenges.length === 0 && !loading && (
          <div
            className="font-mono text-center"
            style={{
              background: 'rgba(255,255,255,0.03)',
              border: '1px solid rgba(255,255,255,0.08)',
              padding: '3rem 1rem',
              borderRadius: '1rem',
              color: '#6b7280',
            }}
          >
            NO MISSIONS MATCH THE CURRENT FILTER.
          </div>
        )}

      </main>
    </div>
  );
}
