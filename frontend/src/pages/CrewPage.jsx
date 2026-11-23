import { useState, useEffect } from 'react';
import { getMyTeam, createTeam, joinTeam, getTeamMembers } from '../services/ctfd';
import { useAuth } from '../hooks/useAuth';
import NavBar from '../sections/NavBar';

export default function CrewPage() {
  const { user } = useAuth();
  const [team, setTeam] = useState(null);
  const [members, setMembers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionError, setActionError] = useState(null);

  // Forms
  const [createName, setCreateName] = useState('');
  const [createPass, setCreatePass] = useState('');
  const [joinName, setJoinName] = useState('');
  const [joinPass, setJoinPass] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const fetchTeamData = async () => {
    setLoading(true);
    setActionError(null);
    try {
      const myTeam = await getMyTeam();
      setTeam(myTeam);
      if (myTeam?.id) {
        const mems = await getTeamMembers(myTeam.id).catch(() => []);
        setMembers(mems);
      }
    } catch {
      setTeam(null);
      setMembers([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTeamData();
  }, [user]);

  const handleCreateTeam = async (e) => {
    e.preventDefault();
    if (!createName || !createPass) return;
    setSubmitting(true);
    setActionError(null);
    try {
      await createTeam(createName.trim(), createPass);
      await fetchTeamData();
    } catch (err) {
      setActionError(err.response?.data?.errors?.name?.[0] || err.message || 'Failed to create crew');
    } finally {
      setSubmitting(false);
    }
  };

  const handleJoinTeam = async (e) => {
    e.preventDefault();
    if (!joinName || !joinPass) return;
    setSubmitting(true);
    setActionError(null);
    try {
      await joinTeam(joinName.trim(), joinPass);
      await fetchTeamData();
    } catch (err) {
      setActionError(err.response?.data?.errors?.name?.[0] || err.message || 'Failed to join crew. Check credentials.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="app-bg min-h-screen text-white pb-20">
      <NavBar />

      <main className="max-w-5xl mx-auto pt-28 px-4 sm:px-6 lg:px-8 space-y-8">

        {/* PAGE HEADER */}
        <div>
          <h1
            className="font-long text-5xl uppercase tracking-tight"
            style={{
              background: 'linear-gradient(90deg, #FF6EB0, #00E5FF)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
            }}
          >
            CREW MANAGEMENT
          </h1>
          <p className="font-mono text-sm text-gray-400 mt-1 uppercase tracking-widest">
            SYNDICATE DOSSIER · 2–3 OPERATIVES PER CREW
          </p>
        </div>

        {/* ERROR BANNER */}
        {actionError && (
          <div className="inline-flex items-center gap-2 bg-red-950/80 border border-red-500/60 text-red-300 text-sm font-mono px-5 py-3 rounded-full">
            <span className="text-red-400">⚠</span>
            {actionError}
          </div>
        )}

        {/* LOADING STATE */}
        {loading ? (
          <div className="flex-center py-20 flex-col gap-4">
            <div className="spinner" />
            <span className="text-sm font-mono text-gray-400">PULLING DOSSIER FROM ARCHIVES...</span>
          </div>
        ) : team ? (
          /* ── HAS TEAM: ACTIVE CREW CARD ── */
          <div
            className="bg-[#0d0d1a] rounded-2xl p-8 relative overflow-hidden space-y-6"
            style={{ border: '2px solid rgba(255,249,203,0.4)' }}
          >
            {/* Watermark */}
            <div className="absolute right-6 bottom-6 text-7xl font-long text-white/5 select-none pointer-events-none uppercase">
              CLASSIFIED
            </div>

            {/* Top section */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-white/10 pb-6">
              <div>
                <span
                  className="inline-block text-xs font-mono uppercase tracking-widest font-bold px-3 py-1 rounded-full mb-3"
                  style={{
                    background: 'rgba(255,249,203,0.1)',
                    color: '#fff9cb',
                    border: '1px solid rgba(255,249,203,0.3)',
                  }}
                >
                  ● REGISTERED SYNDICATE
                </span>
                <h2 className="text-4xl font-long text-white mt-1 uppercase">
                  {team.name}
                </h2>
                <p className="text-xs font-mono text-gray-400 mt-1">
                  CREW ID #{team.id} · AFFILIATION ACTIVE
                </p>
              </div>

              <div className="text-right font-mono">
                <span className="text-xs text-gray-400 block uppercase mb-1">COLLECTIVE BOUNTY</span>
                <span className="text-4xl font-long" style={{ color: '#39FF14' }}>
                  ${team.score?.toLocaleString() || 0}
                </span>
              </div>
            </div>

            {/* Operative Roster */}
            <div className="space-y-4">
              <h3 className="text-sm font-mono uppercase text-gray-300 tracking-wider">
                ACTIVE OPERATIVE ROSTER ({members.length} / 3 MAXIMUM)
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {members.map((m, idx) => (
                  <div
                    key={m.id || idx}
                    className="rounded-xl bg-white/5 border border-white/10 p-5"
                  >
                    <div className="flex justify-between items-center mb-3">
                      <span className="text-xs font-mono font-bold" style={{ color: '#FF6EB0' }}>
                        {idx === 0 ? '👑 CREW CAPTAIN' : 'OPERATIVE'}
                      </span>
                      <span className="w-2 h-2 rounded-full" style={{ background: '#39FF14' }} />
                    </div>
                    <span className="text-lg font-bold text-white block">{m.name}</span>
                    <span className="text-xs font-mono text-gray-500 block mt-1">
                      Score: ${m.score || 0}
                    </span>
                  </div>
                ))}

                {/* Empty slots */}
                {Array.from({ length: Math.max(0, 3 - members.length) }).map((_, i) => (
                  <div
                    key={`empty-${i}`}
                    className="rounded-xl p-5 flex flex-col items-center justify-center border-2 border-dashed border-white/20 text-gray-500 font-mono text-xs text-center gap-1 min-h-[100px]"
                  >
                    <span className="text-2xl text-gray-600">+</span>
                    <span>OPEN CREW SLOT</span>
                    <span className="text-[10px] text-gray-600">Invite teammate with crew key</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Footer */}
            <div className="pt-4 border-t border-white/10 flex flex-col md:flex-row justify-between gap-2 text-xs font-mono text-gray-400">
              <span>INVITE INSTRUCTION: Share your exact Crew Name and Passcode with teammates.</span>
              <span style={{ color: '#fff9cb' }}>TEAM LIMIT: 3 OPERATIVES MAXIMUM</span>
            </div>
          </div>
        ) : (
          /* ── NO TEAM: CREATE OR JOIN ── */
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">

            {/* FOUND A NEW CREW */}
            <div
              className="bg-[#0d0d1a] rounded-2xl p-8 space-y-5"
              style={{ border: '2px solid rgba(255,110,176,0.4)' }}
            >
              <div>
                <h2 className="text-2xl font-long uppercase tracking-wider" style={{ color: '#FF6EB0' }}>
                  FOUND A NEW CREW
                </h2>
                <p className="text-xs font-mono text-gray-400 mt-1">
                  Register as Captain. Set a secure crew passcode so teammates can join.
                </p>
              </div>

              <form onSubmit={handleCreateTeam} className="space-y-4">
                <div>
                  <label className="block text-xs uppercase font-mono text-gray-300 mb-1">
                    CREW CALLSIGN
                  </label>
                  <input
                    type="text"
                    value={createName}
                    onChange={(e) => setCreateName(e.target.value)}
                    placeholder="e.g. Vinewood Syndicate"
                    className="heist-input rounded text-sm"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs uppercase font-mono text-gray-300 mb-1">
                    JOIN PASSCODE
                  </label>
                  <input
                    type="password"
                    value={createPass}
                    onChange={(e) => setCreatePass(e.target.value)}
                    placeholder="••••••••"
                    className="heist-input rounded text-sm"
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={submitting}
                  className="btn-heist w-full py-3 text-xs font-mono font-bold cursor-pointer"
                >
                  {submitting ? 'ESTABLISHING...' : '▶ COMMISSION CREW'}
                </button>
              </form>
            </div>

            {/* JOIN EXISTING CREW */}
            <div
              className="bg-[#0d0d1a] rounded-2xl p-8 space-y-5"
              style={{ border: '2px solid rgba(0,229,255,0.4)' }}
            >
              <div>
                <h2 className="text-2xl font-long uppercase tracking-wider" style={{ color: '#00E5FF' }}>
                  JOIN EXISTING CREW
                </h2>
                <p className="text-xs font-mono text-gray-400 mt-1">
                  Enter your crew captain's callsign and secret passcode to enlist.
                </p>
              </div>

              <form onSubmit={handleJoinTeam} className="space-y-4">
                <div>
                  <label className="block text-xs uppercase font-mono text-gray-300 mb-1">
                    CREW CALLSIGN
                  </label>
                  <input
                    type="text"
                    value={joinName}
                    onChange={(e) => setJoinName(e.target.value)}
                    placeholder="e.g. Vinewood Syndicate"
                    className="heist-input rounded text-sm"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs uppercase font-mono text-gray-300 mb-1">
                    CREW PASSCODE
                  </label>
                  <input
                    type="password"
                    value={joinPass}
                    onChange={(e) => setJoinPass(e.target.value)}
                    placeholder="••••••••"
                    className="heist-input rounded text-sm"
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={submitting}
                  className="btn-outline-heist w-full py-3 text-xs font-mono font-bold cursor-pointer"
                >
                  {submitting ? 'ENLISTING...' : 'ENLIST IN CREW →'}
                </button>
              </form>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
