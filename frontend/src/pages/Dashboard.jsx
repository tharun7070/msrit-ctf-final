import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { useChallenges } from '../hooks/useChallenges';
import { getMyTeam, getStandings } from '../services/ctfd';
import WantedStars from '../components/WantedStars';
import CountdownTimer from '../components/CountdownTimer';
import NavBar from '../sections/NavBar';

export default function Dashboard() {
  const { user } = useAuth();
  const { challenges, solvedIds, loading: challengesLoading } = useChallenges();
  const [team, setTeam] = useState(null);
  const [teamRank, setTeamRank] = useState(null);
  const [teamScore, setTeamScore] = useState(0);
  const navigate = useNavigate();

  useEffect(() => {
    async function loadTeamData() {
      try {
        const t = await getMyTeam();
        setTeam(t);
        if (t?.id) {
          const standings = await getStandings().catch(() => []);
          const idx = standings.findIndex((s) => s.id === t.id);
          if (idx !== -1) {
            setTeamRank(idx + 1);
            setTeamScore(standings[idx].score || 0);
          } else if (t.score !== undefined) {
            setTeamScore(t.score);
          }
        }
      } catch {
        setTeam(null);
      }
    }
    loadTeamData();
  }, [user]);

  // Calculate difficulty progress
  const easyChallenges = challenges.filter(c => c.level === 'Easy');
  const mediumChallenges = challenges.filter(c => c.level === 'Medium');
  const hardChallenges = challenges.filter(c => c.level === 'Hard');

  const easySolved = easyChallenges.filter(c => solvedIds.has(c.ctfd_id)).length;
  const mediumSolved = mediumChallenges.filter(c => solvedIds.has(c.ctfd_id)).length;
  const hardSolved = hardChallenges.filter(c => solvedIds.has(c.ctfd_id)).length;

  const totalSolved = solvedIds.size;
  const totalChallenges = challenges.length || 25;
  const totalBountyPossible = 2200;

  // Use team score if in team, otherwise calculate from solved challenges
  const effectiveCash = teamScore || (
    easySolved * 50 + mediumSolved * 100 + hardSolved * 160
  );

  const launchpad = [
    {
      emoji: '🎯',
      label: 'MISSION BOARD',
      sub: 'View all active contracts',
      path: '/missions',
      accent: '#FF6EB0',
      border: 'border-[#FF6EB0]/40',
      hoverBorder: 'hover:border-[#FF6EB0]',
      glow: 'hover:shadow-[0_0_30px_rgba(255,110,176,0.25)]',
    },
    {
      emoji: '🏆',
      label: 'LEADERBOARD',
      sub: 'Crew & operative rankings',
      path: '/leaderboard',
      accent: '#fff9cb',
      border: 'border-[#fff9cb]/30',
      hoverBorder: 'hover:border-[#fff9cb]',
      glow: 'hover:shadow-[0_0_30px_rgba(255,249,203,0.2)]',
    },
    {
      emoji: '⚡',
      label: 'INTEL WORKBENCH',
      sub: 'Decrypt & analyse files',
      path: '/intel',
      accent: '#00E5FF',
      border: 'border-[#00E5FF]/30',
      hoverBorder: 'hover:border-[#00E5FF]',
      glow: 'hover:shadow-[0_0_30px_rgba(0,229,255,0.2)]',
    },
    {
      emoji: '👥',
      label: 'CREW ROSTER',
      sub: 'Manage your syndicate',
      path: '/crew',
      accent: '#FF7A59',
      border: 'border-[#FF7A59]/30',
      hoverBorder: 'hover:border-[#FF7A59]',
      glow: 'hover:shadow-[0_0_30px_rgba(255,122,89,0.2)]',
    },
  ];

  return (
    <div className="app-bg min-h-screen text-white pb-20">
      <NavBar />

      <main className="max-w-7xl mx-auto pt-28 px-4 sm:px-6 lg:px-8 space-y-8">

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
            OPERATIVE HQ
          </h1>
          <p className="font-mono text-sm text-gray-400 mt-1 uppercase tracking-widest">
            LOGGED IN AS <span className="text-white">{user?.name}</span>
          </p>
        </div>

        {/* WELCOME BANNER CARD */}
        <div
          className="bg-[#0d0d1a] border border-white/10 rounded-2xl p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-6"
          style={{ borderLeft: '4px solid #FF6EB0' }}
        >
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#39FF14] animate-pulse" />
              <span className="text-xs uppercase font-mono text-gray-400 tracking-widest">
                OPERATIVE ACTIVE
              </span>
            </div>
            <h2 className="text-3xl md:text-4xl font-long uppercase text-white">
              {user?.name || 'OPERATIVE'}
            </h2>
            <p className="text-sm font-mono text-gray-400 mt-1">
              CREW:{' '}
              <span className="text-[#FF6EB0] font-bold">
                {team?.name || 'LONE WOLF (NO CREW)'}
              </span>
              {teamRank && (
                <span className="ml-3 text-[#00E5FF]">RANK #{teamRank}</span>
              )}
            </p>
          </div>

          <div className="flex flex-col md:items-end gap-2">
            <span className="text-xs font-mono uppercase text-gray-400">WANTED LEVEL</span>
            <WantedStars solved={totalSolved} total={totalChallenges} />
            <div className="mt-1">
              <CountdownTimer />
            </div>
          </div>
        </div>

        {/* STATS ROW */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Card 1: Heist Earnings */}
          <div className="bg-[#0d0d1a] border border-white/10 rounded-2xl overflow-hidden flex flex-col">
            <div style={{ height: 6, background: '#39FF14' }} />
            <div className="p-6 flex flex-col justify-between flex-1">
              <span className="text-xs font-mono uppercase tracking-wider text-gray-400">
                HEIST EARNINGS
              </span>
              <div
                className="font-long text-5xl mt-2 tracking-wide"
                style={{ color: '#39FF14' }}
              >
                ${effectiveCash.toLocaleString()}
              </div>
              <div className="mt-4 pt-4 border-t border-white/10 flex justify-between text-xs font-mono text-gray-400">
                <span>MAX AVAILABLE</span>
                <span className="text-white">${totalBountyPossible.toLocaleString()}</span>
              </div>
            </div>
          </div>

          {/* Card 2: Contracts Cracked */}
          <div className="bg-[#0d0d1a] border border-white/10 rounded-2xl overflow-hidden flex flex-col">
            <div style={{ height: 6, background: '#00E5FF' }} />
            <div className="p-6 flex flex-col justify-between flex-1">
              <span className="text-xs font-mono uppercase tracking-wider text-gray-400">
                CONTRACTS CRACKED
              </span>
              <div
                className="font-long text-5xl mt-2 tracking-wide"
                style={{ color: '#00E5FF' }}
              >
                {totalSolved}
                <span className="text-xl text-gray-500 font-sans ml-1">/ {totalChallenges}</span>
              </div>
              <div className="mt-4 pt-4 border-t border-white/10 flex justify-between text-xs font-mono text-gray-400">
                <span>COMPLETION RATE</span>
                <span className="text-white">
                  {Math.round((totalSolved / totalChallenges) * 100)}%
                </span>
              </div>
            </div>
          </div>

          {/* Card 3: Crew Dossier */}
          <div className="bg-[#0d0d1a] border border-white/10 rounded-2xl overflow-hidden flex flex-col">
            <div style={{ height: 6, background: '#fff9cb' }} />
            <div className="p-6 flex flex-col justify-between flex-1">
              <span className="text-xs font-mono uppercase tracking-wider text-gray-400">
                CREW DOSSIER
              </span>
              <div className="text-xl font-bold mt-2" style={{ color: '#fff9cb' }}>
                {team?.name || 'UNATTACHED OPERATIVE'}
              </div>
              <p className="text-xs text-gray-400 mt-1">
                {team
                  ? '2–3 Operative syndicate active'
                  : 'Teams of 2–3 get shared points and crew rank'}
              </p>
              <div className="mt-4 pt-4 border-t border-white/10">
                <Link
                  to="/crew"
                  className="text-xs font-mono uppercase tracking-wider font-bold flex items-center gap-1"
                  style={{ color: '#FF6EB0' }}
                >
                  {team ? 'MANAGE CREW DOSSIER →' : '+ ASSEMBLE CREW NOW →'}
                </Link>
              </div>
            </div>
          </div>
        </div>

        {/* ACT PROGRESSION */}
        <div className="bg-[#0d0d1a] border border-white/10 rounded-2xl p-6 space-y-6">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-long uppercase text-white tracking-wider">
              ACT PROGRESSION
            </h2>
            <Link
              to="/missions"
              className="text-xs font-mono uppercase font-bold hover:underline"
              style={{ color: '#FF6EB0' }}
            >
              VIEW MISSION BOARD ↗
            </Link>
          </div>

          <div className="space-y-5 font-mono text-sm">
            {/* Act I – Easy */}
            <div>
              <div className="flex justify-between mb-2">
                <span className="font-bold" style={{ color: '#39FF14' }}>
                  ACT I: THE STREET JOB (EASY)
                </span>
                <span className="text-gray-400">
                  {easySolved} / 10 SOLVED (${easySolved * 50} / $500)
                </span>
              </div>
              <div className="w-full bg-white/10 h-4 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${(easySolved / 10) * 100}%`,
                    background: '#39FF14',
                    boxShadow: '0 0 10px #39FF14aa',
                  }}
                />
              </div>
            </div>

            {/* Act II – Medium */}
            <div>
              <div className="flex justify-between mb-2">
                <span className="font-bold text-orange-400">
                  ACT II: THE BIG HEIST (MEDIUM)
                </span>
                <span className="text-gray-400">
                  {mediumSolved} / 5 SOLVED (${mediumSolved * 100} / $500)
                </span>
              </div>
              <div className="w-full bg-white/10 h-4 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${(mediumSolved / 5) * 100}%`,
                    background: '#fb923c',
                    boxShadow: '0 0 10px #fb923caa',
                  }}
                />
              </div>
            </div>

            {/* Act III – Hard */}
            <div>
              <div className="flex justify-between mb-2">
                <span className="font-bold text-red-500">
                  ACT III: THE FINAL GETAWAY (HARD)
                </span>
                <span className="text-gray-400">
                  {hardSolved} / 5 SOLVED (${hardSolved * 160} / $800)
                </span>
              </div>
              <div className="w-full bg-white/10 h-4 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${(hardSolved / 5) * 100}%`,
                    background: '#ef4444',
                    boxShadow: '0 0 10px #ef4444aa',
                  }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* QUICK LAUNCHPAD */}
        <div className="grid grid-cols-2 gap-4">
          {launchpad.map((tile) => (
            <button
              key={tile.path}
              onClick={() => navigate(tile.path)}
              className={`bg-[#0d0d1a] border ${tile.border} ${tile.hoverBorder} ${tile.glow} rounded-2xl p-8 flex flex-col items-center justify-center gap-3 hover:scale-[1.03] transition-all duration-200 cursor-pointer`}
            >
              <span className="text-5xl">{tile.emoji}</span>
              <span
                className="font-long text-lg uppercase tracking-wide"
                style={{ color: tile.accent }}
              >
                {tile.label}
              </span>
              <span className="text-xs font-mono text-gray-500 text-center">
                {tile.sub}
              </span>
            </button>
          ))}
        </div>
      </main>
    </div>
  );
}
