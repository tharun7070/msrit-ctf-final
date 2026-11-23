import { useState, useEffect } from 'react';
import { getStandings, getMyTeam } from '../services/ctfd';
import NavBar from '../sections/NavBar';

export default function LeaderboardPage() {
  const [standings, setStandings] = useState([]);
  const [myTeam, setMyTeam] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(new Date());

  const fetchScoreboard = async () => {
    try {
      const [list, team] = await Promise.allSettled([
        getStandings(),
        getMyTeam(),
      ]);
      if (list.status === 'fulfilled') {
        setStandings(list.value || []);
      }
      if (team.status === 'fulfilled') {
        setMyTeam(team.value);
      }
      setLastUpdated(new Date());
    } catch {
      // Keep existing data on polling error
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScoreboard();
    const interval = setInterval(fetchScoreboard, 10000); // 10s live poll
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app-bg min-h-screen text-white pb-20">
      <NavBar />

      <main className="max-w-6xl mx-auto pt-28 px-4 sm:px-6 lg:px-8 space-y-8">

        {/* Header */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-white/10 pb-6">
          <div>
            <span className="text-xs font-mono uppercase tracking-widest text-gray-400 font-bold block mb-1">
              LOS SANTOS POLICE DEPARTMENT // WANTED REGISTRY
            </span>
            <h1
              className="font-long text-5xl uppercase"
              style={{
                background: 'linear-gradient(90deg,#ff6eb0,#00e5ff)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}
            >
              LOS SANTOS MOST WANTED
            </h1>
            <p className="text-sm font-mono text-gray-400 mt-1">
              LIVE CREW STANDINGS // UPDATES AUTOMATICALLY EVERY 10 SECONDS
            </p>
          </div>

          {/* Live badge */}
          <div className="flex items-center gap-3 bg-white/5 border border-white/10 rounded-xl px-4 py-2 shrink-0">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-500 opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-500" />
            </span>
            <span className="font-mono text-xs font-bold text-white tracking-widest">LIVE</span>
            <span className="font-mono text-xs text-gray-400">
              LAST SYNC:{' '}
              <span className="text-[#00e5ff] font-bold">{lastUpdated.toLocaleTimeString()}</span>
            </span>
          </div>
        </div>

        {/* Podium Top 3 */}
        {!loading && standings.length >= 3 && (
          <div className="flex flex-col md:flex-row gap-6 items-end pt-4">

            {/* Rank 2 — Silver (left) */}
            <div className="flex-1 rounded-2xl bg-[#0d0d1a] border-2 border-gray-400/40 p-7 text-center order-2 md:order-1">
              <span className="text-xl font-long text-gray-400 block mb-1">#2 SILVER HEIST</span>
              <h3 className="text-lg font-round-bold uppercase truncate text-white mt-1">
                {standings[1].name}
              </h3>
              <div className="text-3xl font-long text-[#39FF14] mt-3">
                ${standings[1].score?.toLocaleString()}
              </div>
              <span className="text-xs font-mono text-gray-500 mt-1 block">
                {standings[1].solves?.length || '—'} Solves
              </span>
            </div>

            {/* Rank 1 — Gold (center, biggest) */}
            <div
              className="flex-1 rounded-2xl bg-[#0d0d1a] border-2 p-8 text-center order-1 md:order-2 md:scale-105 md:-translate-y-2"
              style={{
                borderColor: 'rgba(255,215,0,0.6)',
                boxShadow: '0 0 40px rgba(255,215,0,0.25)',
              }}
            >
              <span className="text-3xl font-long block mb-1" style={{ color: '#ffd700' }}>
                ★ #1 KINGPIN
              </span>
              <h3
                className="text-2xl font-round-bold uppercase truncate mt-1"
                style={{ color: '#ffd700' }}
              >
                {standings[0].name}
              </h3>
              <div className="text-4xl font-long text-[#39FF14] mt-3">
                ${standings[0].score?.toLocaleString()}
              </div>
              <span className="text-xs font-mono text-gray-400 mt-1 block">
                {standings[0].solves?.length || '—'} Solves
              </span>
            </div>

            {/* Rank 3 — Bronze (right) */}
            <div className="flex-1 rounded-2xl bg-[#0d0d1a] border-2 border-amber-700/40 p-7 text-center order-3">
              <span className="text-xl font-long text-amber-700 block mb-1">#3 BRONZE HEIST</span>
              <h3 className="text-lg font-round-bold uppercase truncate text-white mt-1">
                {standings[2].name}
              </h3>
              <div className="text-3xl font-long text-[#39FF14] mt-3">
                ${standings[2].score?.toLocaleString()}
              </div>
              <span className="text-xs font-mono text-gray-500 mt-1 block">
                {standings[2].solves?.length || '—'} Solves
              </span>
            </div>
          </div>
        )}

        {/* Rankings Table */}
        <div className="rounded-2xl bg-[#0d0d1a] border border-white/10 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-sm">
              <thead className="bg-white/5 uppercase text-xs text-gray-400 border-b border-white/10">
                <tr>
                  <th className="py-4 px-6 w-24">RANK</th>
                  <th className="py-4 px-6">CREW SYNDICATE</th>
                  <th className="py-4 px-6 text-right">TOTAL BOUNTY</th>
                  <th className="py-4 px-6 text-center w-36">STATUS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {standings.map((team, index) => {
                  const rank = index + 1;
                  const isMyCrew = myTeam && myTeam.id === team.id;
                  const isFirst = rank === 1;

                  return (
                    <tr
                      key={team.id || index}
                      className={`transition-colors ${index % 2 === 0 ? 'bg-white/[0.02]' : ''}`}
                      style={
                        isFirst
                          ? { borderLeft: '4px solid #fff9cb' }
                          : isMyCrew
                          ? { borderLeft: '4px solid #FF6EB0' }
                          : { borderLeft: '4px solid transparent' }
                      }
                    >
                      <td className="py-4 px-6 font-bold">
                        {isFirst && <span className="mr-1" style={{ color: '#ffd700' }}>★</span>}
                        #{rank}
                      </td>

                      <td className="py-4 px-6">
                        <span className="font-bold text-white block">{team.name}</span>
                        {isMyCrew && (
                          <span
                            className="text-xs font-mono font-bold px-2 py-0.5 rounded mt-0.5 inline-block"
                            style={{ color: '#FF6EB0', background: 'rgba(255,110,176,0.12)', border: '1px solid rgba(255,110,176,0.3)' }}
                          >
                            YOUR CREW
                          </span>
                        )}
                      </td>

                      <td className="py-4 px-6 text-right font-long text-xl text-[#39FF14]">
                        ${team.score?.toLocaleString() || 0}
                      </td>

                      <td className="py-4 px-6 text-center">
                        <span className="px-2.5 py-1 rounded text-xs uppercase bg-white/5 border border-white/10 text-gray-300">
                          ACTIVE
                        </span>
                      </td>
                    </tr>
                  );
                })}

                {standings.length === 0 && !loading && (
                  <tr>
                    <td colSpan={4} className="py-12 text-center text-gray-500 font-mono text-sm">
                      NO CREWS LOGGED IN STANDINGS YET. FIRST FLAG WINS THE SPOTLIGHT!
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

      </main>
    </div>
  );
}
