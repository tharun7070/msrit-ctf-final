import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { getChallenge, getChallengeFiles, getChallengeHints, submitFlag, unlockHint, getHintContent, getMySolves, getMyTeam, getTeamSolves } from '../services/ctfd';
import { getChallengeMeta, ALL_15_CHALLENGES, BONUS_CHALLENGES, LEVEL_COLORS } from '../data/challengeMeta';
import { useAuth } from '../hooks/useAuth';
import NavBar from '../sections/NavBar';

// Unlocking a hint deducts from the crew's score (enforced server-side by CTFd).
const HINT_COST_BY_LEVEL = { Easy: 10, Medium: 20, Hard: 30 };
// Three wrong flag submissions lock this mission's terminal for 120 seconds.
const MAX_ATTEMPTS = 3;
const LOCKOUT_MS = 120 * 1000;

// Briefings must resolve across both waves (25 main + 10 bonus).
const ALL_CHALLENGES = [...ALL_15_CHALLENGES, ...BONUS_CHALLENGES];
const findChallenge = (ref) =>
  ALL_CHALLENGES.find(
    (c) =>
      String(c.id) === String(ref) ||
      String(c.ctfd_id) === String(ref) ||
      c.fta_id?.toLowerCase() === String(ref).toLowerCase()
  );

export default function MissionBriefing() {
  const { id } = useParams();
  const { user } = useAuth();
  const navigate = useNavigate();

  // Instant sync resolution so the briefing renders in 0ms without waiting for offline timeouts
  const initialChallenge = findChallenge(id) || ALL_15_CHALLENGES[0];

  const [challenge, setChallenge] = useState(initialChallenge);
  const [files, setFiles] = useState(
    (initialChallenge.files || []).map((f) => ({
      name: f,
      location: `/challenges/${(initialChallenge.level || 'EASY').toUpperCase()}/${initialChallenge.fta_id}/${f}`,
    }))
  );
  const [hints, setHints] = useState(
    (initialChallenge.hints || []).map((h, i) => ({
      id: `local-${i + 1}`,
      cost: HINT_COST_BY_LEVEL[initialChallenge.level] ?? 10,
      content: null,
      text: h,
    }))
  );
  const [unlockedHints, setUnlockedHints] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Submission state
  const [flag, setFlag] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submissionResult, setSubmissionResult] = useState(null); // 'correct' | 'incorrect' | 'already_solved'
  const [resultMessage, setResultMessage] = useState('');
  const [isSolved, setIsSolved] = useState(false);

  // Per-mission lockout state (3 wrong attempts -> 120s cooldown)
  const [wrongCount, setWrongCount] = useState(0);
  const [lockUntil, setLockUntil] = useState(0);
  const [nowTick, setNowTick] = useState(Date.now());

  // Active tab: 'briefing' | 'evidence' | 'hints'
  const [activeTab, setActiveTab] = useState('briefing');

  useEffect(() => {
    async function loadData() {
      if (!challenge) setLoading(true);
      setError(null);

      let cData = null;
      let fData = [];
      let hData = [];

      try {
        const [cRes, fRes, hRes] = await Promise.all([
          getChallenge(id).catch(() => null),
          getChallengeFiles(id).catch(() => []),
          getChallengeHints(id).catch(() => []),
        ]);
        cData = cRes;
        fData = fRes || [];
        hData = hRes || [];
      } catch (err) {
        // Continue to fallback
      }

      // If backend call returned null/empty, resolve from our canonical challenge set
      if (!cData || !cData.name) {
        cData = findChallenge(id) || ALL_15_CHALLENGES[0];
      }

      const meta = getChallengeMeta(cData.name || cData.fta_id || id) || {};
      const lvl = meta.level || cData.level || (cData.value === 50 ? 'Easy' : cData.value === 100 ? 'Medium' : cData.value === 25 ? 'Bonus' : 'Hard');
      const ftaId = meta.fta_id || cData.fta_id || (cData.name ? cData.name.slice(0, 3) : 'E01');
      const act = meta.act || cData.act || (lvl === 'Easy' ? 'The Street Job' : lvl === 'Medium' ? 'The Big Heist' : 'The Final Getaway');

      const fullChallenge = {
        ...meta,
        ...cData,
        id: cData.id || id,
        fta_id: ftaId,
        level: lvl,
        act,
        reward: meta.reward || cData.value || cData.reward || (lvl === 'Easy' ? 50 : lvl === 'Medium' ? 100 : lvl === 'Bonus' ? 25 : 160),
        location: meta.location || cData.location || 'Los Santos Underground',
        description: meta.briefing || cData.description || cData.briefing,
        briefing: meta.briefing || cData.briefing || cData.description,
        objective: meta.objective || cData.objective || 'Submit recovered flag to CTFd in FTA{...} format.',
      };

      // Ensure files array has downloadable locations
      const challengeFiles = (fData.length > 0 ? fData : (meta.files || cData.files || [])).map((f) => {
        if (typeof f === 'string') {
          return {
            name: f,
            location: `/challenges/${lvl.toUpperCase()}/${ftaId}/${f}`,
          };
        }
        return {
          name: f.name || f.location?.split('/').pop() || 'evidence_file',
          location: f.location || `/challenges/${lvl.toUpperCase()}/${ftaId}/${f.name}`,
        };
      });

      // Ensure hints array. Content stays locked until unlocked (unlock deducts score).
      const rawHints = hData.length > 0 ? hData : (meta.hints || cData.hints || []);
      const hintCost = HINT_COST_BY_LEVEL[lvl] ?? 10;
      const challengeHints = rawHints.map((h, i) => {
        if (typeof h === 'string') {
          return { id: `local-${i + 1}`, cost: hintCost, content: null, text: h };
        }
        return { ...h, cost: h.cost ?? hintCost, text: h.text || h.content || '' };
      });

      setChallenge(fullChallenge);
      setFiles(challengeFiles);
      setHints(challengeHints);

      // Preserve any hints the team already unlocked on the server.
      const alreadyUnlocked = {};
      challengeHints.forEach((h) => {
        if (!String(h.id).startsWith('local-') && h.content) alreadyUnlocked[h.id] = h.content;
      });
      if (Object.keys(alreadyUnlocked).length) {
        setUnlockedHints((prev) => ({ ...prev, ...alreadyUnlocked }));
      }

      // Check if already solved
      try {
        const team = await getMyTeam().catch(() => null);
        let solves = [];
        if (team?.id) {
          solves = await getTeamSolves(team.id).catch(() => []);
        } else {
          solves = await getMySolves().catch(() => []);
        }
        const solved = solves.some(
          (s) => String(s.challenge_id) === String(id) || String(s.challenge_id) === String(fullChallenge.id)
        );
        setIsSolved(solved);
      } catch (e) {
        // ignore offline solve check
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, [id]);

  // Load any active lockout for this mission (persists across reloads).
  useEffect(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(`fta_lock_${id}`) || 'null');
      setWrongCount(saved?.wrongCount || 0);
      setLockUntil(saved?.lockUntil || 0);
    } catch {
      setWrongCount(0);
      setLockUntil(0);
    }
  }, [id]);

  // 1s tick so the lockout countdown updates live.
  useEffect(() => {
    const tick = setInterval(() => setNowTick(Date.now()), 1000);
    return () => clearInterval(tick);
  }, []);

  const isLocked = lockUntil > nowTick;
  const lockedRemaining = Math.max(0, Math.ceil((lockUntil - nowTick) / 1000));

  const persistLock = (wrong, until) => {
    try {
      localStorage.setItem(`fta_lock_${id}`, JSON.stringify({ wrongCount: wrong, lockUntil: until }));
    } catch {
      // ignore storage errors
    }
  };

  const handleSubmitFlag = async (e) => {
    e.preventDefault();
    if (!flag.trim()) return;

    if (lockUntil > Date.now()) {
      setSubmissionResult('incorrect');
      setResultMessage('Submissions locked — too many failed attempts. Try again shortly.');
      return;
    }

    setSubmitting(true);
    setSubmissionResult(null);
    setResultMessage('');

    try {
      const resp = await submitFlag(id, flag.trim());
      const status = resp?.data?.status;
      const message = resp?.data?.message || '';

      if (status === 'correct') {
        setSubmissionResult('correct');
        setIsSolved(true);
        setFlag('');
        setWrongCount(0);
        setLockUntil(0);
        persistLock(0, 0);
      } else if (status === 'already_solved') {
        setSubmissionResult('already_solved');
        setIsSolved(true);
        setResultMessage(message || 'This mission was already cleared by your crew.');
        setWrongCount(0);
        setLockUntil(0);
        persistLock(0, 0);
      } else {
        // Any non-correct response counts as a wrong attempt.
        const next = wrongCount + 1;
        if (next >= MAX_ATTEMPTS) {
          const until = Date.now() + LOCKOUT_MS;
          setWrongCount(0);
          setLockUntil(until);
          persistLock(0, until);
          setSubmissionResult('incorrect');
          setResultMessage('3 failed attempts — flag submissions locked for 120 seconds.');
        } else {
          setWrongCount(next);
          persistLock(next, lockUntil);
          setSubmissionResult('incorrect');
          setResultMessage(message || `MISSION FAILED — INCORRECT FLAG RECEIVED (${MAX_ATTEMPTS - next} attempt(s) left)`);
        }
      }
    } catch (err) {
      setSubmissionResult('error');
      setResultMessage(err.response?.data?.errors?.join(', ') || 'Submission error. Check network connection.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleUnlockHint = async (hint) => {
    const cost = hint.cost || 0;
    const conf = window.confirm(
      cost > 0
        ? `Unlock this intel? $${cost} will be deducted from your crew's score.`
        : 'Unlock this intel? (no score cost)'
    );
    if (!conf) return;

    try {
      // The score deduction is applied server-side by CTFd when the unlock is accepted.
      await unlockHint(hint.id);
      const content = await getHintContent(hint.id).catch(() => null);
      setUnlockedHints((prev) => ({
        ...prev,
        [hint.id]: content?.content || hint.text || 'Intel unlocked',
      }));
    } catch (err) {
      alert('Intel remains locked: unlock failed and no score was deducted. ' + (err.message || 'Server unreachable'));
    }
  };

  if (loading && !challenge) {
    return (
      <div className="app-bg min-h-screen text-white flex-center flex-col gap-4">
        <NavBar />
        <div className="spinner" />
        <span className="font-mono text-sm text-gray-400 uppercase tracking-widest">
          DECRYPTING MISSION DOSSIER...
        </span>
      </div>
    );
  }

  if (error || !challenge) {
    return (
      <div className="app-bg min-h-screen text-white p-8 pt-28">
        <NavBar />
        <div className="max-w-md mx-auto hud-panel p-6 text-center rounded">
          <p className="text-red-400 font-mono mb-4">⚠ {error || 'Target not found in dispatch.'}</p>
          <Link to="/missions" className="btn-outline-heist py-2 px-4 text-xs font-mono">
            ← RETURN TO MISSION BOARD
          </Link>
        </div>
      </div>
    );
  }

  const levelColor = LEVEL_COLORS[challenge.level] || LEVEL_COLORS.Easy;
  const cashAmount = challenge.reward || challenge.value || 50;

  return (
    <div className="app-bg min-h-screen text-white pb-20">
      <NavBar />

      <main className="max-w-7xl mx-auto pt-28 px-4 sm:px-6 lg:px-8 space-y-8">
        {/* Breadcrumb & Navigation */}
        <div className="flex justify-between items-center text-xs font-mono text-gray-400">
          <Link to="/missions" className="hover:text-pink transition">
            ← MISSION BOARD
          </Link>
          <span className="text-gray-600">DOSSIER // {challenge.fta_id || challenge.id}</span>
        </div>

        {/* Mission Banner Header */}
        <div className="hud-panel p-6 rounded-lg flex flex-col md:flex-row justify-between items-start md:items-center gap-6 border-l-4" style={{ borderLeftColor: levelColor.text }}>
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span 
                className="px-2 py-0.5 rounded text-xs font-mono font-bold uppercase"
                style={{ background: levelColor.bg, color: levelColor.text }}
              >
                {challenge.level} // {challenge.category}
              </span>
              <span className="text-xs font-mono text-gray-400">📍 {challenge.location || 'Los Santos'}</span>
            </div>

            <h1 className="text-3xl md:text-4xl font-long uppercase text-white">
              {challenge.name}
            </h1>

            <p className="text-sm font-mono text-gray-400 mt-1">
              FOCUS: {challenge.topic || challenge.category}
            </p>
          </div>

          <div className="flex flex-col md:items-end gap-2">
            <span className="text-xs font-mono uppercase text-gray-400">BOUNTY REWARD</span>
            <span className="text-3xl md:text-4xl font-long text-cash">
              ${cashAmount}
            </span>
            {isSolved ? (
              <span className="px-3 py-1 rounded bg-cash/20 text-cash text-xs font-mono font-bold">
                ✓ MISSION CLEARED
              </span>
            ) : (
              <span className="px-3 py-1 rounded bg-pink/20 text-pink text-xs font-mono font-bold">
                ● ACTIVE CONTRACT
              </span>
            )}
          </div>
        </div>

        {/* Two Column Layout: Intel vs Submission */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Column (2 Cols): Intel, Evidence, Hints */}
          <div className="lg:col-span-2 space-y-6">
            {/* Tabs */}
            <div className="flex border-b border-white/10 gap-4">
              <button
                onClick={() => setActiveTab('briefing')}
                className={`pb-3 text-sm font-mono font-bold uppercase tracking-wider cursor-pointer border-b-2 transition ${
                  activeTab === 'briefing'
                    ? 'border-pink text-pink'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                MISSION BRIEFING
              </button>

              <button
                onClick={() => setActiveTab('evidence')}
                className={`pb-3 text-sm font-mono font-bold uppercase tracking-wider cursor-pointer border-b-2 transition ${
                  activeTab === 'evidence'
                    ? 'border-pink text-pink'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                EVIDENCE FILES ({files.length || challenge.files?.length || 0})
              </button>

              <button
                onClick={() => setActiveTab('hints')}
                className={`pb-3 text-sm font-mono font-bold uppercase tracking-wider cursor-pointer border-b-2 transition ${
                  activeTab === 'hints'
                    ? 'border-pink text-pink'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                TACTICAL INTEL ({hints.length || challenge.hints?.length || 0})
              </button>
            </div>

            {/* Tab: Briefing */}
            {activeTab === 'briefing' && (
              <div className="hud-panel p-6 rounded-lg space-y-4">
                {challenge.game && (
                  <Link
                    to={`/bonus/${challenge.game}`}
                    className="flex justify-between items-center gap-4 p-4 rounded cursor-pointer transition"
                    style={{ background: 'rgba(0,229,255,0.08)', border: '1px solid #00E5FF' }}
                  >
                    <div>
                      <div className="font-mono text-xs uppercase tracking-widest" style={{ color: '#00E5FF' }}>
                        🎮 INTERACTIVE COMPONENT — REQUIRED
                      </div>
                      <div className="font-mono text-xs text-gray-400 mt-1">
                        This job ships an on-site mini-game. Win it to recover the key, then apply it to the downloaded artefact.
                      </div>
                    </div>
                    <span className="btn-outline-heist py-1.5 px-4 text-xs font-mono whitespace-nowrap">
                      PLAY MINI-GAME →
                    </span>
                  </Link>
                )}

                <h3 className="text-sm font-mono uppercase text-gray-400 tracking-wider">
                  SITUATION BRIEFING
                </h3>
                <div className="prose prose-invert max-w-none text-gray-200 leading-relaxed font-sans text-base whitespace-pre-line">
                  {challenge.description || challenge.briefing || 'No public briefing available.'}
                </div>
              </div>
            )}

            {/* Tab: Evidence Files */}
            {activeTab === 'evidence' && (
              <div className="hud-panel p-6 rounded-lg space-y-4">
                <h3 className="text-sm font-mono uppercase text-gray-400 tracking-wider">
                  DOWNLOADABLE EVIDENCE ARTIFACTS
                </h3>
                <p className="text-xs font-mono text-gray-400">
                  Analyze all files inside an isolated environment. All files are authorized competition evidence.
                </p>

                <div className="space-y-3 mt-4">
                  {/* Real CTFd files if present */}
                  {files.length > 0 ? (
                    files.map((file, idx) => (
                      <div 
                        key={idx}
                        className="p-4 bg-white/5 border border-white/10 rounded flex justify-between items-center hover:border-pink/50 transition"
                      >
                        <div>
                          <span className="font-mono text-sm text-white block">
                            📦 {file.name || file}
                          </span>
                          <span className="text-xs text-gray-500 font-mono">ATTACHED BY DISPATCH</span>
                        </div>
                        <a
                          href={file.location || `/api/v1/files/${file.id}`}
                          download
                          className="btn-outline-heist py-1.5 px-4 text-xs font-mono"
                        >
                          DOWNLOAD ↓
                        </a>
                      </div>
                    ))
                  ) : challenge.files?.length > 0 ? (
                    challenge.files.map((fn, idx) => {
                      const fileName = typeof fn === 'string' ? fn : fn.name;
                      const fileLoc = typeof fn === 'string'
                        ? `/challenges/${(challenge.level || 'EASY').toUpperCase()}/${challenge.fta_id || 'E01'}/${fn}`
                        : fn.location;
                      return (
                        <div 
                          key={idx}
                          className="p-4 bg-white/5 border border-white/10 rounded flex justify-between items-center hover:border-pink/50 transition"
                        >
                          <div>
                            <span className="font-mono text-sm text-white block">
                              📦 {fileName}
                            </span>
                            <span className="text-xs text-cyan font-mono">AUTHORIZED EVIDENCE FILE</span>
                          </div>
                          <a
                            href={fileLoc}
                            download={fileName}
                            className="btn-outline-heist py-1.5 px-4 text-xs font-mono"
                          >
                            DOWNLOAD ↓
                          </a>
                        </div>
                      );
                    })
                  ) : (
                    <p className="text-sm text-gray-500 font-mono">No external files attached for this job.</p>
                  )}
                </div>
              </div>
            )}

            {/* Tab: Hints */}
            {activeTab === 'hints' && (
              <div className="hud-panel p-6 rounded-lg space-y-4">
                <h3 className="text-sm font-mono uppercase text-gray-400 tracking-wider">
                  PROGRESSIVE TACTICAL HINTS
                </h3>
                <p className="text-xs font-mono text-gray-400">
                  Each unlocked hint deducts points from your crew's score. Hints are optional.
                </p>

                <div className="space-y-4 mt-4">
                  {hints.length > 0 ? (
                    hints.map((hint, index) => {
                      const revealed = unlockedHints[hint.id];
                      const cost = hint.cost || 0;
                      return (
                        <div key={hint.id} className="p-4 bg-white/5 border border-white/10 rounded">
                          <div className="flex justify-between items-center">
                            <span className="font-mono text-xs uppercase text-yellow font-bold">
                              INTEL DROP #{index + 1}
                            </span>
                            {revealed ? (
                              <span className="font-mono text-xs text-cash font-bold">✓ UNLOCKED</span>
                            ) : (
                              <button
                                onClick={() => handleUnlockHint(hint)}
                                className="btn-outline-heist py-1 px-3 text-xs font-mono"
                              >
                                🔒 UNLOCK INTEL {cost > 0 ? `(-$${cost})` : '(FREE)'}
                              </button>
                            )}
                          </div>
                          {revealed ? (
                            <p className="text-sm text-gray-200 mt-2 font-mono bg-black/40 p-3 rounded border border-white/5">
                              {revealed}
                            </p>
                          ) : (
                            <p className="text-xs text-gray-500 mt-1 italic font-mono">
                              [CLASSIFIED] Unlocking this intel deducts ${cost} from your crew's score.
                            </p>
                          )}
                        </div>
                      );
                    })
                  ) : challenge.hints?.length > 0 ? (
                    challenge.hints.map((hText, index) => (
                      <div key={index} className="p-4 bg-white/5 border border-white/10 rounded font-mono">
                        <span className="text-xs uppercase text-yellow font-bold block mb-1">
                          INTEL DROP #{index + 1}
                        </span>
                        <p className="text-sm text-gray-200">{hText}</p>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-gray-500 font-mono">No tactical hints logged for this target.</p>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Right Column (1 Col): Flag Submission Terminal */}
          <div className="space-y-6">
            <div className="hud-panel p-6 rounded-lg border border-pink/30 space-y-4 shadow-xl">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-pink animate-ping" />
                <h3 className="text-lg font-long uppercase text-white tracking-wider">
                  SUBMIT RECOVERED FLAG
                </h3>
              </div>

              <p className="text-xs font-mono text-gray-400">
                Submit exact flag format: <span className="text-pink font-bold">FTA&#123;...&#125;</span>
              </p>

              {/* Status messages */}
              {submissionResult === 'correct' && (
                <div className="p-3 bg-green-950/80 border border-green-500/50 text-green-200 text-xs font-mono rounded">
                  ✓ MISSION PASSED — correct flag. <span className="text-cash font-bold">+${cashAmount}</span> credited to your crew.
                </div>
              )}

              {submissionResult === 'incorrect' && (
                <div className="p-3 bg-red-950/80 border border-red-500/50 text-red-200 text-xs font-mono rounded">
                  ✕ {resultMessage}
                </div>
              )}

              {submissionResult === 'already_solved' && (
                <div className="p-3 bg-yellow-950/80 border border-yellow-500/50 text-yellow-200 text-xs font-mono rounded">
                  ⚠ {resultMessage}
                </div>
              )}

              {submissionResult === 'error' && (
                <div className="p-3 bg-red-950/80 border border-red-500/50 text-red-200 text-xs font-mono rounded">
                  ⚠ {resultMessage}
                </div>
              )}

              {isLocked && (
                <div className="p-3 bg-red-950/80 border border-red-500/50 text-red-200 text-xs font-mono rounded">
                  ⛔ SUBMISSIONS LOCKED — 3 failed attempts. Retry in {lockedRemaining}s.
                </div>
              )}

              {!isLocked && wrongCount > 0 && (
                <div className="p-3 bg-yellow-950/80 border border-yellow-500/50 text-yellow-200 text-xs font-mono rounded">
                  ⚠ Attempt {wrongCount}/{MAX_ATTEMPTS} — wrong flags lock this terminal for 120s.
                </div>
              )}

              {!user ? (
                <div className="p-4 bg-white/5 border border-pink/30 rounded text-center space-y-3">
                  <span className="text-xs font-mono uppercase text-gray-400 block">
                    AUTHENTICATION REQUIRED TO SUBMIT
                  </span>
                  <Link to="/login" className="btn-heist block text-xs py-2.5 px-4 font-bold">
                    LOGIN TO TRANSMIT PROOF
                  </Link>
                </div>
              ) : (
                <form onSubmit={handleSubmitFlag} className="space-y-4">
                  <div>
                    <input
                      type="text"
                      value={flag}
                      onChange={(e) => setFlag(e.target.value)}
                      onPaste={(e) => e.preventDefault()}
                      onDrop={(e) => e.preventDefault()}
                      placeholder="FTA{...}"
                      disabled={submitting || isLocked}
                      className="heist-input rounded font-mono uppercase tracking-wider"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={submitting || !flag.trim() || isLocked}
                    className="btn-heist w-full py-3.5 flex-center gap-2 cursor-pointer disabled:opacity-50 font-bold"
                  >
                    {submitting ? (
                      <div className="spinner !size-5 !border-2" />
                    ) : isLocked ? (
                      `LOCKED ${lockedRemaining}s`
                    ) : (
                      '▶ TRANSMIT PROOF'
                    )}
                  </button>
                </form>
              )}

              <div className="pt-4 border-t border-white/10 text-xs font-mono text-gray-500 space-y-1">
                <p>• Verified directly against CTFd secure validator</p>
                <p>• Score credited immediately on correct transmission</p>
                <p>• Duplicate solves receive no additional cash</p>
                <p>• Three wrong flags lock this terminal for 120 seconds</p>
              </div>
            </div>

            {/* Quick Workbench Tool Link */}
            <div className="hud-panel p-5 rounded-lg text-center space-y-2">
              <span className="text-xs font-mono text-gray-400 uppercase">STUCK ON CIPHER OR ENCODING?</span>
              <Link 
                to="/intel"
                className="btn-outline-heist block py-2 text-xs font-mono font-bold"
              >
                ⚡ OPEN LESTER'S WORKBENCH
              </Link>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
