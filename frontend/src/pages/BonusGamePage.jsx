import { useCallback, useEffect, useRef, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import NavBar from '../sections/NavBar';

// ─────────────────────────────────────────────────────────────────────────────
// On-site bonus mini-games. Winning a game reveals a 16-byte ASCII key that the
// participant then applies BY HAND to the matching downloaded artefact.
// The keys are stored base64-encoded so they are not grep-able in the bundle,
// and are only decoded on a successful win.
// ─────────────────────────────────────────────────────────────────────────────

const softAtob = (s) => {
  try { return window.atob(s); } catch { return ''; }
};

const GAMES = {
  simon: {
    mission: 'B01',
    title: 'SIMON SAYS: DISPATCH EDITION',
    blurb: 'Repeat the 8-note dispatch sequence with no mistake. One wrong tone resets the desk.',
    key: 'NUlNME4tRDE1UDRUQ0gtSw==',
  },
  reflex: {
    mission: 'B02',
    title: 'THE REFLEX JOB',
    blurb: 'Hit the window faster than the alarm. Clean, fast reactions only — the rig is unforgiving.',
    key: 'UjNGTDNYLVcxTkQwVy0yNg==',
  },
  terminal: {
    mission: 'B03',
    title: "CAPTAIN'S LOG, STAR DATE WHATEVER",
    blurb: "Tell the bridge terminal what it wants to hear and it prints the key.",
    key: 'V0FSUC1DMFJFLUszWS0yNg==',
  },
  idle: {
    mission: 'B04',
    title: 'ACHIEVEMENT UNLOCKED: TOUCHED GRASS',
    blurb: 'The rarest achievement there is. Do absolutely nothing for 30 seconds. Any input resets it.',
    key: 'VDBVQ0gzRC1HUjRTUy0yNg==',
  },
};

const ORDER = ['simon', 'reflex', 'terminal', 'idle'];

// ── shared bits ──────────────────────────────────────────────────────────────
function Panel({ children }) {
  return (
    <div className="hud-panel p-6 rounded-lg" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {children}
    </div>
  );
}

function KeyReveal({ keyText, mission }) {
  return (
    <div
      className="font-mono"
      style={{
        marginTop: '1rem',
        padding: '1rem',
        background: 'rgba(0,229,255,0.08)',
        border: '1px solid #00E5FF',
        borderRadius: '0.5rem',
        textAlign: 'center',
      }}
    >
      <div style={{ color: '#00E5FF', fontSize: '0.7rem', letterSpacing: '0.15em', textTransform: 'uppercase' }}>
        ✓ Key recovered
      </div>
      <div style={{ color: '#fff', fontSize: '1.4rem', fontWeight: 700, margin: '0.4rem 0' }}>{keyText}</div>
      <div style={{ color: '#9ca3af', fontSize: '0.72rem' }}>
        Apply this key to the downloaded artefact for {mission} (see the mission card), then submit the flag.
      </div>
    </div>
  );
}

// ── B01 · Simon ──────────────────────────────────────────────────────────────
const PADS = [
  { color: '#39FF14', freq: 329.63 },
  { color: '#FF6EB0', freq: 415.30 },
  { color: '#00E5FF', freq: 523.25 },
  { color: '#FFD700', freq: 659.25 },
];

function SimonGame({ onWin }) {
  const SEQ_LEN = 8;
  const [seq, setSeq] = useState([]);
  const [step, setStep] = useState(0);
  const [active, setActive] = useState(-1);
  const [phase, setPhase] = useState('idle'); // idle | watch | repeat | won
  const seqRef = useRef([]);
  const stepRef = useRef(0);
  const audioRef = useRef(null);

  const beep = useCallback((freq, ms = 220) => {
    try {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      if (!audioRef.current) audioRef.current = new Ctx();
      const ctx = audioRef.current;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.frequency.value = freq;
      osc.type = 'sine';
      gain.gain.value = 0.15;
      osc.connect(gain).connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + ms / 1000);
    } catch { /* audio is optional */ }
  }, []);

  const playSequence = useCallback((list) => {
    setPhase('watch');
    let i = 0;
    const run = () => {
      if (i >= list.length) { setPhase('repeat'); return; }
      const pad = list[i];
      setActive(pad);
      beep(PADS[pad].freq);
      setTimeout(() => setActive(-1), 320);
      i += 1;
      setTimeout(run, 520);
    };
    setTimeout(run, 600);
  }, [beep]);

  const newRound = useCallback(() => {
    const list = Array.from({ length: SEQ_LEN }, () => Math.floor(Math.random() * 4));
    seqRef.current = list;
    stepRef.current = 0;
    setSeq(list);
    setStep(0);
    playSequence(list);
  }, [playSequence]);

  const handlePad = (idx) => {
    if (phase !== 'repeat') return;
    if (!seqRef.current.length) return;
    setActive(idx);
    beep(PADS[idx].freq, 180);
    setTimeout(() => setActive(-1), 200);
    if (seqRef.current[stepRef.current] === idx) {
      const next = stepRef.current + 1;
      stepRef.current = next;
      setStep(next);
      if (next >= seqRef.current.length) {
        setPhase('won');
        onWin();
      }
    } else {
      stepRef.current = 0;
      setStep(0);
      setPhase('idle');
      setTimeout(newRound, 400);
    }
  };

  return (
    <Panel>
      <div style={{ color: '#9ca3af', fontSize: '0.8rem' }}>
        {phase === 'idle' && 'Press START, watch the tones, then repeat them in order.'}
        {phase === 'watch' && 'WATCH — the desk is playing the sequence...'}
        {phase === 'repeat' && `YOUR TURN — ${step}/${SEQ_LEN}`}
        {phase === 'won' && 'SEQUENCE ACCEPTED.'}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem', maxWidth: '320px' }}>
        {PADS.map((p, i) => (
          <button
            key={i}
            onClick={() => handlePad(i)}
            disabled={phase !== 'repeat'}
            style={{
              height: '80px',
              borderRadius: '0.6rem',
              border: '1px solid rgba(255,255,255,0.15)',
              cursor: phase === 'repeat' ? 'pointer' : 'default',
              background: active === i ? p.color : 'rgba(255,255,255,0.06)',
              boxShadow: active === i ? `0 0 24px ${p.color}` : 'none',
              transition: 'background 0.08s, box-shadow 0.08s',
            }}
            aria-label={`pad ${i + 1}`}
          />
        ))}
      </div>

      {phase === 'idle' && (
        <button onClick={newRound} className="btn-heist py-2 px-5 font-bold cursor-pointer" style={{ width: 'fit-content' }}>
          ▶ START DISPATCH
        </button>
      )}
      {phase === 'won' && <KeyReveal keyText={softAtob(GAMES.simon.key)} mission="B01" />}
    </Panel>
  );
}

// ── B02 · Reflex ─────────────────────────────────────────────────────────────
function ReflexGame({ onWin }) {
  const [phase, setPhase] = useState('idle'); // idle|wait|go|slow|early|won
  const [ms, setMs] = useState(null);
  const startRef = useRef(0);
  const timerRef = useRef(null);

  const arm = () => {
    setMs(null);
    setPhase('wait');
    const delay = 1200 + Math.random() * 2600;
    timerRef.current = setTimeout(() => {
      startRef.current = performance.now();
      setPhase('go');
    }, delay);
  };

  useEffect(() => () => clearTimeout(timerRef.current), []);

  const handlePad = () => {
    if (phase === 'wait') { clearTimeout(timerRef.current); setPhase('early'); return; }
    if (phase !== 'go') return;
    const dt = Math.round(performance.now() - startRef.current);
    setMs(dt);
    if (dt < 200) { setPhase('won'); onWin(); } else { setPhase('slow'); }
  };

  const padColor = phase === 'go' ? '#39FF14' : phase === 'wait' ? '#FF8C00' : '#1b1b2e';

  return (
    <Panel>
      <div style={{ color: '#9ca3af', fontSize: '0.8rem' }}>
        {phase === 'idle' && 'Press ARM. When the pad turns green, click it under 200 ms.'}
        {phase === 'wait' && 'WAIT for green... clicking now is a false start.'}
        {phase === 'go' && 'NOW!'}
        {phase === 'early' && 'False start — the grid resets.'}
        {phase === 'slow' && `Too slow (${ms} ms). Need < 200 ms.`}
        {phase === 'won' && `Clean hit: ${ms} ms.`}
      </div>

      <button
        onClick={handlePad}
        style={{
          height: '150px',
          borderRadius: '0.6rem',
          border: '1px solid rgba(255,255,255,0.15)',
          background: padColor,
          cursor: phase === 'wait' || phase === 'go' ? 'pointer' : 'default',
          boxShadow: phase === 'go' ? '0 0 30px #39FF14' : 'none',
          transition: 'background 0.05s',
          color: '#fff',
          fontWeight: 700,
        }}
      >
        {phase === 'idle' ? 'ARM' : phase === 'won' ? 'LOCKED' : 'TARGET'}
      </button>

      {(phase === 'idle' || phase === 'early' || phase === 'slow') && (
        <button onClick={arm} className="btn-heist py-2 px-5 font-bold cursor-pointer" style={{ width: 'fit-content' }}>
          {phase === 'idle' ? '▶ ARM ALARM' : '↻ RETRY'}
        </button>
      )}
      {phase === 'won' && <KeyReveal keyText={softAtob(GAMES.reflex.key)} mission="B02" />}
    </Panel>
  );
}

// ── B03 · Terminal ───────────────────────────────────────────────────────────
function TerminalGame({ onWin }) {
  const [log, setLog] = useState([
    'LCARS bridge terminal — USS OVERRIDE',
    "Type 'help' for a list of commands.",
  ]);
  const [input, setInput] = useState('');
  const [unlocked, setUnlocked] = useState(false);
  const [won, setWon] = useState(false);
  const endRef = useRef(null);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [log]);

  const push = (...lines) => setLog((l) => [...l, ...lines]);

  const submit = (e) => {
    e.preventDefault();
    const cmd = input.trim();
    setInput('');
    if (!cmd) return;
    push('bridge> ' + cmd);

    if (cmd === 'help') {
      push('  help', '  scan', '  unlock --code <code>', '  override warp', '  status');
    } else if (cmd === 'scan') {
      push('  scanning... alien relay detected. One command requires the override code.');
    } else if (cmd === 'status') {
      push(unlocked ? '  systems: override latched.' : '  systems: locked. Try unlocking.');
    } else if (cmd === 'unlock --code 4702') {
      setUnlocked(true);
      push('  override code accepted. warp command armed.');
    } else if (cmd.startsWith('unlock')) {
      push('  override code rejected.');
    } else if (cmd === 'override warp') {
      if (!unlocked) { push('  denied: override not latched. unlock first.'); }
      else {
        setWon(true);
        push('  warp core spinning up...', `  KEY: ${softAtob(GAMES.terminal.key)}`);
        onWin();
      }
    } else {
      push('  unknown command: ' + cmd);
    }
  };

  return (
    <Panel>
      <div
        className="font-mono"
        style={{
          background: '#05050c', border: '1px solid rgba(0,229,255,0.3)', borderRadius: '0.5rem',
          padding: '1rem', height: '240px', overflowY: 'auto', fontSize: '0.82rem', color: '#9affea',
        }}
      >
        {log.map((l, i) => (<div key={i} style={{ whiteSpace: 'pre-wrap' }}>{l}</div>))}
        <div ref={endRef} />
      </div>
      <form onSubmit={submit} style={{ display: 'flex', gap: '0.5rem' }}>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="type a command..."
          className="heist-input rounded font-mono"
          autoComplete="off"
          spellCheck={false}
        />
        <button type="submit" className="btn-heist py-2 px-5 font-bold cursor-pointer">RUN</button>
      </form>
      {won && <KeyReveal keyText={softAtob(GAMES.terminal.key)} mission="B03" />}
    </Panel>
  );
}

// ── B04 · Idle ───────────────────────────────────────────────────────────────
function IdleGame({ onWin }) {
  const TARGET = 30; // seconds
  const [active, setActive] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [won, setWon] = useState(false);
  const wonRef = useRef(false);

  useEffect(() => {
    if (!active || won) return undefined;
    const events = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart', 'wheel'];
    const reset = () => setElapsed(0);
    events.forEach((ev) => window.addEventListener(ev, reset, { passive: true }));

    const started = Date.now();
    const tick = setInterval(() => {
      if (wonRef.current) return;
      const secs = (Date.now() - started) / 1000;
      setElapsed(secs);
      if (secs >= TARGET) {
        wonRef.current = true;
        clearInterval(tick);
        setWon(true);
        onWin();
      }
    }, 200);

    return () => {
      events.forEach((ev) => window.removeEventListener(ev, reset));
      clearInterval(tick);
    };
  }, [active, won, onWin]);

  const pct = Math.min(100, Math.round((elapsed / TARGET) * 100));

  return (
    <Panel>
      <div style={{ color: '#9ca3af', fontSize: '0.8rem' }}>
        {!active && 'Press BEGIN, then leave this page completely alone. Do not move the mouse.'}
        {active && !won && 'DO NOTHING. Any mouse move, key press, scroll or click resets the timer.'}
        {won && 'ACHIEVEMENT UNLOCKED: TOUCHED GRASS.'}
      </div>
      <div style={{ background: 'rgba(255,255,255,0.08)', borderRadius: '999px', height: '14px', overflow: 'hidden' }}>
        <div
          style={{
            width: `${pct}%`, height: '100%', background: won ? '#39FF14' : '#00E5FF',
            transition: 'width 0.2s linear',
          }}
        />
      </div>
      <div className="font-mono" style={{ color: '#6b7280', fontSize: '0.78rem' }}>
        IDLE: {Math.floor(elapsed)}s / {TARGET}s
      </div>
      {!active && (
        <button onClick={() => setActive(true)} className="btn-heist py-2 px-5 font-bold cursor-pointer" style={{ width: 'fit-content' }}>
          ▶ BEGIN DOING NOTHING
        </button>
      )}
      {won && <KeyReveal keyText={softAtob(GAMES.idle.key)} mission="B04" />}
    </Panel>
  );
}

const COMPONENTS = { simon: SimonGame, reflex: ReflexGame, terminal: TerminalGame, idle: IdleGame };

// ── page ─────────────────────────────────────────────────────────────────────
export default function BonusGamePage() {
  const { game } = useParams();
  const slug = COMPONENTS[game] ? game : 'simon';
  const cfg = GAMES[slug];
  const Comp = COMPONENTS[slug];
  const [won, setWon] = useState(false);
  const onWin = useCallback(() => setWon(true), []);

  return (
    <div className="app-bg min-h-screen text-white pb-20">
      <NavBar />
      <main className="max-w-3xl mx-auto pt-28 px-4 sm:px-6 space-y-6">
        <div className="flex justify-between items-center text-xs font-mono text-gray-400">
          <Link to="/missions" className="hover:text-pink transition">← MISSION BOARD</Link>
          <span className="text-gray-600">BONUS MINI-GAME // {cfg.mission}</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          <span className="font-mono text-xs uppercase tracking-widest" style={{ color: '#00E5FF' }}>
            BONUS WAVE · INTERACTIVE
          </span>
          <h1 className="font-long text-4xl uppercase" style={{ color: '#fff' }}>{cfg.title}</h1>
          <p className="font-mono text-sm" style={{ color: '#9ca3af' }}>{cfg.blurb}</p>
        </div>

        <Comp key={slug} onWin={onWin} />

        <div className="hud-panel p-4 rounded-lg" style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
          <span className="font-mono text-xs" style={{ color: '#9ca3af' }}>
            {won ? '✓ Key revealed above — apply it to the downloaded artefact.' : 'Win the game to reveal the key.'}
          </span>
          <Link to={`/mission/${cfg.mission}`} className="btn-outline-heist py-1.5 px-4 text-xs font-mono">
            OPEN {cfg.mission} DOSSIER →
          </Link>
        </div>

        <div className="flex gap-3 flex-wrap">
          {ORDER.map((s) => (
            <Link
              key={s}
              to={`/bonus/${s}`}
              className="font-mono text-xs py-1.5 px-3 rounded"
              style={{
                border: '1px solid rgba(255,255,255,0.15)',
                color: s === slug ? '#00E5FF' : '#9ca3af',
                borderColor: s === slug ? '#00E5FF' : 'rgba(255,255,255,0.15)',
              }}
            >
              {GAMES[s].mission} · {s}
            </Link>
          ))}
        </div>
      </main>
    </div>
  );
}
