import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const { login, error, setError } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username || !password) {
      setError('Please provide operative ID and access code.');
      return;
    }
    setLoading(true);
    const success = await login(username, password);
    setLoading(false);
    if (success) {
      navigate('/dashboard');
    }
  };

  return (
    <div className="app-bg min-h-screen flex-center px-4 py-12 relative overflow-hidden">
      {/* Background radial glow */}
      <div className="absolute w-[600px] h-[600px] bg-pink/10 rounded-full blur-[140px] pointer-events-none" />

      <div className="hud-panel max-w-md w-full p-8 rounded-lg relative z-10 border border-pink/30 shadow-2xl">
        <div className="text-center mb-8">
          <Link to="/">
            <img src="/images/logo.webp" alt="FTA Logo" className="w-24 mx-auto mb-4 hover:scale-105 transition duration-300" />
          </Link>
          <h1 className="text-3xl font-long uppercase tracking-wider text-pink">
            WELCOME BACK, OUTLAW
          </h1>
          <p className="text-xs text-gray-400 mt-2 uppercase tracking-widest font-mono">
            AUTHENTICATE TO ACCESS MISSION TERMINAL
          </p>
        </div>

        {error && (
          <div className="bg-red-950/80 border border-red-500/50 text-red-200 text-sm p-3 rounded mb-6 text-center font-mono">
            ⚠ {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs uppercase tracking-widest text-gray-300 mb-2 font-mono">
              OPERATIVE ID (USERNAME)
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. ghost_driver"
              className="heist-input rounded"
              autoFocus
              required
            />
          </div>

          <div>
            <label className="block text-xs uppercase tracking-widest text-gray-300 mb-2 font-mono">
              ACCESS CODE (PASSWORD)
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="heist-input rounded"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-heist w-full py-3 text-center flex-center gap-2 mt-4 cursor-pointer disabled:opacity-50"
          >
            {loading ? <div className="spinner !size-5 !border-2" /> : '▶ LOGIN TO CREW'}
          </button>
        </form>

        <div className="mt-8 pt-6 border-t border-white/10 flex flex-col gap-3 text-center text-sm text-gray-400">
          <div>
            New operative? Registration is closed — collect your crew credentials from the organizers at check-in.
          </div>
          <div>
            <Link to="/" className="text-gray-500 hover:text-gray-300 text-xs">
              ← RETURN TO SURFACE
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
