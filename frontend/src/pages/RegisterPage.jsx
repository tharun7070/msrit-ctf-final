import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export default function RegisterPage() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [validationError, setValidationError] = useState('');
  const { register, error, setError } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setValidationError('');
    setError(null);

    if (password !== confirmPassword) {
      setValidationError('Access codes do not match.');
      return;
    }

    if (password.length < 6) {
      setValidationError('Access code must be at least 6 characters.');
      return;
    }

    setLoading(true);
    const success = await register({
      name: username.trim(),
      email: email.trim(),
      password,
    });
    setLoading(false);

    if (success) {
      navigate('/crew');
    }
  };

  return (
    <div className="app-bg min-h-screen flex-center px-4 py-12 relative overflow-hidden">
      <div className="absolute w-[600px] h-[600px] bg-cyan/10 rounded-full blur-[140px] pointer-events-none" />

      <div className="hud-panel max-w-md w-full p-8 rounded-lg relative z-10 border border-cyan/30 shadow-2xl">
        <div className="text-center mb-8">
          <Link to="/">
            <img src="/images/logo.webp" alt="FTA Logo" className="w-24 mx-auto mb-4 hover:scale-105 transition duration-300" />
          </Link>
          <h1 className="text-3xl font-long uppercase tracking-wider text-cyan">
            JOIN THE UNDERGROUND
          </h1>
          <p className="text-xs text-gray-400 mt-2 uppercase tracking-widest font-mono">
            REGISTER NEW OPERATIVE DOSSIER
          </p>
        </div>

        {(error || validationError) && (
          <div className="bg-red-950/80 border border-red-500/50 text-red-200 text-sm p-3 rounded mb-6 text-center font-mono">
            ⚠ {validationError || error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs uppercase tracking-widest text-gray-300 mb-2 font-mono">
              CALLSIGN (USERNAME)
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. razor_wire"
              className="heist-input rounded"
              autoFocus
              required
            />
          </div>

          <div>
            <label className="block text-xs uppercase tracking-widest text-gray-300 mb-2 font-mono">
              DISPATCH FREQUENCY (EMAIL)
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="operative@heist.local"
              className="heist-input rounded"
              required
            />
          </div>

          <div>
            <label className="block text-xs uppercase tracking-widest text-gray-300 mb-2 font-mono">
              SECURITY KEY (PASSWORD)
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

          <div>
            <label className="block text-xs uppercase tracking-widest text-gray-300 mb-2 font-mono">
              CONFIRM SECURITY KEY
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
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
            {loading ? <div className="spinner !size-5 !border-2" /> : '▶ ACTIVATE OPERATIVE'}
          </button>
        </form>

        <div className="mt-8 pt-6 border-t border-white/10 flex flex-col gap-3 text-center text-sm text-gray-400">
          <div>
            Already verified?{' '}
            <Link to="/login" className="text-cyan hover:underline font-bold">
              OPERATIVE LOGIN ↗
            </Link>
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
