import { Link } from 'react-router-dom';

export default function NotFoundPage() {
  return (
    <div className="app-bg min-h-screen flex-center px-4 text-white text-center">
      <div className="hud-panel max-w-md w-full p-8 rounded-lg border border-red-500/40 space-y-6">
        <div className="text-red-500 font-long text-7xl md:text-8xl tracking-wider">
          404
        </div>

        <div>
          <h1 className="text-2xl font-long uppercase text-white">
            OPERATIVE OUT OF BOUNDS
          </h1>
          <p className="text-xs font-mono text-gray-400 mt-2">
            This sector does not exist in Los Santos dispatch records.
          </p>
        </div>

        <div>
          <Link to="/" className="btn-heist inline-block py-3 px-8 text-xs font-mono font-bold">
            ← RETURN TO KNOWN TERRITORY
          </Link>
        </div>
      </div>
    </div>
  );
}
