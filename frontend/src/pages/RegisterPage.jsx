import { Link } from 'react-router-dom';

/**
 * Self-registration is closed for this event: every crew is pre-provisioned
 * with organizer-issued credentials, so a group cannot enrol twice.
 * The CTFd backend also rejects POST /api/v1/users while registration is private.
 */
export default function RegisterPage() {
  return (
    <div className="app-bg min-h-screen flex-center px-4 py-12 relative overflow-hidden">
      <div className="absolute w-[600px] h-[600px] bg-cyan/10 rounded-full blur-[140px] pointer-events-none" />

      <div className="hud-panel max-w-md w-full p-8 rounded-lg relative z-10 border border-cyan/30 shadow-2xl">
        <div className="text-center mb-8">
          <Link to="/">
            <img src="/images/logo.webp" alt="FTA Logo" className="w-24 mx-auto mb-4 hover:scale-105 transition duration-300" />
          </Link>
          <h1 className="text-3xl font-long uppercase tracking-wider text-cyan">
            REGISTRATION CLOSED
          </h1>
          <p className="text-xs text-gray-400 mt-2 uppercase tracking-widest font-mono">
            CREWS ARE PRE-ENROLLED BY THE ORGANIZERS
          </p>
        </div>

        <div className="bg-cyan-950/40 border border-cyan/30 text-cyan-100 text-sm p-4 rounded mb-6 text-center font-mono leading-relaxed">
          No open sign-up for this heist. Use the operative credentials (callsign + security key)
          handed to your crew at check-in.
        </div>

        <Link
          to="/login"
          className="btn-heist w-full py-3 text-center flex-center gap-2 cursor-pointer"
        >
          ▶ OPERATIVE LOGIN
        </Link>

        <div className="mt-8 pt-6 border-t border-white/10 flex flex-col gap-3 text-center text-sm text-gray-400">
          <div>
            Lost your credentials? Contact an organizer at check-in.
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
