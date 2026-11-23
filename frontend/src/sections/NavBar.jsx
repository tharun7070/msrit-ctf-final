import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

const NavBar = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  useGSAP(() => {
    gsap.from('nav', { opacity: 0, duration: 1, ease: 'power1.inOut' });
  });

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  return (
    <nav>
      <Link to="/" className="flex items-center gap-2">
        <img src="/images/nav-logo.svg" className="scale-90 w-16" alt="FTA Logo" />
        <span className="text-white font-bold tracking-widest text-sm hidden md:block">
          FTA | FLAG THEFT AUTO
        </span>
      </Link>

      <div className="flex items-center gap-4">
        {user ? (
          <>
            <Link to="/dashboard" className="nav-link">DASHBOARD</Link>
            <Link to="/missions" className="nav-link">MISSIONS</Link>
            <Link to="/leaderboard" className="nav-link">LEADERBOARD</Link>
            <button onClick={handleLogout} className="nav-link">LOGOUT</button>
          </>
        ) : (
          <>
            <Link to="/login" className="btn-heist text-sm py-2 px-4">ENTER THE HEIST</Link>
            <Link to="/missions" className="btn-outline-heist text-sm py-2 px-4">VIEW MISSIONS</Link>
          </>
        )}
      </div>
    </nav>
  );
};

export default NavBar;
