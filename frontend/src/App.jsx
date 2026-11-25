import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Routes, Route, useLocation } from 'react-router-dom';
import { useEffect, useRef } from 'react';

import { AuthProvider } from './hooks/useAuth';
import ProtectedRoute from './components/ProtectedRoute';

// Pages
import LandingPage    from './pages/LandingPage';
import LoginPage      from './pages/LoginPage';
import RegisterPage   from './pages/RegisterPage';
import Dashboard      from './pages/Dashboard';
import MissionsPage   from './pages/MissionsPage';
import MissionBriefing from './pages/MissionBriefing';
import BonusGamePage   from './pages/BonusGamePage';
import LeaderboardPage from './pages/LeaderboardPage';
import CrewPage       from './pages/CrewPage';
import IntelPage      from './pages/IntelPage';
import NotFoundPage   from './pages/NotFoundPage';

gsap.registerPlugin(ScrollTrigger);

function ScrollToTop() {
  const { pathname } = useLocation();
  const prevPathRef = useRef(pathname);

  useEffect(() => {
    // Only kill triggers when actually transitioning AWAY from a page that had them
    if (prevPathRef.current !== pathname) {
      if (prevPathRef.current === '/') {
        ScrollTrigger.getAll().forEach(t => t.kill());
      }
      prevPathRef.current = pathname;
    }
    window.scrollTo(0, 0);
  }, [pathname]);

  return null;
}

export default function App() {
  return (
    <AuthProvider>
      <ScrollToTop />
      <Routes>
        {/* Public routes */}
        <Route path="/"           element={<LandingPage />} />
        <Route path="/login"      element={<LoginPage />} />
        <Route path="/register"   element={<RegisterPage />} />
        <Route path="/leaderboard" element={<LeaderboardPage />} />

        {/* Protected routes — require auth */}
        <Route path="/missions" element={
          <ProtectedRoute><MissionsPage /></ProtectedRoute>
        } />
        <Route path="/mission/:id" element={
          <ProtectedRoute><MissionBriefing /></ProtectedRoute>
        } />
        <Route path="/bonus/:game" element={
          <ProtectedRoute><BonusGamePage /></ProtectedRoute>
        } />
        <Route path="/dashboard" element={
          <ProtectedRoute><Dashboard /></ProtectedRoute>
        } />
        <Route path="/crew" element={
          <ProtectedRoute><CrewPage /></ProtectedRoute>
        } />
        <Route path="/intel" element={
          <ProtectedRoute><IntelPage /></ProtectedRoute>
        } />

        {/* 404 */}
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </AuthProvider>
  );
}
