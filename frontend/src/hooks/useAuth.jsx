/**
 * useAuth — session state backed entirely by CTFd server session.
 * Never stores passwords or flags in state/localStorage.
 */
import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { getMe, login as apiLogin, logout as apiLogout, register as apiRegister } from '../services/ctfd';

const AuthCtx = createContext(null);

// ── Dev-only demo operative ───────────────────────────────────────────
// Lets you exercise the authenticated UI without a CTFd backend.
// `import.meta.env.DEV` is false in production builds, so this branch is
// dead-code-eliminated and can NEVER be used on the live site.
const DEMO_KEY  = 'fta_demo';
const DEMO_USER = { id: 9001, name: 'demo_operative', email: 'demo@flagtheftauto.cv', team_id: 9001, type: 'user' };

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(null);   // null = unknown, false = anon
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const refresh = useCallback(async () => {
    try {
      const me = await getMe();
      setUser(me);
    } catch {
      setUser(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const login = useCallback(async (name, password) => {
    setError(null);
    // Dev-only mock login — disabled in production builds.
    if (import.meta.env.DEV && name === 'demo' && password === 'demo1234') {
      sessionStorage.setItem(DEMO_KEY, '1');
      setUser(DEMO_USER);
      return true;
    }
    try {
      await apiLogin(name, password);
      await refresh();
      return true;
    } catch (e) {
      const msg = e.response?.data?.errors?.join(', ') || e.message || 'Login failed';
      setError(msg);
      return false;
    }
  }, [refresh]);

  const register = useCallback(async (fields) => {
    setError(null);
    try {
      await apiRegister(fields);
      await apiLogin(fields.name, fields.password);
      await refresh();
      return true;
    } catch (e) {
      const msg = e.response?.data?.errors?.join(', ') || e.message || 'Registration failed';
      setError(msg);
      return false;
    }
  }, [refresh]);

  const logout = useCallback(async () => {
    if (import.meta.env.DEV && sessionStorage.getItem(DEMO_KEY) === '1') {
      sessionStorage.removeItem(DEMO_KEY);
      setUser(false);
      return;
    }
    await apiLogout().catch(() => {});
    setUser(false);
  }, []);

  return (
    <AuthCtx.Provider value={{ user, loading, error, setError, login, logout, register, refresh }}>
      {children}
    </AuthCtx.Provider>
  );
}

export function useAuth() {
  return useContext(AuthCtx);
}
