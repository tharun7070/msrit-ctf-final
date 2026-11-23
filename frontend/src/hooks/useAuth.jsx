/**
 * useAuth — session state backed entirely by CTFd server session.
 * Never stores passwords or flags in state/localStorage.
 */
import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { getMe, login as apiLogin, logout as apiLogout, register as apiRegister } from '../services/ctfd';

const AuthCtx = createContext(null);

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
