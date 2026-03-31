import { createContext, useContext, useEffect, useMemo, useState } from 'react';

import apiClient, { AUTH_SYNC_EVENT, clearStoredSession, storeSessionTokens } from '../api/client';

const AuthContext = createContext(null);

const readStoredSession = () => ({
  access: localStorage.getItem('aegis_access') || '',
  refresh: localStorage.getItem('aegis_refresh') || '',
  user: JSON.parse(localStorage.getItem('aegis_user') || 'null'),
});

function persistUser(user) {
  if (user) {
    localStorage.setItem('aegis_user', JSON.stringify(user));
  } else {
    localStorage.removeItem('aegis_user');
  }
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(AUTH_SYNC_EVENT));
  }
}

export function AuthProvider({ children }) {
  const [session, setSession] = useState(readStoredSession);

  useEffect(() => {
    const syncSession = () => setSession(readStoredSession());
    window.addEventListener(AUTH_SYNC_EVENT, syncSession);
    window.addEventListener('storage', syncSession);
    return () => {
      window.removeEventListener(AUTH_SYNC_EVENT, syncSession);
      window.removeEventListener('storage', syncSession);
    };
  }, []);

  const login = async (payload) => {
    const { data } = await apiClient.post('/auth/login/', payload);
    storeSessionTokens({ access: data.access, refresh: data.refresh });
    persistUser(data.user);
    setSession({ access: data.access, refresh: data.refresh, user: data.user });
    return data;
  };

  const register = async (payload) => {
    await apiClient.post('/auth/register/', payload);
    return login({ email: payload.email, password: payload.password });
  };

  const logout = async () => {
    try {
      const refresh = localStorage.getItem('aegis_refresh') || session.refresh;
      if (refresh) {
        await apiClient.post('/auth/logout/', { refresh });
      }
    } catch (_error) {
      // local cleanup still happens even if token blacklisting fails
    }
    clearStoredSession();
    setSession({ access: '', refresh: '', user: null });
  };

  const refreshProfile = async () => {
    const { data } = await apiClient.get('/auth/profile/');
    persistUser(data);
    setSession((current) => ({ ...current, user: data }));
    return data;
  };

  const updateProfile = async (payload) => {
    const { data } = await apiClient.patch('/auth/profile/', payload);
    persistUser(data);
    setSession((current) => ({ ...current, user: data }));
    return data;
  };

  const value = useMemo(() => ({
    ...session,
    isAuthenticated: Boolean(session.access),
    isAdmin: session.user?.role === 'admin',
    login,
    logout,
    register,
    refreshProfile,
    updateProfile,
  }), [session]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used inside AuthProvider');
  }
  return context;
}
