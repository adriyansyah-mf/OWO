'use client';

import { createContext, useContext, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

export function getApiBase(): string {
  if (typeof window === 'undefined') return '';
  const base = process.env.NEXT_PUBLIC_API_URL;
  if (base) return base;
  return `${window.location.protocol}//${window.location.hostname}:8080`;
}

const TOKEN_KEY = 'edr_token';
const USER_KEY = 'edr_user';

export type UserRole = 'admin' | 'analyst' | 'readonly' | 'auditor';

export type AuthUser = {
  username: string;
  role: UserRole;
};

type AuthContextType = {
  token: string | null;
  user: AuthUser | null;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  isLoading: boolean;
  isAdmin: boolean;
  canWrite: boolean;
};

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const t = typeof window !== 'undefined' ? localStorage.getItem(TOKEN_KEY) : null;
    const u = typeof window !== 'undefined' ? localStorage.getItem(USER_KEY) : null;
    setToken(t);
    setUser(u ? JSON.parse(u) : null);
    setIsLoading(false);
  }, []);

  const login = async (username: string, password: string): Promise<boolean> => {
    const api = getApiBase();
    const res = await fetch(`${api || '/api'}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (res.ok && data.token) {
      const authUser: AuthUser = {
        username: data.username || username,
        role: (data.role as UserRole) || 'readonly',
      };
      localStorage.setItem(TOKEN_KEY, data.token);
      localStorage.setItem(USER_KEY, JSON.stringify(authUser));
      setToken(data.token);
      setUser(authUser);
      return true;
    }
    return false;
  };

  const logout = () => {
    if (token) {
      fetch(`${getApiBase() || '/api'}/api/v1/auth/logout`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => {});
    }
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setToken(null);
    setUser(null);
    router.push('/login');
  };

  const isAdmin = user?.role === 'admin';
  const canWrite = user?.role === 'admin' || user?.role === 'analyst';

  return (
    <AuthContext.Provider value={{ token, user, login, logout, isLoading, isAdmin, canWrite }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

export function getAuthHeaders(): Record<string, string> {
  if (typeof window === 'undefined') return {};
  const t = localStorage.getItem(TOKEN_KEY);
  if (!t) return {};
  return { Authorization: `Bearer ${t}` };
}
