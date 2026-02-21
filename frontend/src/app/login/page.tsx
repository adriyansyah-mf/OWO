'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login, token, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && token) {
      router.replace('/');
    }
  }, [token, isLoading, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    const ok = await login(username, password);
    setLoading(false);
    if (ok) {
      router.push('/');
    } else {
      setError('Invalid username or password');
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
          <div className="logo-icon" style={{ width: 40, height: 40 }}>
            <svg viewBox="0 0 24 24" style={{ width: 22, height: 22 }}><path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7L12 2z" fill="white"/></svg>
          </div>
          <div>
            <h1>OWO</h1>
            <p>Open Workstation Observer — Sign in to continue</p>
          </div>
        </div>
        <form onSubmit={handleSubmit}>
          <label>Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="admin"
            autoComplete="username"
            required
          />
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            autoComplete="current-password"
            required
          />
          {error && <div className="login-error">{error}</div>}
          <button type="submit" className="btn-login" disabled={loading}>
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}
