'use client';

import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { getApiBase } from './AuthContext';

export type AlertToast = {
  id: string;
  title: string;
  message?: string;
  severity: string;
  host_id?: string;
  created_at?: string;
};

type AlertStreamContextType = {
  toasts: AlertToast[];
  dismissToast: (id: string) => void;
};

const AlertStreamContext = createContext<AlertStreamContextType>({
  toasts: [],
  dismissToast: () => {},
});

export function AlertStreamProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<AlertToast[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  useEffect(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('edr_token') : null;
    if (!token) return;

    const api = getApiBase() || 'http://localhost:8080';
    const url = `${api.replace(/\/$/, '')}/api/v1/alerts/stream?token=${encodeURIComponent(token)}`;
    const eventSource = new EventSource(url);

    eventSource.onmessage = (e) => {
      try {
        const a = JSON.parse(e.data);
        const toast: AlertToast = {
          id: a.id || 't-' + Date.now(),
          title: a.title || a.rule_name || 'Alert',
          message: a.message,
          severity: a.severity || 'info',
          host_id: a.host_id,
          created_at: a.created_at,
        };
        setToasts((prev) => {
          const exists = prev.some((t) => t.id === toast.id);
          if (exists) return prev;
          const next = [...prev, toast];
          if (next.length > 5) return next.slice(-5);
          return next;
        });
      } catch {
        // ignore parse errors
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
    };

    return () => eventSource.close();
  }, []);

  return (
    <AlertStreamContext.Provider value={{ toasts, dismissToast }}>
      {children}
    </AlertStreamContext.Provider>
  );
}

export function useAlertStream() {
  return useContext(AlertStreamContext);
}
