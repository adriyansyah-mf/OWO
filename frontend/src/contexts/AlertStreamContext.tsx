'use client';

import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
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
  subscribeToNewAlerts: (cb: (alert: AlertToast) => void) => () => void;
};

const AlertStreamContext = createContext<AlertStreamContextType>({
  toasts: [],
  dismissToast: () => {},
  subscribeToNewAlerts: () => () => {},
});

export function AlertStreamProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<AlertToast[]>([]);
  const [reconnect, setReconnect] = useState(0);
  const subscribersRef = useRef<Set<(a: AlertToast) => void>>(new Set());

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const subscribeToNewAlerts = useCallback((cb: (alert: AlertToast) => void) => {
    subscribersRef.current.add(cb);
    return () => { subscribersRef.current.delete(cb); };
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
        subscribersRef.current.forEach((cb) => cb(toast));
      } catch {
        // ignore parse errors
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
      setTimeout(() => setReconnect((c) => c + 1), 3000);
    };

    return () => eventSource.close();
  }, [reconnect]);

  return (
    <AlertStreamContext.Provider value={{ toasts, dismissToast, subscribeToNewAlerts }}>
      {children}
    </AlertStreamContext.Provider>
  );
}

export function useAlertStream() {
  return useContext(AlertStreamContext);
}
