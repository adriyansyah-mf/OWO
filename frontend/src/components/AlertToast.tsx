'use client';

import Link from 'next/link';
import { useAlertStream } from '@/contexts/AlertStreamContext';

export default function AlertToastContainer() {
  const { toasts, dismissToast } = useAlertStream();

  if (toasts.length === 0) return null;

  return (
    <div
      style={{
        position: 'fixed',
        top: 16,
        right: 16,
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        maxWidth: 380,
      }}
    >
      {toasts.map((t) => (
        <div
          key={t.id}
          style={{
            padding: '12px 16px',
            borderRadius: 8,
            background: t.severity === 'critical' || t.severity === 'high'
              ? 'rgba(239, 68, 68, 0.15)'
              : t.severity === 'medium'
                ? 'rgba(234, 179, 8, 0.15)'
                : 'var(--bg-secondary)',
            border: `1px solid ${t.severity === 'critical' || t.severity === 'high' ? 'var(--red)' : t.severity === 'medium' ? 'var(--yellow)' : 'var(--border)'}`,
            boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
            animation: 'slideIn 0.3s ease',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)', marginBottom: 4 }}>
                {t.title}
              </div>
              {t.message && (
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>{t.message}</div>
              )}
              {t.host_id && (
                <Link
                  href={`/process-tree/${t.host_id}`}
                  style={{ fontSize: 11, color: 'var(--accent)', textDecoration: 'none' }}
                >
                  {t.host_id} →
                </Link>
              )}
            </div>
            <button
              onClick={() => dismissToast(t.id)}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: 'var(--text-muted)',
                padding: 4,
                fontSize: 18,
                lineHeight: 1,
              }}
            >
              ×
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
