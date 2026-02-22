'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { getAuthHeaders, getApiBase } from '@/contexts/AuthContext';
import { useSearch } from '@/contexts/SearchContext';
import { useAlertStream } from '@/contexts/AlertStreamContext';

function formatTime(ts: string) {
  if (!ts) return '—';
  const d = new Date(ts);
  const now = new Date();
  const diff = (now.getTime() - d.getTime()) / 60000;
  if (diff < 1) return 'just now';
  if (diff < 60) return `${Math.floor(diff)}m ago`;
  if (diff < 1440) return `${Math.floor(diff / 60)}h ago`;
  return d.toLocaleDateString();
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [testLoading, setTestLoading] = useState(false);
  const { query: search } = useSearch();
  const { subscribeToNewAlerts } = useAlertStream();

  const filtered = alerts.filter((a: any) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase().trim();
    return (
      (a.title || '').toLowerCase().includes(q) ||
      (a.host_id || '').toLowerCase().includes(q) ||
      ((a.mitre as string[] || []).join(' ').toLowerCase().includes(q))
    );
  });

  const fetchAlerts = useCallback(() => {
    const headers = getAuthHeaders();
    fetch(`${getApiBase() || 'http://localhost:8080'}/api/v1/alerts`, { headers })
      .then(r => r.json())
      .then(a => setAlerts(Array.isArray(a) ? a : []))
      .catch(() => setAlerts([]))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    fetchAlerts();
    const unsub = subscribeToNewAlerts((a) => {
      setAlerts((prev) => (prev.some((x) => x.id === a.id) ? prev : [a, ...prev]));
    });
    const id = setInterval(fetchAlerts, 15000);
    return () => {
      unsub();
      clearInterval(id);
    };
  }, [fetchAlerts, subscribeToNewAlerts]);

    const runTestInject = async () => {
    setTestLoading(true);
    try {
      const res = await fetch(`${getApiBase() || 'http://localhost:8080'}/api/v1/test/inject-event`, {
        method: 'POST',
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        setTimeout(fetchAlerts, 2000);
      }
    } finally {
      setTestLoading(false);
    }
  };

  const severityPill = (sev: string) => {
    const c = sev === 'critical' || sev === 'high' ? 'critical' : sev === 'medium' ? 'warning' : 'info';
    return <span className={`status-pill ${c}`}>● {sev || 'info'}</span>;
  };

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Threat Alerts</span>
        <span className="status-pill critical">● Live</span>
        <span className="card-subtitle" style={{ marginLeft: 8 }}>{filtered.length} of {alerts.length}</span>
        <button
          type="button"
          onClick={runTestInject}
          disabled={testLoading}
          className="btn btn-secondary"
          style={{ marginLeft: 'auto', fontSize: 12 }}
        >
          {testLoading ? 'Injecting…' : 'Test Pipeline'}
        </button>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Title</th>
              <th>Host</th>
              <th>MITRE</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} style={{ padding: 24, color: 'var(--text-muted)' }}>Loading...</td></tr>
            ) : alerts.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: 24, color: 'var(--text-muted)' }}>No alerts yet.</td></tr>
            ) : filtered.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: 24, color: 'var(--text-muted)' }}>No alerts match search.</td></tr>
            ) : (
              filtered.map((a: any, i: number) => (
                <tr key={i}>
                  <td>{severityPill(a.severity)}</td>
                  <td>
                    <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{a.title || a.rule_name || 'Alert'}</span>
                  </td>
                  <td>
                    <Link href={`/process-tree/${a.host_id}`} style={{ color: 'var(--accent)', textDecoration: 'none' }}>
                      {a.host_id}
                    </Link>
                  </td>
                  <td className="mono" style={{ fontSize: 11 }}>{(a.mitre as string[] || []).join(', ') || '—'}</td>
                  <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{formatTime(a.created_at)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
