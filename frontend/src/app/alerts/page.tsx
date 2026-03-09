'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
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
  // artifact state: key = "host_id:artifact_name"
  const [collecting, setCollecting] = useState<Record<string, boolean>>({});
  const [readyArtifacts, setReadyArtifacts] = useState<Set<string>>(new Set());
  const pollTimers = useRef<Record<string, ReturnType<typeof setInterval>>>({});
  const { query: search } = useSearch();
  const { subscribeToNewAlerts } = useAlertStream();
  const apiBase = getApiBase() || 'http://localhost:8080';

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
    fetch(`${apiBase}/api/v1/alerts`, { headers })
      .then(r => r.json())
      .then(a => setAlerts(Array.isArray(a) ? a : []))
      .catch(() => setAlerts([]))
      .finally(() => setLoading(false));
  }, [apiBase]);

  useEffect(() => {
    fetchAlerts();
    const unsub = subscribeToNewAlerts((a) => {
      setAlerts((prev) => (prev.some((x) => x.id === a.id) ? prev : [a, ...prev]));
    });
    const id = setInterval(fetchAlerts, 15000);
    return () => {
      unsub();
      clearInterval(id);
      Object.values(pollTimers.current).forEach(clearInterval);
    };
  }, [fetchAlerts, subscribeToNewAlerts]);

  const runTestInject = async () => {
    setTestLoading(true);
    try {
      const res = await fetch(`${apiBase}/api/v1/test/inject-event`, {
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

  const collectArtifacts = async (hostID: string) => {
    const artifactName = `triage_${Date.now()}`;
    const key = `${hostID}:${artifactName}`;
    setCollecting(prev => ({ ...prev, [key]: true }));
    try {
      await fetch(`${apiBase}/api/v1/ir/collect`, {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({
          host_id: hostID,
          paths: ['/tmp', '/var/log/auth.log', '/var/log/syslog', '/etc/passwd', '/etc/hosts', '/proc/net/tcp'],
          artifact_name: artifactName,
        }),
      });
      // Poll until artifact is ready (max 120s)
      let attempts = 0;
      const timer = setInterval(async () => {
        attempts++;
        try {
          const res = await fetch(`${apiBase}/api/v1/ir/artifacts?host_id=${encodeURIComponent(hostID)}`, {
            headers: getAuthHeaders(),
          });
          const list: any[] = await res.json();
          if (list.some((a: any) => a.artifact_name === artifactName)) {
            clearInterval(timer);
            delete pollTimers.current[key];
            setCollecting(prev => { const n = { ...prev }; delete n[key]; return n; });
            setReadyArtifacts(prev => new Set(prev).add(key));
          }
        } catch {}
        if (attempts >= 24) { // 2 min timeout
          clearInterval(timer);
          delete pollTimers.current[key];
          setCollecting(prev => { const n = { ...prev }; delete n[key]; return n; });
        }
      }, 5000);
      pollTimers.current[key] = timer;
    } catch {
      setCollecting(prev => { const n = { ...prev }; delete n[key]; return n; });
    }
  };

  const downloadArtifact = (hostID: string, artifactName: string) => {
    const url = `${apiBase}/api/v1/ir/artifact?host_id=${encodeURIComponent(hostID)}&name=${encodeURIComponent(artifactName)}`;
    const a = document.createElement('a');
    a.href = url;
    // include auth token as query param for download
    const headers = getAuthHeaders();
    const token = headers['Authorization']?.replace('Bearer ', '');
    a.href = token ? `${url}&token=${encodeURIComponent(token)}` : url;
    a.download = `${artifactName}_${hostID}.tar.gz`;
    a.click();
  };

  // Find the most recent ready artifact key for a given host
  const getReadyArtifactForHost = (hostID: string) => {
    for (const key of readyArtifacts) {
      if (key.startsWith(`${hostID}:`)) return key;
    }
    return null;
  };

  const getCollectingKeyForHost = (hostID: string) => {
    for (const key of Object.keys(collecting)) {
      if (key.startsWith(`${hostID}:`)) return key;
    }
    return null;
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
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} style={{ padding: 24, color: 'var(--text-muted)' }}>Loading...</td></tr>
            ) : alerts.length === 0 ? (
              <tr><td colSpan={6} style={{ padding: 24, color: 'var(--text-muted)' }}>No alerts yet.</td></tr>
            ) : filtered.length === 0 ? (
              <tr><td colSpan={6} style={{ padding: 24, color: 'var(--text-muted)' }}>No alerts match search.</td></tr>
            ) : (
              filtered.map((a: any, i: number) => {
                const collectingKey = getCollectingKeyForHost(a.host_id);
                const readyKey = getReadyArtifactForHost(a.host_id);
                const artifactName = readyKey?.split(':').slice(1).join(':');
                return (
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
                    <td>
                      {readyKey && artifactName ? (
                        <button
                          type="button"
                          className="btn btn-secondary"
                          style={{ fontSize: 11, padding: '2px 8px' }}
                          onClick={() => downloadArtifact(a.host_id, artifactName)}
                        >
                          Download Artifacts
                        </button>
                      ) : collectingKey ? (
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Collecting…</span>
                      ) : (
                        <button
                          type="button"
                          className="btn btn-secondary"
                          style={{ fontSize: 11, padding: '2px 8px' }}
                          onClick={() => collectArtifacts(a.host_id)}
                        >
                          Collect
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
