'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { getAuthHeaders, getApiBase } from '@/contexts/AuthContext';
import { useSearch } from '@/contexts/SearchContext';

async function irAction(api: string, path: string, body: object) {
  const res = await fetch(`${api}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify(body),
  });
  return res.ok;
}

function formatTime(ts: string) {
  if (!ts) return '—';
  const d = new Date(ts);
  const now = new Date();
  const diff = (now.getTime() - d.getTime()) / 60000;
  if (diff < 1) return 'Active now';
  if (diff < 60) return `${Math.floor(diff)} min ago`;
  if (diff < 1440) return `${Math.floor(diff / 60)}h ago`;
  return `Offline ${Math.floor(diff / 1440)}h`;
}

function riskLevel(score: number): { label: string; color: string; pct: number } {
  if (score >= 70) return { label: 'High', color: 'var(--red)', pct: Math.min(score, 100) };
  if (score >= 30) return { label: 'Med', color: 'var(--yellow)', pct: score };
  return { label: 'Low', color: 'var(--green)', pct: score };
}

type HostFilter = 'all' | 'critical' | 'isolated';

export default function HostsPage() {
  const [hosts, setHosts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState<string | null>(null);
  const [filter, setFilter] = useState<HostFilter>('all');
  const { query: search } = useSearch();
  const api = getApiBase() || 'http://localhost:8080';

  const filtered = hosts.filter((h: any) => {
    if (filter === 'critical' && (h.risk_score ?? 0) < 70) return false;
    if (filter === 'isolated' && h.status !== 'isolated') return false;
    if (search.trim()) {
      const q = search.toLowerCase().trim();
      return (h.hostname || h.id || '').toLowerCase().includes(q);
    }
    return true;
  });

  useEffect(() => {
    const headers = getAuthHeaders();
    fetch(`${getApiBase() || 'http://localhost:8080'}/api/v1/hosts`, { headers })
      .then(r => r.json())
      .then(h => setHosts(Array.isArray(h) ? h : []))
      .catch(() => setHosts([]))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">All Endpoints</span>
        <div className="filter-tabs">
          <div className={`tab ${filter === 'all' ? 'active' : ''}`} onClick={() => setFilter('all')}>All</div>
          <div className={`tab ${filter === 'critical' ? 'active' : ''}`} onClick={() => setFilter('critical')}>Critical</div>
          <div className={`tab ${filter === 'isolated' ? 'active' : ''}`} onClick={() => setFilter('isolated')}>Isolated</div>
        </div>
        <span className="card-subtitle" style={{ marginLeft: 8 }}>{filtered.length} of {hosts.length} {search.trim() ? '(filtered)' : ''}</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Endpoint</th>
              <th>Last Seen</th>
              <th>Risk</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} style={{ padding: 24, color: 'var(--text-muted)' }}>Loading...</td></tr>
            ) : hosts.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: 24, color: 'var(--text-muted)' }}>No endpoints. Start the EDR agent.</td></tr>
            ) : filtered.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: 24, color: 'var(--text-muted)' }}>No endpoints match filter.</td></tr>
            ) : (
              filtered.map((h: any) => {
                const risk = riskLevel(h.risk_score ?? 0);
                const isOnline = h.status === 'online';
                return (
                  <tr key={h.id}>
                    <td>
                      <div className="endpoint-name">
                        <div className="endpoint-icon">
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}><path d="M20 16.2A4.5 4.5 0 0017.5 8h-1.8A7 7 0 104 14.9"/><polyline points="16 16 12 20 8 16"/><line x1="12" y1="12" x2="12" y2="20"/></svg>
                        </div>
                        <div>
                          <div className="ep-name">{h.hostname || h.id}</div>
                          <div className="ep-os">Linux</div>
                        </div>
                      </div>
                    </td>
                    <td style={{ fontSize: 12, color: isOnline ? 'var(--green)' : 'var(--text-muted)' }}>
                      {formatTime(h.last_seen)}
                    </td>
                    <td>
                      <div className="risk-bar-wrap">
                        <div style={{ fontSize: 11, color: risk.color, marginBottom: 3 }}>{risk.label} · {Math.round(h.risk_score || 0)}</div>
                        <div className="risk-bar"><div className="risk-fill" style={{ width: `${risk.pct}%`, background: risk.color }} /></div>
                      </div>
                    </td>
                    <td>
                      <span className={`status-pill ${isOnline ? (risk.pct >= 70 ? 'critical' : risk.pct >= 30 ? 'warning' : 'safe') : ''}`} style={!isOnline ? { background: '#1e2535', color: 'var(--text-muted)' } : undefined}>
                        ● {isOnline ? (risk.pct >= 70 ? 'Critical' : risk.pct >= 30 ? 'Warning' : 'Secure') : 'Offline'}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        <Link href={`/process-tree/${h.id}`} className="status-pill info" style={{ fontSize: 10, padding: '2px 8px', textDecoration: 'none' }}>
                          Process Tree
                        </Link>
                        {isOnline && (
                          <>
                            <button
                              className="status-pill critical"
                              style={{ fontSize: 10, padding: '2px 8px', border: 'none', cursor: 'pointer' }}
                              disabled={acting !== null}
                              onClick={async () => {
                                setActing(`isolate-${h.id}`);
                                await irAction(api, '/api/v1/ir/isolate', { host_id: h.id });
                                setActing(null);
                              }}
                            >
                              Isolate
                            </button>
                            <button
                              className="status-pill safe"
                              style={{ fontSize: 10, padding: '2px 8px', border: 'none', cursor: 'pointer' }}
                              disabled={acting !== null}
                              onClick={async () => {
                                setActing(`release-${h.id}`);
                                await irAction(api, '/api/v1/ir/release', { host_id: h.id });
                                setActing(null);
                              }}
                            >
                              Release
                            </button>
                            <button
                              className="status-pill info"
                              style={{ fontSize: 10, padding: '2px 8px', border: 'none', cursor: 'pointer' }}
                              disabled={acting !== null}
                              onClick={async () => {
                                setActing(`collect-${h.id}`);
                                await irAction(api, '/api/v1/ir/collect', { host_id: h.id, paths: ['/tmp', '/var/log'], artifact_name: 'triage' });
                                setActing(null);
                              }}
                            >
                              Collect
                            </button>
                          </>
                        )}
                      </div>
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
