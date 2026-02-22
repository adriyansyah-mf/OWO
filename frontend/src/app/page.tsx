'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
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

function riskLevel(score: number): { label: string; color: string; pct: number } {
  if (score >= 70) return { label: 'High', color: 'var(--red)', pct: Math.min(score, 100) };
  if (score >= 30) return { label: 'Med', color: 'var(--yellow)', pct: score };
  return { label: 'Low', color: 'var(--green)', pct: score };
}

async function irAction(api: string, path: string, body: object) {
  const res = await fetch(`${api}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify(body),
  });
  return res.ok;
}

export default function Dashboard() {
  const router = useRouter();
  const [hosts, setHosts] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'critical' | 'isolated'>('all');
  const { query: search } = useSearch();
  const { subscribeToNewAlerts } = useAlertStream();
  const api = getApiBase() || 'http://localhost:8080';

  const filteredHosts = hosts.filter((h: any) => {
    if (filter === 'critical' && (h.risk_score ?? 0) < 70) return false;
    if (filter === 'isolated' && h.status !== 'isolated') return false;
    if (search.trim()) {
      const q = search.toLowerCase().trim();
      return (h.hostname || h.id || '').toLowerCase().includes(q);
    }
    return true;
  });

  const refreshHosts = useCallback(() => {
    fetch(`${api}/api/v1/hosts`, { headers: getAuthHeaders() })
      .then(r => r.json())
      .then(h => setHosts(Array.isArray(h) ? h : []))
      .catch(() => {});
  }, [api]);

  const refresh = useCallback(() => {
    const api = getApiBase() || 'http://localhost:8080';
    const headers = getAuthHeaders();
    Promise.all([
      fetch(`${api}/api/v1/hosts`, { headers }).then(r => r.json()),
      fetch(`${api}/api/v1/alerts`, { headers }).then(r => r.json()),
    ]).then(([h, a]) => {
      setHosts(Array.isArray(h) ? h : []);
      setAlerts(Array.isArray(a) ? a : []);
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    refresh();
    const unsub = subscribeToNewAlerts((a) => {
      setAlerts((prev) => (prev.some((x) => x.id === a.id) ? prev : [a, ...prev]));
    });
    const id = setInterval(refresh, 5000);
    return () => {
      unsub();
      clearInterval(id);
    };
  }, [refresh, subscribeToNewAlerts]);

  const onlineCount = hosts.filter((h: any) => h.status === 'online').length;

  return (
    <>
      <div className="stats-row">
        <div className="stat-card">
          <div className="stat-label">
            <div className="stat-dot" style={{ background: 'var(--green)' }} />
            Protected Endpoints
          </div>
          <div className="stat-value" style={{ color: 'var(--text-primary)' }}>{loading ? '…' : onlineCount}</div>
          <div className="stat-change down">↑ {hosts.length} total</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            <div className="stat-dot" style={{ background: 'var(--red)' }} />
            Active Threats
          </div>
          <div className="stat-value" style={{ color: 'var(--red)' }}>{loading ? '…' : alerts.length}</div>
          <div className="stat-change up">↑ Alerts (24h)</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            <div className="stat-dot" style={{ background: 'var(--yellow)' }} />
            Quarantined Files
          </div>
          <div className="stat-value" style={{ color: 'var(--yellow)' }}>0</div>
          <div className="stat-change neutral">Last updated —</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            <div className="stat-dot" style={{ background: 'var(--accent)' }} />
            Threats Blocked (24h)
          </div>
          <div className="stat-value" style={{ color: 'var(--accent)' }}>{alerts.length}</div>
          <div className="stat-change down">Detection active</div>
        </div>
      </div>

      <div className="main-grid">
        <div className="card">
          <div className="card-header">
            <span className="card-title">Endpoint Status</span>
            <div className="filter-tabs">
              <div className="tab active">All</div>
              <div className="tab">Critical</div>
              <div className="tab">Isolated</div>
            </div>
            <span className="card-subtitle" style={{ marginLeft: 8 }}>{hosts.length} total</span>
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
                  <tr><td colSpan={5} style={{ padding: 24, color: 'var(--text-muted)' }}>No endpoints yet. Start the EDR agent to see data.</td></tr>
                ) : (
                  filteredHosts.slice(0, 8).map((h: any) => {
                    const risk = riskLevel(h.risk_score ?? 0);
                    const isOnline = h.status === 'online';
                    return (
                      <tr key={h.id} onClick={() => router.push(`/process-tree/${h.id}`)}>
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
                          {isOnline ? 'Active now' : (h.last_seen ? formatTime(h.last_seen) : '—')}
                        </td>
                        <td>
                          <div className="risk-bar-wrap">
                            <div style={{ fontSize: 11, color: risk.color, marginBottom: 3 }}>{risk.label} · {Math.round(h.risk_score || 0)}</div>
                            <div className="risk-bar"><div className="risk-fill" style={{ width: `${risk.pct}%`, background: risk.color }} /></div>
                          </div>
                        </td>
                        <td>
                          <span className={`status-pill ${isOnline ? (risk.pct >= 70 ? 'critical' : risk.pct >= 30 ? 'warning' : 'safe') : ''}`} style={!isOnline ? { background: '#1e2535', color: 'var(--text-muted)' } : undefined}>
                            ● {h.status === 'isolated' ? 'Isolated' : isOnline ? (risk.pct >= 70 ? 'Critical' : risk.pct >= 30 ? 'Warning' : 'Secure') : 'Offline'}
                          </span>
                        </td>
                        <td onClick={(e) => e.stopPropagation()}>
                          {h.status === 'isolated' ? (
                            <button
                              className="status-pill safe"
                              style={{ fontSize: 10, padding: '2px 8px', border: 'none', cursor: acting ? 'wait' : 'pointer' }}
                              disabled={!!acting}
                              onClick={async () => {
                                setActing(h.id);
                                await irAction(api, '/api/v1/ir/release', { host_id: h.id });
                                refreshHosts();
                                setActing(null);
                              }}
                            >
                              Release
                            </button>
                          ) : (
                            <button
                              className="status-pill critical"
                              style={{ fontSize: 10, padding: '2px 8px', border: 'none', cursor: acting ? 'wait' : 'pointer' }}
                              disabled={!!acting}
                              onClick={async () => {
                                setActing(h.id);
                                await irAction(api, '/api/v1/ir/isolate', { host_id: h.id });
                                refreshHosts();
                                setActing(null);
                              }}
                            >
                              Isolate
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

        <div className="card" style={{ animationDelay: '0.3s' }}>
          <div className="card-header">
            <span className="card-title">Threat Intelligence Feed</span>
            <span className="status-pill critical">● Live</span>
          </div>
          <div className="threat-feed">
            {loading ? (
              <div className="threat-item"><div className="threat-meta">Loading...</div></div>
            ) : alerts.length === 0 ? (
              <div className="threat-item">
                <div className="threat-icon info">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                </div>
                <div className="threat-body">
                  <div className="threat-title">No alerts yet</div>
                  <div className="threat-meta">Alerts will appear when detection rules match</div>
                </div>
              </div>
            ) : (
              alerts.slice(0, 6).map((a: any, i: number) => (
                <div key={i} className="threat-item">
                  <div className={`threat-icon ${a.severity === 'critical' || a.severity === 'high' ? 'crit' : a.severity === 'medium' ? 'warn' : 'info'}`}>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                  </div>
                  <div className="threat-body">
                    <div className="threat-title">{a.title || a.rule_name || 'Alert'}</div>
                    <div className="threat-meta">{a.host_id} · {(a.mitre as string[] || []).join(', ') || '—'}</div>
                  </div>
                  <div className="threat-time">{formatTime(a.created_at)}</div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="bottom-row">
        <div className="card" style={{ animationDelay: '0.35s' }}>
          <div className="card-header">
            <span className="card-title">Attack Telemetry (7d)</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Detections per day</span>
          </div>
          <div className="chart-area">
            <div className="sparkline">
              {[35, 55, 40, 75, 60, 90, 70].map((h, i) => (
                <div key={i} className="spark-bar" style={{ height: `${h}%`, background: i === 5 ? 'var(--red)' : i === 6 ? 'var(--yellow)' : 'var(--accent-dark)', animationDelay: `${0.1 + i * 0.05}s` }} />
              ))}
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8, fontSize: 11, color: 'var(--text-muted)' }}>
              <span>Mon</span><span>Tue</span><span>Wed</span><span>Thu</span><span>Fri</span><span>Sat</span><span>Sun</span>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, padding: '0 18px 16px', marginTop: 4 }}>
            <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 7, padding: '10px 12px' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Peak Day</div>
              <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--red)' }}>Sat · 342</div>
            </div>
            <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 7, padding: '10px 12px' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Auto-blocked</div>
              <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--green)' }}>98.7%</div>
            </div>
          </div>
        </div>

        <div className="card" style={{ animationDelay: '0.4s' }}>
          <div className="card-header">
            <span className="card-title">Suspicious Processes</span>
            <span className="status-pill warning">From process tree</span>
          </div>
          <div className="process-list">
            <div className="process-item">
              <div className="proc-name">—</div>
              <div className="proc-pid">View Process Tree per host</div>
              <Link href="/hosts" className="status-pill info" style={{ fontSize: 10, padding: '2px 7px' }}>VIEW</Link>
            </div>
          </div>
        </div>

        <div className="card" style={{ animationDelay: '0.45s' }}>
          <div className="card-header">
            <span className="card-title">Agent Coverage</span>
            <span className="status-pill safe">{hosts.length > 0 ? `${Math.round((onlineCount / hosts.length) * 100)}% online` : '0% covered'}</span>
          </div>
          <div className="agent-stats">
            <div className="agent-stat">
              <div className="agent-stat-val" style={{ color: 'var(--green)' }}>{onlineCount}</div>
              <div className="agent-stat-label">Online & Protected</div>
            </div>
            <div className="agent-stat">
              <div className="agent-stat-val" style={{ color: 'var(--red)' }}>{hosts.length - onlineCount}</div>
              <div className="agent-stat-label">Offline / Unreachable</div>
            </div>
            <div className="agent-stat">
              <div className="agent-stat-val" style={{ color: 'var(--yellow)' }}>0</div>
              <div className="agent-stat-label">Outdated Agent</div>
            </div>
            <div className="agent-stat">
              <div className="agent-stat-val" style={{ color: 'var(--purple)' }}>0</div>
              <div className="agent-stat-label">Isolated</div>
            </div>
          </div>
          <div style={{ padding: '0 18px 16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5, fontSize: 11, color: 'var(--text-secondary)' }}>
                <span>Linux</span><span>{hosts.length}</span>
              </div>
              <div className="risk-bar">
                <div className="risk-fill" style={{ width: hosts.length ? '100%' : '0%', background: 'var(--green)' }} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
