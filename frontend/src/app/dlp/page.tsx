'use client';

import { useEffect, useState } from 'react';
import { getAuthHeaders, getApiBase } from '@/contexts/AuthContext';

export default function DLPPage() {
  const [results, setResults] = useState<any[]>([]);
  const [patterns, setPatterns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<'results' | 'patterns'>('results');
  const api = getApiBase() || 'http://localhost:8080';

  const fetchResults = () => {
    const headers = getAuthHeaders();
    fetch(`${api}/api/v1/dlp-scan-results`, { headers })
      .then((r) => r.json())
      .then((d) => setResults(Array.isArray(d) ? d : []))
      .catch(() => setResults([]));
  };

  const fetchPatterns = () => {
    const headers = getAuthHeaders();
    fetch(`${api}/api/v1/dlp/patterns`, { headers })
      .then((r) => r.json())
      .then((d) => setPatterns(Array.isArray(d) ? d : []))
      .catch(() => setPatterns([]));
  };

  useEffect(() => {
    fetchResults();
    fetchPatterns();
    setLoading(false);
    const iv = setInterval(fetchResults, 5000);
    return () => clearInterval(iv);
  }, [api]);

  const totalMatches = results.reduce((acc: number, r: any) => acc + (Array.isArray(r.matches) ? r.matches.length : 0), 0);

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Data Loss Prevention</span>
        <div className="filter-tabs" style={{ marginLeft: 16 }}>
          <div className={`tab ${tab === 'results' ? 'active' : ''}`} onClick={() => setTab('results')}>
            Scan Results
          </div>
          <div className={`tab ${tab === 'patterns' ? 'active' : ''}`} onClick={() => setTab('patterns')}>
            Patterns
          </div>
        </div>
        <span className="card-subtitle" style={{ marginLeft: 8 }}>
          {tab === 'results' ? `${results.length} scan(s), ${totalMatches} finding(s)` : `${patterns.length} pattern(s)`}
        </span>
      </div>

      <div className="table-wrap">
        {loading ? (
          <div style={{ padding: 24, color: 'var(--text-muted)' }}>Loading...</div>
        ) : tab === 'results' ? (
          results.length === 0 ? (
            <div style={{ padding: 24, color: 'var(--text-muted)' }}>
              Belum ada hasil DLP scan. Klik &quot;DLP Scan&quot; di sidebar, pilih host, lalu jalankan.
            </div>
          ) : (
            <div style={{ padding: 16 }}>
              {results.map((r: any, i: number) => {
                const matches = r.matches || [];
                return (
                  <div
                    key={i}
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: 8,
                      padding: 16,
                      marginBottom: 12,
                      background: 'var(--bg-secondary)',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
                      <strong>{r.host_id || 'Unknown'}</strong>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {r.timestamp ? new Date(r.timestamp).toLocaleString() : '—'}
                      </span>
                    </div>
                    <div style={{ fontSize: 13, marginBottom: 8 }}>
                      {matches.length} finding(s)
                    </div>
                    {matches.length > 0 && (
                      <div style={{ marginTop: 8 }}>
                        <div style={{ fontSize: 12, color: 'var(--yellow)', marginBottom: 6 }}>Sensitive content:</div>
                        <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12 }}>
                          {matches.slice(0, 20).map((m: any, j: number) => (
                            <li key={j} style={{ marginBottom: 4 }}>
                              <code style={{ fontSize: 11 }}>{m.path}</code>
                              {m.line && <span style={{ color: 'var(--text-muted)' }}> L{m.line}</span>}
                              {m.pattern && (
                                <span style={{ color: 'var(--red)', marginLeft: 8 }}>→ {m.pattern}</span>
                              )}
                              {m.snippet && (
                                <div style={{ marginTop: 2, color: 'var(--text-muted)', fontSize: 11 }}>
                                  {m.snippet}
                                </div>
                              )}
                            </li>
                          ))}
                        </ul>
                        {matches.length > 20 && (
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
                            +{matches.length - 20} more
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )
        ) : (
          <div style={{ padding: 16 }}>
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Name</th>
                  <th>Severity</th>
                  <th>Regex</th>
                </tr>
              </thead>
              <tbody>
                {patterns.map((p: any, i: number) => (
                  <tr key={i}>
                    <td><code>{p.id}</code></td>
                    <td>{p.name}</td>
                    <td>
                      <span
                        className="status-pill"
                        style={{
                          background: p.severity === 'critical' ? 'var(--red-dim)' : p.severity === 'high' ? 'var(--red-dim)' : p.severity === 'medium' ? 'var(--yellow-dim)' : 'var(--green-dim)',
                          color: p.severity === 'critical' || p.severity === 'high' ? 'var(--red)' : p.severity === 'medium' ? 'var(--yellow)' : 'var(--green)',
                        }}
                      >
                        {p.severity}
                      </span>
                    </td>
                    <td><code style={{ fontSize: 11 }}>{p.regex}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
