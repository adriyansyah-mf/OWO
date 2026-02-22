'use client';

import { useCallback, useEffect, useState } from 'react';
import { getAuthHeaders, getApiBase } from '@/contexts/AuthContext';

export default function DLPPage() {
  const [results, setResults] = useState<any[]>([]);
  const [patterns, setPatterns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [newPattern, setNewPattern] = useState({ id: '', name: '', regex: '', severity: 'medium' });
  const [tab, setTab] = useState<'results' | 'patterns'>('results');
  const api = getApiBase() || 'http://localhost:8080';

  const fetchResults = useCallback(() => {
    const headers = getAuthHeaders();
    fetch(`${api}/api/v1/dlp-scan-results`, { headers })
      .then((r) => r.json())
      .then((d) => setResults(Array.isArray(d) ? d : []))
      .catch(() => setResults([]));
  }, [api]);

  const fetchPatterns = useCallback(() => {
    const headers = getAuthHeaders();
    fetch(`${api}/api/v1/dlp/patterns`, { headers })
      .then((r) => r.json())
      .then((d) => setPatterns(Array.isArray(d) ? d : []))
      .catch(() => setPatterns([]));
  }, [api]);

  useEffect(() => {
    fetchResults();
    fetchPatterns();
    setLoading(false);
    const iv = setInterval(fetchResults, 5000);
    return () => clearInterval(iv);
  }, [api, fetchResults, fetchPatterns]);

  const savePatterns = async () => {
    setSaving(true);
    setMessage(null);
    try {
      const res = await fetch(`${api}/api/v1/dlp/patterns`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(patterns),
      });
      if (!res.ok) {
        const err = await res.text();
        setMessage({ type: 'err', text: err || `Save failed (${res.status})` });
        return;
      }
      const data = await res.json();
      setPatterns(Array.isArray(data) ? data : []);
      setMessage({ type: 'ok', text: 'Patterns saved. Next DLP scan will use these rules.' });
      setNewPattern({ id: '', name: '', regex: '', severity: 'medium' });
    } catch (e) {
      setMessage({ type: 'err', text: e instanceof Error ? e.message : 'Failed to save' });
    } finally {
      setSaving(false);
    }
  };

  const addPattern = () => {
    if (!newPattern.regex.trim()) return;
    const id = newPattern.id.trim() || 'custom_' + Date.now();
    setPatterns((p) => [...p, { id, name: newPattern.name || id, regex: newPattern.regex, severity: newPattern.severity }]);
    setNewPattern({ id: '', name: '', regex: '', severity: 'medium' });
  };

  const removePattern = (idx: number) => {
    setPatterns((p) => p.filter((_, i) => i !== idx));
  };

  const updatePattern = (idx: number, field: string, value: string) => {
    setPatterns((p) => {
      const next = [...p];
      next[idx] = { ...next[idx], [field]: value };
      return next;
    });
  };

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
            {message && (
              <div
                style={{
                  padding: 12,
                  borderRadius: 8,
                  marginBottom: 16,
                  background: message.type === 'ok' ? 'var(--green-dim)' : 'var(--red-dim)',
                  color: message.type === 'ok' ? 'var(--green)' : 'var(--red)',
                }}
              >
                {message.text}
              </div>
            )}
            <div style={{ marginBottom: 16, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
              <input
                placeholder="ID (optional)"
                value={newPattern.id}
                onChange={(e) => setNewPattern((p) => ({ ...p, id: e.target.value }))}
                style={{ width: 100, padding: 8, borderRadius: 6 }}
              />
              <input
                placeholder="Name"
                value={newPattern.name}
                onChange={(e) => setNewPattern((p) => ({ ...p, name: e.target.value }))}
                style={{ width: 140, padding: 8, borderRadius: 6 }}
              />
              <input
                placeholder="Regex (e.g. AKIA[A-Z0-9]{16})"
                value={newPattern.regex}
                onChange={(e) => setNewPattern((p) => ({ ...p, regex: e.target.value }))}
                onKeyDown={(e) => e.key === 'Enter' && addPattern()}
                style={{ flex: 1, minWidth: 180, padding: 8, borderRadius: 6 }}
              />
              <select
                value={newPattern.severity}
                onChange={(e) => setNewPattern((p) => ({ ...p, severity: e.target.value }))}
                style={{ padding: 8, borderRadius: 6 }}
              >
                <option value="low">low</option>
                <option value="medium">medium</option>
                <option value="high">high</option>
                <option value="critical">critical</option>
              </select>
              <button type="button" onClick={addPattern} disabled={!newPattern.regex.trim()}>
                Add
              </button>
              <button type="button" onClick={savePatterns} disabled={saving} style={{ marginLeft: 'auto' }}>
                {saving ? 'Saving...' : 'Save Patterns'}
              </button>
            </div>
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Name</th>
                  <th>Severity</th>
                  <th>Regex</th>
                  <th style={{ width: 60 }}></th>
                </tr>
              </thead>
              <tbody>
                {patterns.map((p: any, i: number) => (
                  <tr key={i}>
                    <td>
                      <input
                        value={p.id}
                        onChange={(e) => updatePattern(i, 'id', e.target.value)}
                        style={{ width: 90, padding: 6, fontSize: 12, background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 4 }}
                      />
                    </td>
                    <td>
                      <input
                        value={p.name}
                        onChange={(e) => updatePattern(i, 'name', e.target.value)}
                        style={{ width: 120, padding: 6, fontSize: 12, background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 4 }}
                      />
                    </td>
                    <td>
                      <select
                        value={p.severity}
                        onChange={(e) => updatePattern(i, 'severity', e.target.value)}
                        style={{ padding: 6, fontSize: 12, background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 4 }}
                      >
                        <option value="low">low</option>
                        <option value="medium">medium</option>
                        <option value="high">high</option>
                        <option value="critical">critical</option>
                      </select>
                    </td>
                    <td>
                      <input
                        value={p.regex}
                        onChange={(e) => updatePattern(i, 'regex', e.target.value)}
                        style={{ width: '100%', minWidth: 150, padding: 6, fontSize: 11, fontFamily: 'monospace', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 4 }}
                      />
                    </td>
                    <td>
                      <button
                        type="button"
                        onClick={() => removePattern(i)}
                        style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 16 }}
                      >
                        ×
                      </button>
                    </td>
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
