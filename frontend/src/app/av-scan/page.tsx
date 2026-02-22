'use client';

import { useEffect, useState } from 'react';
import { getAuthHeaders, getApiBase } from '@/contexts/AuthContext';
import { useSearch } from '@/contexts/SearchContext';

export default function AVScanPage() {
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const { query: search } = useSearch();
  const api = getApiBase() || 'http://localhost:8080';

  const fetchResults = () => {
    const headers = getAuthHeaders();
    fetch(`${api}/api/v1/av-scan-results`, { headers })
      .then((r) => r.json())
      .then((d) => setResults(Array.isArray(d) ? d : []))
      .catch(() => setResults([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchResults();
    const iv = setInterval(fetchResults, 5000);
    return () => clearInterval(iv);
  }, [api]);

  const filtered = results.filter((r: any) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    const host = (r.host_id || '').toLowerCase();
    const ts = (r.timestamp || '').toLowerCase();
    return host.includes(q) || ts.includes(q);
  });

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">AV Scan Results (ClamAV)</span>
        <span className="card-subtitle" style={{ marginLeft: 8 }}>
          {filtered.length} scan{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>
      <div className="table-wrap">
        {loading ? (
          <div style={{ padding: 24, color: 'var(--text-muted)' }}>Loading...</div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: 24, color: 'var(--text-muted)' }}>
            Belum ada hasil AV scan. Klik &quot;AV Scan&quot; di sidebar, pilih host, lalu jalankan.
          </div>
        ) : (
          <div style={{ padding: 16 }}>
            {filtered.map((r: any, i: number) => {
              const res = r.results || [];
              const summary = res.find((x: any) => x.status === 'summary');
              const infected = res.filter((x: any) => x.status === 'infected');
              const scanned = summary?.scanned ?? 0;
              const infCount = summary?.infected ?? infected.length;
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
                    Scanned: {scanned} · Infected: {infCount}
                  </div>
                  {infected.length > 0 && (
                    <div style={{ marginTop: 8 }}>
                      <div style={{ fontSize: 12, color: 'var(--red)', marginBottom: 6 }}>Infected files:</div>
                      <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12 }}>
                        {infected.map((x: any, j: number) => (
                          <li key={j} style={{ marginBottom: 4 }}>
                            <code style={{ fontSize: 11 }}>{x.path}</code>
                            {x.virus && (
                              <span style={{ color: 'var(--red)', marginLeft: 8 }}>→ {x.virus}</span>
                            )}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
