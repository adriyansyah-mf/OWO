'use client';

import { useCallback, useEffect, useState } from 'react';
import { getAuthHeaders, getApiBase, useAuth } from '@/contexts/AuthContext';

type IOCType = 'ip' | 'domain' | 'hash' | 'url';
type TLP = 'white' | 'green' | 'amber' | 'red';

type IOC = {
  id: string;
  type: IOCType;
  value: string;
  severity: string;
  confidence: number;
  source: string;
  tags: string[];
  tlp: TLP;
  description?: string;
  expires_at?: string;
  created_at: string;
  hit_count: number;
  last_hit_at?: string;
};

type LookupResult = {
  matched: boolean;
  ioc?: IOC;
  value: string;
  type: string;
};

type ImportResult = {
  added: number;
  skipped: number;
  errors: string[];
  source: string;
  duration_ms?: number;
};

type Stats = {
  total: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
  by_source: Record<string, number>;
};

type TabId = 'iocs' | 'lookup' | 'feed' | 'stats';

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)',
  high: 'var(--orange, #f97316)',
  medium: 'var(--yellow)',
  low: 'var(--text-muted)',
  info: 'var(--blue, #3b82f6)',
};

const TLP_COLOR: Record<TLP, string> = {
  red: 'var(--red)',
  amber: 'var(--yellow)',
  green: 'var(--green)',
  white: 'var(--text-muted)',
};

const inputStyle: React.CSSProperties = {
  padding: '7px 10px',
  borderRadius: 6,
  border: '1px solid var(--border)',
  background: 'var(--bg-secondary)',
  color: 'inherit',
  fontSize: 13,
};

const Msg = ({ msg }: { msg: { type: 'ok' | 'err'; text: string } | null }) =>
  msg ? (
    <div style={{ padding: '10px 14px', borderRadius: 8, marginBottom: 14, fontSize: 13,
      background: msg.type === 'ok' ? 'var(--green-dim)' : 'var(--red-dim)',
      color: msg.type === 'ok' ? 'var(--green)' : 'var(--red)' }}>
      {msg.text}
    </div>
  ) : null;

export default function ThreatIntelPage() {
  const api = getApiBase() || 'http://localhost:8080';
  const { canWrite } = useAuth();
  const [tab, setTab] = useState<TabId>('iocs');
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // Filters
  const [filterType, setFilterType] = useState('');
  const [filterSev, setFilterSev] = useState('');
  const [filterQuery, setFilterQuery] = useState('');

  // Add IOC form
  const [showAdd, setShowAdd] = useState(false);
  const [newIOC, setNewIOC] = useState({ value: '', type: 'ip' as IOCType, severity: 'medium', source: '', tlp: 'green' as TLP, description: '', tags: '' });
  const [saving, setSaving] = useState(false);

  // Lookup
  const [lookupValue, setLookupValue] = useState('');
  const [lookupResult, setLookupResult] = useState<LookupResult | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);

  // Feed import
  const [feedURL, setFeedURL] = useState('');
  const [feedText, setFeedText] = useState('');
  const [feedFormat, setFeedFormat] = useState('auto');
  const [feedSource, setFeedSource] = useState('');
  const [feedLoading, setFeedLoading] = useState(false);
  const [feedResult, setFeedResult] = useState<ImportResult | null>(null);

  const showMsg = (type: 'ok' | 'err', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  };

  const fetchIOCs = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams();
    if (filterType) params.set('type', filterType);
    if (filterSev) params.set('severity', filterSev);
    if (filterQuery) params.set('q', filterQuery);
    fetch(`${api}/api/v1/threat-intel/iocs?${params}`, { headers: getAuthHeaders() })
      .then((r) => r.json())
      .then((d) => setIocs(Array.isArray(d) ? d : []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [api, filterType, filterSev, filterQuery]);

  const fetchStats = useCallback(() => {
    fetch(`${api}/api/v1/threat-intel/stats`, { headers: getAuthHeaders() })
      .then((r) => r.json())
      .then((d) => setStats(d))
      .catch(() => {});
  }, [api]);

  useEffect(() => {
    if (tab === 'iocs') fetchIOCs();
    if (tab === 'stats') fetchStats();
  }, [tab, fetchIOCs, fetchStats]);

  const addIOC = async () => {
    if (!newIOC.value) return;
    setSaving(true);
    try {
      const payload = {
        ...newIOC,
        tags: newIOC.tags ? newIOC.tags.split(',').map((t) => t.trim()).filter(Boolean) : [],
      };
      const res = await fetch(`${api}/api/v1/threat-intel/iocs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(payload),
      });
      if (!res.ok) { showMsg('err', (await res.json())?.error || `Failed (${res.status})`); return; }
      fetchIOCs();
      setShowAdd(false);
      setNewIOC({ value: '', type: 'ip', severity: 'medium', source: '', tlp: 'green', description: '', tags: '' });
      showMsg('ok', 'IOC added.');
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  const deleteIOC = async (id: string, value: string) => {
    if (!confirm(`Remove IOC "${value}"?`)) return;
    try {
      const res = await fetch(`${api}/api/v1/threat-intel/iocs/${id}`, { method: 'DELETE', headers: getAuthHeaders() });
      if (!res.ok) { showMsg('err', (await res.json())?.error || 'Failed'); return; }
      fetchIOCs();
      showMsg('ok', 'IOC removed.');
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
  };

  const doLookup = async () => {
    if (!lookupValue.trim()) return;
    setLookupLoading(true);
    setLookupResult(null);
    try {
      const res = await fetch(`${api}/api/v1/threat-intel/lookup?value=${encodeURIComponent(lookupValue.trim())}`, { headers: getAuthHeaders() });
      if (res.ok) setLookupResult(await res.json());
    } catch {}
    finally { setLookupLoading(false); }
  };

  const doFeedImport = async () => {
    if (!feedURL && !feedText) return;
    setFeedLoading(true);
    setFeedResult(null);
    try {
      const res = await fetch(`${api}/api/v1/threat-intel/feed`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify({ url: feedURL || undefined, text: feedText || undefined, format: feedFormat, source: feedSource || 'manual' }),
      });
      const d = await res.json();
      if (!res.ok) { showMsg('err', d?.error || `Failed (${res.status})`); return; }
      setFeedResult(d);
      fetchStats();
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setFeedLoading(false); }
  };

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Threat Intelligence</span>
        <div className="filter-tabs" style={{ marginLeft: 16 }}>
          {(['iocs', 'lookup', 'feed', 'stats'] as TabId[]).map((t) => (
            <div key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}
              style={{ textTransform: 'capitalize' }}>
              {t === 'iocs' ? 'IOC Database' : t === 'lookup' ? 'Lookup' : t === 'feed' ? 'Feed Import' : 'Statistics'}
            </div>
          ))}
        </div>
      </div>

      <div className="table-wrap">
        <div style={{ padding: 16 }}>
          <Msg msg={message} />

          {/* ── IOC Database ── */}
          {tab === 'iocs' && (
            <>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 12 }}>
                <select value={filterType} onChange={(e) => setFilterType(e.target.value)} style={{ ...inputStyle, width: 100 }}>
                  <option value="">All Types</option>
                  <option value="ip">IP</option>
                  <option value="domain">Domain</option>
                  <option value="hash">Hash</option>
                  <option value="url">URL</option>
                </select>
                <select value={filterSev} onChange={(e) => setFilterSev(e.target.value)} style={{ ...inputStyle, width: 110 }}>
                  <option value="">All Severity</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
                <input placeholder="Search value / source..." value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && fetchIOCs()}
                  style={{ ...inputStyle, width: 200 }} />
                <button type="button" onClick={fetchIOCs}>Search</button>
                <div style={{ flex: 1 }} />
                {canWrite && (
                  <button type="button" onClick={() => setShowAdd((v) => !v)}>
                    {showAdd ? 'Cancel' : '+ Add IOC'}
                  </button>
                )}
              </div>

              {showAdd && (
                <div style={{ padding: 14, border: '1px solid var(--border)', borderRadius: 8,
                  background: 'var(--bg-secondary)', marginBottom: 14 }}>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                    <div>
                      <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Type</label>
                      <select value={newIOC.type} onChange={(e) => setNewIOC((v) => ({ ...v, type: e.target.value as IOCType }))} style={inputStyle}>
                        <option value="ip">IP</option>
                        <option value="domain">Domain</option>
                        <option value="hash">Hash</option>
                        <option value="url">URL</option>
                      </select>
                    </div>
                    <div>
                      <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Value *</label>
                      <input value={newIOC.value} onChange={(e) => setNewIOC((v) => ({ ...v, value: e.target.value }))}
                        placeholder="e.g. 1.2.3.4, evil.com, sha256..." style={{ ...inputStyle, width: 250 }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Severity</label>
                      <select value={newIOC.severity} onChange={(e) => setNewIOC((v) => ({ ...v, severity: e.target.value }))} style={inputStyle}>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="info">Info</option>
                      </select>
                    </div>
                    <div>
                      <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>TLP</label>
                      <select value={newIOC.tlp} onChange={(e) => setNewIOC((v) => ({ ...v, tlp: e.target.value as TLP }))} style={inputStyle}>
                        <option value="white">White</option>
                        <option value="green">Green</option>
                        <option value="amber">Amber</option>
                        <option value="red">Red</option>
                      </select>
                    </div>
                    <div>
                      <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Source</label>
                      <input value={newIOC.source} onChange={(e) => setNewIOC((v) => ({ ...v, source: e.target.value }))}
                        placeholder="e.g. manual, VirusTotal" style={{ ...inputStyle, width: 130 }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Tags (comma sep)</label>
                      <input value={newIOC.tags} onChange={(e) => setNewIOC((v) => ({ ...v, tags: e.target.value }))}
                        placeholder="ransomware, c2" style={{ ...inputStyle, width: 160 }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Description</label>
                      <input value={newIOC.description} onChange={(e) => setNewIOC((v) => ({ ...v, description: e.target.value }))}
                        placeholder="optional notes" style={{ ...inputStyle, width: 200 }} />
                    </div>
                    <button type="button" onClick={addIOC} disabled={saving || !newIOC.value}>
                      {saving ? 'Adding...' : 'Add IOC'}
                    </button>
                  </div>
                </div>
              )}

              {loading ? (
                <div style={{ color: 'var(--text-muted)', padding: 16 }}>Loading...</div>
              ) : iocs.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', padding: 16 }}>No IOCs found.</div>
              ) : (
                <table>
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Value</th>
                      <th>Severity</th>
                      <th>TLP</th>
                      <th>Source</th>
                      <th>Hits</th>
                      <th>Last Hit</th>
                      <th>Added</th>
                      {canWrite && <th style={{ width: 40 }}></th>}
                    </tr>
                  </thead>
                  <tbody>
                    {iocs.map((ioc) => (
                      <tr key={ioc.id}>
                        <td>
                          <span style={{ fontSize: 11, fontFamily: 'monospace', background: 'var(--bg-secondary)',
                            padding: '2px 6px', borderRadius: 4, border: '1px solid var(--border)' }}>
                            {ioc.type}
                          </span>
                        </td>
                        <td style={{ fontFamily: 'monospace', fontSize: 12, maxWidth: 300, wordBreak: 'break-all' }}>
                          {ioc.value}
                          {ioc.tags?.length > 0 && (
                            <div style={{ marginTop: 2, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                              {ioc.tags.map((t) => (
                                <span key={t} style={{ fontSize: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                                  borderRadius: 3, padding: '1px 5px', color: 'var(--text-muted)' }}>{t}</span>
                              ))}
                            </div>
                          )}
                        </td>
                        <td>
                          <span style={{ fontSize: 12, fontWeight: 600, color: SEV_COLOR[ioc.severity] || 'inherit' }}>
                            {ioc.severity}
                          </span>
                        </td>
                        <td>
                          <span style={{ fontSize: 11, fontWeight: 700, color: TLP_COLOR[ioc.tlp] }}>
                            TLP:{ioc.tlp?.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{ioc.source || '—'}</td>
                        <td style={{ fontSize: 12 }}>{ioc.hit_count || 0}</td>
                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {ioc.last_hit_at ? new Date(ioc.last_hit_at).toLocaleString() : '—'}
                        </td>
                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {new Date(ioc.created_at).toLocaleDateString()}
                        </td>
                        {canWrite && (
                          <td>
                            <button type="button" onClick={() => deleteIOC(ioc.id, ioc.value)}
                              style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 16 }}>
                              ×
                            </button>
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}

          {/* ── Lookup ── */}
          {tab === 'lookup' && (
            <div style={{ maxWidth: 600 }}>
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 10 }}>
                  Lookup any IP address, domain, file hash, or URL against the IOC database.
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <input value={lookupValue} onChange={(e) => setLookupValue(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && doLookup()}
                    placeholder="1.2.3.4, evil.com, sha256hash, https://..."
                    style={{ ...inputStyle, flex: 1 }} />
                  <button type="button" onClick={doLookup} disabled={lookupLoading || !lookupValue.trim()}>
                    {lookupLoading ? 'Looking up...' : 'Lookup'}
                  </button>
                </div>
              </div>

              {lookupResult && (
                <div style={{ padding: 16, borderRadius: 8, border: `2px solid ${lookupResult.matched ? 'var(--red)' : 'var(--green)'}`,
                  background: lookupResult.matched ? 'var(--red-dim)' : 'var(--green-dim)' }}>
                  <div style={{ fontWeight: 700, fontSize: 15, color: lookupResult.matched ? 'var(--red)' : 'var(--green)', marginBottom: 8 }}>
                    {lookupResult.matched ? '⚠ THREAT DETECTED' : '✓ Not found in IOC database'}
                  </div>
                  {lookupResult.matched && lookupResult.ioc && (
                    <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '6px 16px', fontSize: 13 }}>
                      <span style={{ color: 'var(--text-muted)' }}>Value</span>
                      <span style={{ fontFamily: 'monospace' }}>{lookupResult.ioc.value}</span>
                      <span style={{ color: 'var(--text-muted)' }}>Type</span>
                      <span>{lookupResult.ioc.type}</span>
                      <span style={{ color: 'var(--text-muted)' }}>Severity</span>
                      <span style={{ fontWeight: 600, color: SEV_COLOR[lookupResult.ioc.severity] }}>{lookupResult.ioc.severity}</span>
                      <span style={{ color: 'var(--text-muted)' }}>TLP</span>
                      <span style={{ fontWeight: 700, color: TLP_COLOR[lookupResult.ioc.tlp] }}>TLP:{lookupResult.ioc.tlp?.toUpperCase()}</span>
                      <span style={{ color: 'var(--text-muted)' }}>Source</span>
                      <span>{lookupResult.ioc.source || '—'}</span>
                      {lookupResult.ioc.description && (
                        <>
                          <span style={{ color: 'var(--text-muted)' }}>Description</span>
                          <span>{lookupResult.ioc.description}</span>
                        </>
                      )}
                      <span style={{ color: 'var(--text-muted)' }}>Total Hits</span>
                      <span>{lookupResult.ioc.hit_count}</span>
                    </div>
                  )}
                  {!lookupResult.matched && (
                    <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                      <span style={{ fontFamily: 'monospace' }}>{lookupResult.value}</span> ({lookupResult.type}) — no match
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ── Feed Import ── */}
          {tab === 'feed' && (
            <div style={{ maxWidth: 700 }}>
              {!canWrite ? (
                <div style={{ color: 'var(--text-muted)' }}>Write access required to import feeds.</div>
              ) : (
                <>
                  <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16 }}>
                    Import IOCs from an external feed URL or paste raw text. Supported formats: plain text (one value per line), JSON array, URLhaus CSV.
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    <div>
                      <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Feed URL (optional)</label>
                      <input value={feedURL} onChange={(e) => setFeedURL(e.target.value)}
                        placeholder="https://feeds.example.com/iocs.txt"
                        style={{ ...inputStyle, width: '100%' }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Paste raw text (optional)</label>
                      <textarea value={feedText} onChange={(e) => setFeedText(e.target.value)}
                        placeholder="1.2.3.4&#10;evil.com&#10;..."
                        style={{ ...inputStyle, width: '100%', minHeight: 100, resize: 'vertical', fontFamily: 'monospace', fontSize: 12 }} />
                    </div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      <div>
                        <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Format</label>
                        <select value={feedFormat} onChange={(e) => setFeedFormat(e.target.value)} style={inputStyle}>
                          <option value="auto">Auto-detect</option>
                          <option value="plain">Plain text</option>
                          <option value="json">JSON</option>
                          <option value="urlhaus">URLhaus CSV</option>
                        </select>
                      </div>
                      <div>
                        <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Source label</label>
                        <input value={feedSource} onChange={(e) => setFeedSource(e.target.value)}
                          placeholder="e.g. abuse.ch, custom" style={{ ...inputStyle, width: 160 }} />
                      </div>
                      <div style={{ alignSelf: 'flex-end' }}>
                        <button type="button" onClick={doFeedImport}
                          disabled={feedLoading || (!feedURL && !feedText)}>
                          {feedLoading ? 'Importing...' : 'Import'}
                        </button>
                      </div>
                    </div>
                  </div>

                  {feedResult && (
                    <div style={{ marginTop: 16, padding: 14, borderRadius: 8,
                      background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                      <div style={{ fontWeight: 600, marginBottom: 8, fontSize: 14 }}>Import Result</div>
                      <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '4px 16px', fontSize: 13 }}>
                        <span style={{ color: 'var(--text-muted)' }}>Added</span>
                        <span style={{ color: 'var(--green)', fontWeight: 600 }}>{feedResult.added}</span>
                        <span style={{ color: 'var(--text-muted)' }}>Skipped</span>
                        <span>{feedResult.skipped}</span>
                        <span style={{ color: 'var(--text-muted)' }}>Source</span>
                        <span>{feedResult.source}</span>
                        {feedResult.errors?.length > 0 && (
                          <>
                            <span style={{ color: 'var(--red)' }}>Errors</span>
                            <span style={{ color: 'var(--red)', fontSize: 12, fontFamily: 'monospace' }}>
                              {feedResult.errors.slice(0, 5).join(', ')}
                              {feedResult.errors.length > 5 ? ` (+${feedResult.errors.length - 5} more)` : ''}
                            </span>
                          </>
                        )}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {/* ── Statistics ── */}
          {tab === 'stats' && (
            <>
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
                <button type="button" onClick={fetchStats}>Refresh</button>
              </div>
              {!stats ? (
                <div style={{ color: 'var(--text-muted)' }}>Loading statistics...</div>
              ) : (
                <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                  <StatCard title="Total IOCs" value={stats.total} />
                  <StatSection title="By Type" data={stats.by_type} />
                  <StatSection title="By Severity" data={stats.by_severity} colors={SEV_COLOR} />
                  <StatSection title="By Source" data={stats.by_source} />
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value }: { title: string; value: number }) {
  return (
    <div style={{ padding: '16px 24px', borderRadius: 10, border: '1px solid var(--border)',
      background: 'var(--bg-secondary)', minWidth: 140, textAlign: 'center' }}>
      <div style={{ fontSize: 28, fontWeight: 700 }}>{value}</div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>{title}</div>
    </div>
  );
}

function StatSection({ title, data, colors }: { title: string; data: Record<string, number>; colors?: Record<string, string> }) {
  const entries = Object.entries(data || {}).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return null;
  return (
    <div style={{ padding: 16, borderRadius: 10, border: '1px solid var(--border)',
      background: 'var(--bg-secondary)', minWidth: 180 }}>
      <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 10 }}>{title}</div>
      {entries.map(([key, count]) => (
        <div key={key} style={{ display: 'flex', justifyContent: 'space-between', gap: 16,
          fontSize: 13, marginBottom: 4, color: colors?.[key] || 'inherit' }}>
          <span style={{ textTransform: 'capitalize' }}>{key}</span>
          <span style={{ fontWeight: 600 }}>{count}</span>
        </div>
      ))}
    </div>
  );
}
