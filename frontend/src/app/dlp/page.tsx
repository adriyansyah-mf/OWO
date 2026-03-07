'use client';

import { useCallback, useEffect, useState } from 'react';
import { getAuthHeaders, getApiBase } from '@/contexts/AuthContext';

type TabId = 'results' | 'patterns' | 'policies' | 'audit' | 'behavioral' | 'fingerprints' | 'paths';

const TABS: { id: TabId; label: string }[] = [
  { id: 'results', label: 'Scan Results' },
  { id: 'patterns', label: 'Patterns' },
  { id: 'policies', label: 'Policies' },
  { id: 'audit', label: 'Audit Log' },
  { id: 'behavioral', label: 'Behavioral' },
  { id: 'fingerprints', label: 'Fingerprints' },
  { id: 'paths', label: 'Paths' },
];

const SEVERITY_OPTIONS = ['low', 'medium', 'high', 'critical'];
const ACTION_OPTIONS = ['audit', 'alert', 'escalate', 'quarantine', 'block'];
const CHANNEL_OPTIONS = ['usb', 'cloud_storage', 'email', 'clipboard', 'print', 'network_upload', 'local_file', 'all'];
const LABEL_OPTIONS = ['public', 'internal', 'confidential', 'restricted', 'secret'];

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)',
  high: 'var(--orange, #f97316)',
  medium: 'var(--yellow)',
  low: 'var(--text-muted)',
};

const ACTION_COLOR: Record<string, string> = {
  block: 'var(--red)',
  quarantine: 'var(--orange, #f97316)',
  escalate: 'var(--yellow)',
  alert: 'var(--blue, #3b82f6)',
  audit: 'var(--text-muted)',
};

const inputStyle: React.CSSProperties = {
  padding: '6px 10px',
  borderRadius: 6,
  border: '1px solid var(--border)',
  background: 'var(--bg-secondary)',
  color: 'inherit',
  fontSize: 13,
};

const Badge = ({ text, color }: { text: string; color?: string }) => (
  <span
    style={{
      display: 'inline-block',
      padding: '2px 8px',
      borderRadius: 12,
      fontSize: 11,
      fontWeight: 600,
      background: color ? color + '22' : 'var(--bg-secondary)',
      color: color || 'var(--text-muted)',
      marginRight: 4,
    }}
  >
    {text}
  </span>
);

const Msg = ({ msg }: { msg: { type: 'ok' | 'err'; text: string } | null }) =>
  msg ? (
    <div
      style={{
        padding: '10px 14px',
        borderRadius: 8,
        marginBottom: 14,
        background: msg.type === 'ok' ? 'var(--green-dim)' : 'var(--red-dim)',
        color: msg.type === 'ok' ? 'var(--green)' : 'var(--red)',
        fontSize: 13,
      }}
    >
      {msg.text}
    </div>
  ) : null;

export default function DLPPage() {
  const api = getApiBase() || 'http://localhost:8080';

  // -- Shared state --
  const [tab, setTab] = useState<TabId>('results');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // -- Scan Results --
  const [results, setResults] = useState<any[]>([]);

  // -- Patterns --
  const [patterns, setPatterns] = useState<any[]>([]);
  const [newPattern, setNewPattern] = useState({ id: '', name: '', regex: '', severity: 'medium' });

  // -- Policies --
  const [policies, setPolicies] = useState<any[]>([]);
  const [editingPolicy, setEditingPolicy] = useState<any | null>(null);

  // -- Audit Log --
  const [auditEvents, setAuditEvents] = useState<any[]>([]);
  const [auditSeverityFilter, setAuditSeverityFilter] = useState('');
  const [auditActionFilter, setAuditActionFilter] = useState('');

  // -- Behavioral --
  const [behavioral, setBehavioral] = useState({ enabled: false, mass_access_per_minute: 100, bulk_read_mb: 50, usb_copy_per_minute: 20 });

  // -- Fingerprints --
  const [fingerprints, setFingerprints] = useState<any[]>([]);
  const [newFp, setNewFp] = useState({ hash: '', name: '', label: 'restricted', notes: '' });

  // -- Paths --
  const [paths, setPaths] = useState<string[]>([]);
  const [newPath, setNewPath] = useState('');

  // ─── Fetchers ───────────────────────────────────────────────────────────────

  const fetchResults = useCallback(() => {
    fetch(`${api}/api/v1/dlp-scan-results`, { headers: getAuthHeaders() })
      .then((r) => r.json()).then((d) => setResults(Array.isArray(d) ? d : [])).catch(() => {});
  }, [api]);

  const fetchPatterns = useCallback(() => {
    fetch(`${api}/api/v1/dlp/patterns`, { headers: getAuthHeaders() })
      .then((r) => r.json()).then((d) => setPatterns(Array.isArray(d) ? d : [])).catch(() => {});
  }, [api]);

  const fetchPolicies = useCallback(() => {
    fetch(`${api}/api/v1/dlp/policies`, { headers: getAuthHeaders() })
      .then((r) => r.json()).then((d) => setPolicies(Array.isArray(d) ? d : [])).catch(() => {});
  }, [api]);

  const fetchAudit = useCallback(() => {
    const params = new URLSearchParams({ limit: '200' });
    if (auditSeverityFilter) params.set('severity', auditSeverityFilter);
    if (auditActionFilter) params.set('action', auditActionFilter);
    fetch(`${api}/api/v1/dlp/audit?${params}`, { headers: getAuthHeaders() })
      .then((r) => r.json()).then((d) => setAuditEvents(Array.isArray(d) ? d : [])).catch(() => {});
  }, [api, auditSeverityFilter, auditActionFilter]);

  const fetchBehavioral = useCallback(() => {
    fetch(`${api}/api/v1/dlp/behavioral`, { headers: getAuthHeaders() })
      .then((r) => r.json()).then((d) => { if (d && typeof d === 'object') setBehavioral(d); }).catch(() => {});
  }, [api]);

  const fetchFingerprints = useCallback(() => {
    fetch(`${api}/api/v1/dlp/fingerprints`, { headers: getAuthHeaders() })
      .then((r) => r.json()).then((d) => setFingerprints(Array.isArray(d) ? d : [])).catch(() => {});
  }, [api]);

  const fetchPaths = useCallback(() => {
    fetch(`${api}/api/v1/settings/dlp-paths`, { headers: getAuthHeaders() })
      .then((r) => r.json()).then((d) => setPaths(Array.isArray(d) ? d : [])).catch(() => {});
  }, [api]);

  useEffect(() => {
    Promise.all([fetchResults(), fetchPatterns(), fetchPolicies(), fetchBehavioral(), fetchFingerprints(), fetchPaths()])
      .finally(() => setLoading(false));
    const iv = setInterval(fetchResults, 5000);
    return () => clearInterval(iv);
  }, [fetchResults, fetchPatterns, fetchPolicies, fetchBehavioral, fetchFingerprints, fetchPaths]);

  useEffect(() => {
    if (tab === 'audit') fetchAudit();
  }, [tab, fetchAudit]);

  const showMsg = (type: 'ok' | 'err', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  };

  // ─── Patterns handlers ───────────────────────────────────────────────────────

  const addPattern = () => {
    if (!newPattern.regex.trim()) return;
    const id = newPattern.id.trim() || 'custom_' + Date.now();
    setPatterns((p) => [...p, { id, name: newPattern.name || id, regex: newPattern.regex, severity: newPattern.severity }]);
    setNewPattern({ id: '', name: '', regex: '', severity: 'medium' });
  };

  const savePatterns = async () => {
    setSaving(true);
    try {
      const res = await fetch(`${api}/api/v1/dlp/patterns`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(patterns),
      });
      if (!res.ok) { showMsg('err', await res.text() || `Save failed (${res.status})`); return; }
      setPatterns(await res.json());
      showMsg('ok', 'Patterns saved.');
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  // ─── Policies handlers ───────────────────────────────────────────────────────

  const savePolicies = async (updated: any[]) => {
    setSaving(true);
    try {
      const res = await fetch(`${api}/api/v1/dlp/policies`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(updated),
      });
      if (!res.ok) { showMsg('err', await res.text() || `Save failed (${res.status})`); return; }
      setPolicies(await res.json());
      showMsg('ok', 'Policies saved and pushed to agents.');
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  const togglePolicy = (idx: number) => {
    const updated = policies.map((p, i) => i === idx ? { ...p, enabled: !p.enabled } : p);
    setPolicies(updated);
    savePolicies(updated);
  };

  const deletePolicy = (idx: number) => {
    const updated = policies.filter((_, i) => i !== idx);
    savePolicies(updated);
  };

  const blankPolicy = () => ({
    id: 'pol-' + Date.now(),
    name: 'New Policy',
    enabled: true,
    min_severity: 'high',
    channels: ['usb'],
    actions: ['alert'],
    pattern_ids: [],
    quarantine_dir: '',
    escalation_subject: 'dlp.escalation',
    scope_users: [],
    scope_paths: [],
    scope_processes: [],
    cache_version: 1,
    updated_at: new Date().toISOString(),
  });

  const saveEditingPolicy = () => {
    if (!editingPolicy) return;
    const idx = policies.findIndex((p) => p.id === editingPolicy.id);
    let updated: any[];
    if (idx >= 0) {
      updated = policies.map((p, i) => i === idx ? editingPolicy : p);
    } else {
      updated = [...policies, editingPolicy];
    }
    setEditingPolicy(null);
    savePolicies(updated);
  };

  // ─── Behavioral handlers ─────────────────────────────────────────────────────

  const saveBehavioral = async () => {
    setSaving(true);
    try {
      const res = await fetch(`${api}/api/v1/dlp/behavioral`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(behavioral),
      });
      if (!res.ok) { showMsg('err', await res.text() || `Save failed (${res.status})`); return; }
      setBehavioral(await res.json());
      showMsg('ok', 'Behavioral config saved and pushed to agents.');
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  // ─── Fingerprints handlers ───────────────────────────────────────────────────

  const addFingerprint = async () => {
    if (newFp.hash.length !== 64 || !newFp.name.trim()) return;
    setSaving(true);
    try {
      const res = await fetch(`${api}/api/v1/dlp/fingerprints`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(newFp),
      });
      if (!res.ok) { showMsg('err', await res.text() || `Failed (${res.status})`); return; }
      setNewFp({ hash: '', name: '', label: 'restricted', notes: '' });
      fetchFingerprints();
      showMsg('ok', 'Fingerprint registered.');
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  const deleteFingerprint = async (hash: string) => {
    try {
      await fetch(`${api}/api/v1/dlp/fingerprints?hash=${encodeURIComponent(hash)}`, {
        method: 'DELETE', headers: getAuthHeaders(),
      });
      setFingerprints((f) => f.filter((e) => e.hash !== hash));
    } catch {}
  };

  // ─── Paths handlers ──────────────────────────────────────────────────────────

  const savePaths = async (updated: string[]) => {
    setSaving(true);
    try {
      const res = await fetch(`${api}/api/v1/settings/dlp-paths`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(updated),
      });
      if (!res.ok) { showMsg('err', `Save failed (${res.status})`); return; }
      setPaths(await res.json());
      showMsg('ok', 'DLP scan paths saved.');
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  const addPath = () => {
    const p = newPath.trim();
    if (!p || !p.startsWith('/') || paths.includes(p)) return;
    setNewPath('');
    savePaths([...paths, p]);
  };

  // ─── Subtitle ────────────────────────────────────────────────────────────────

  const subtitle = {
    results: `${results.length} scan(s), ${results.reduce((a, r) => a + (Array.isArray(r.matches) ? r.matches.length : 0), 0)} finding(s)`,
    patterns: `${patterns.length} pattern(s)`,
    policies: `${policies.length} polic${policies.length === 1 ? 'y' : 'ies'}`,
    audit: `${auditEvents.length} event(s)`,
    behavioral: behavioral.enabled ? 'Enabled' : 'Disabled',
    fingerprints: `${fingerprints.length} fingerprint(s)`,
    paths: `${paths.length} path(s)`,
  }[tab];

  // ─── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="card">
      <div className="card-header" style={{ flexWrap: 'wrap', gap: 8 }}>
        <span className="card-title">Data Loss Prevention</span>
        <div className="filter-tabs" style={{ marginLeft: 16, flexWrap: 'wrap' }}>
          {TABS.map((t) => (
            <div key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
              {t.label}
            </div>
          ))}
        </div>
        <span className="card-subtitle" style={{ marginLeft: 8 }}>{subtitle}</span>
      </div>

      <div className="table-wrap">
        {loading ? (
          <div style={{ padding: 24, color: 'var(--text-muted)' }}>Loading...</div>
        ) : (
          <div style={{ padding: 16 }}>
            <Msg msg={message} />

            {/* ── Scan Results ── */}
            {tab === 'results' && (
              results.length === 0 ? (
                <div style={{ color: 'var(--text-muted)' }}>
                  No DLP scan results yet. Run a DLP Scan from the sidebar.
                </div>
              ) : results.map((r: any, i: number) => {
                const matches = r.matches || [];
                return (
                  <div key={i} style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 12, background: 'var(--bg-secondary)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                      <strong>{r.host_id || 'Unknown'}</strong>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {r.timestamp ? new Date(r.timestamp).toLocaleString() : '—'}
                      </span>
                    </div>
                    <div style={{ fontSize: 13, marginBottom: 6 }}>{matches.length} finding(s)</div>
                    {matches.length > 0 && (
                      <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12 }}>
                        {matches.slice(0, 20).map((m: any, j: number) => (
                          <li key={j} style={{ marginBottom: 4 }}>
                            <code style={{ fontSize: 11 }}>{m.path}</code>
                            {m.line && <span style={{ color: 'var(--text-muted)' }}> L{m.line}</span>}
                            {m.pattern && <span style={{ color: 'var(--red)', marginLeft: 8 }}>→ {m.pattern}</span>}
                            {m.snippet && <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 2 }}>{m.snippet}</div>}
                          </li>
                        ))}
                        {matches.length > 20 && <li style={{ color: 'var(--text-muted)', fontSize: 11 }}>+{matches.length - 20} more</li>}
                      </ul>
                    )}
                  </div>
                );
              })
            )}

            {/* ── Patterns ── */}
            {tab === 'patterns' && (
              <>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end', marginBottom: 16 }}>
                  <input placeholder="ID (optional)" value={newPattern.id} onChange={(e) => setNewPattern((p) => ({ ...p, id: e.target.value }))} style={{ ...inputStyle, width: 100 }} />
                  <input placeholder="Name" value={newPattern.name} onChange={(e) => setNewPattern((p) => ({ ...p, name: e.target.value }))} style={{ ...inputStyle, width: 140 }} />
                  <input placeholder="Regex" value={newPattern.regex} onChange={(e) => setNewPattern((p) => ({ ...p, regex: e.target.value }))} onKeyDown={(e) => e.key === 'Enter' && addPattern()} style={{ ...inputStyle, flex: 1, minWidth: 180 }} />
                  <select value={newPattern.severity} onChange={(e) => setNewPattern((p) => ({ ...p, severity: e.target.value }))} style={inputStyle}>
                    {SEVERITY_OPTIONS.map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                  <button type="button" onClick={addPattern} disabled={!newPattern.regex.trim()}>Add</button>
                  <button type="button" onClick={savePatterns} disabled={saving} style={{ marginLeft: 'auto' }}>{saving ? 'Saving...' : 'Save Patterns'}</button>
                </div>
                <table>
                  <thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>Regex</th><th style={{ width: 40 }}></th></tr></thead>
                  <tbody>
                    {patterns.map((p: any, i: number) => (
                      <tr key={i}>
                        <td><input value={p.id} onChange={(e) => setPatterns((arr) => { const n = [...arr]; n[i] = { ...n[i], id: e.target.value }; return n; })} style={{ ...inputStyle, width: 90 }} /></td>
                        <td><input value={p.name} onChange={(e) => setPatterns((arr) => { const n = [...arr]; n[i] = { ...n[i], name: e.target.value }; return n; })} style={{ ...inputStyle, width: 120 }} /></td>
                        <td>
                          <select value={p.severity} onChange={(e) => setPatterns((arr) => { const n = [...arr]; n[i] = { ...n[i], severity: e.target.value }; return n; })} style={inputStyle}>
                            {SEVERITY_OPTIONS.map((s) => <option key={s} value={s}>{s}</option>)}
                          </select>
                        </td>
                        <td><input value={p.regex} onChange={(e) => setPatterns((arr) => { const n = [...arr]; n[i] = { ...n[i], regex: e.target.value }; return n; })} style={{ ...inputStyle, width: '100%', minWidth: 150, fontFamily: 'monospace', fontSize: 11 }} /></td>
                        <td><button type="button" onClick={() => setPatterns((arr) => arr.filter((_, j) => j !== i))} style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 16 }}>×</button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}

            {/* ── Policies ── */}
            {tab === 'policies' && (
              <>
                {editingPolicy ? (
                  <PolicyEditor
                    policy={editingPolicy}
                    onChange={setEditingPolicy}
                    onSave={saveEditingPolicy}
                    onCancel={() => setEditingPolicy(null)}
                    saving={saving}
                  />
                ) : (
                  <>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
                      <button type="button" onClick={() => setEditingPolicy(blankPolicy())}>+ New Policy</button>
                    </div>
                    {policies.length === 0 ? (
                      <div style={{ color: 'var(--text-muted)' }}>No policies configured.</div>
                    ) : (
                      <table>
                        <thead>
                          <tr>
                            <th>Name</th>
                            <th>Min Severity</th>
                            <th>Channels</th>
                            <th>Actions</th>
                            <th>Enabled</th>
                            <th style={{ width: 100 }}></th>
                          </tr>
                        </thead>
                        <tbody>
                          {policies.map((p: any, i: number) => (
                            <tr key={p.id || i} style={{ opacity: p.enabled ? 1 : 0.5 }}>
                              <td>
                                <div style={{ fontWeight: 600, fontSize: 13 }}>{p.name}</div>
                                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{p.id}</div>
                              </td>
                              <td><Badge text={p.min_severity || '—'} color={SEV_COLOR[p.min_severity]} /></td>
                              <td style={{ fontSize: 12 }}>
                                {(p.channels || []).map((c: string) => <Badge key={c} text={c} />)}
                              </td>
                              <td>
                                {(p.actions || []).map((a: string) => <Badge key={a} text={a} color={ACTION_COLOR[a]} />)}
                              </td>
                              <td>
                                <label style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}>
                                  <input type="checkbox" checked={!!p.enabled} onChange={() => togglePolicy(i)} />
                                </label>
                              </td>
                              <td>
                                <button type="button" onClick={() => setEditingPolicy({ ...p })} style={{ marginRight: 6 }}>Edit</button>
                                <button type="button" onClick={() => deletePolicy(i)} style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 16 }}>×</button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </>
                )}
              </>
            )}

            {/* ── Audit Log ── */}
            {tab === 'audit' && (
              <>
                <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
                  <select value={auditSeverityFilter} onChange={(e) => setAuditSeverityFilter(e.target.value)} style={inputStyle}>
                    <option value="">All severities</option>
                    {SEVERITY_OPTIONS.map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                  <select value={auditActionFilter} onChange={(e) => setAuditActionFilter(e.target.value)} style={inputStyle}>
                    <option value="">All actions</option>
                    {ACTION_OPTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
                  </select>
                  <button type="button" onClick={fetchAudit}>Refresh</button>
                </div>
                {auditEvents.length === 0 ? (
                  <div style={{ color: 'var(--text-muted)' }}>No audit events found. DLP audit log may not exist yet on the agent.</div>
                ) : (
                  <table>
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>File</th>
                        <th>Channel</th>
                        <th>Action</th>
                        <th>Severity</th>
                        <th>Policy</th>
                        <th>Process</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditEvents.map((ev: any, i: number) => (
                        <tr key={i}>
                          <td style={{ fontSize: 11, whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                            {ev['@timestamp'] ? new Date(ev['@timestamp']).toLocaleString() : ev.timestamp || '—'}
                          </td>
                          <td style={{ fontSize: 11 }}>
                            <code style={{ fontSize: 10 }}>{ev.object_path || ev['file.path'] || '—'}</code>
                            {ev.sensitivity_label && <Badge text={ev.sensitivity_label} />}
                          </td>
                          <td><Badge text={ev.channel || '—'} /></td>
                          <td><Badge text={ev.action || '—'} color={ACTION_COLOR[ev.action]} /></td>
                          <td><Badge text={ev.severity || '—'} color={SEV_COLOR[ev.severity]} /></td>
                          <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{ev.policy_id || '—'}</td>
                          <td style={{ fontSize: 11 }}>{ev.process_name || ev['process.name'] || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </>
            )}

            {/* ── Behavioral ── */}
            {tab === 'behavioral' && (
              <div style={{ maxWidth: 480 }}>
                <p style={{ color: 'var(--text-muted)', fontSize: 13, marginBottom: 20 }}>
                  Configure the behavioral DLP engine. These thresholds apply per-process over a 60-second sliding window.
                  Changes are pushed to all connected agents via NATS.
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 14 }}>
                    <input
                      type="checkbox"
                      checked={behavioral.enabled}
                      onChange={(e) => setBehavioral((b) => ({ ...b, enabled: e.target.checked }))}
                    />
                    Enable Behavioral DLP Engine
                    <span style={{ fontSize: 12, color: behavioral.enabled ? 'var(--green)' : 'var(--text-muted)' }}>
                      ({behavioral.enabled ? 'ON' : 'OFF'})
                    </span>
                  </label>
                  <ThresholdInput
                    label="Mass File Access (files/min)"
                    hint="Trigger RuleMassFileAccess when a process reads more than N files per minute"
                    value={behavioral.mass_access_per_minute}
                    onChange={(v) => setBehavioral((b) => ({ ...b, mass_access_per_minute: v }))}
                  />
                  <ThresholdInput
                    label="Bulk Read (MB/min)"
                    hint="Trigger RuleBulkRead when a process reads more than N MB per minute"
                    value={behavioral.bulk_read_mb}
                    onChange={(v) => setBehavioral((b) => ({ ...b, bulk_read_mb: v }))}
                  />
                  <ThresholdInput
                    label="USB Copy Rate (files/min)"
                    hint="Trigger RuleUSBBulkCopy when a process writes more than N files to USB per minute"
                    value={behavioral.usb_copy_per_minute}
                    onChange={(v) => setBehavioral((b) => ({ ...b, usb_copy_per_minute: v }))}
                  />
                  <div>
                    <button type="button" onClick={saveBehavioral} disabled={saving}>
                      {saving ? 'Saving...' : 'Save Behavioral Config'}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* ── Fingerprints ── */}
            {tab === 'fingerprints' && (
              <>
                <p style={{ color: 'var(--text-muted)', fontSize: 13, marginBottom: 16 }}>
                  Register SHA256 fingerprints of known sensitive documents. When a scanned file matches,
                  it is automatically classified at the registered label without requiring pattern matching.
                </p>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end', marginBottom: 16, padding: 16, background: 'var(--bg-secondary)', borderRadius: 8, border: '1px solid var(--border)' }}>
                  <input placeholder="SHA256 hash (64 hex chars)" value={newFp.hash} onChange={(e) => setNewFp((f) => ({ ...f, hash: e.target.value.toLowerCase().trim() }))} style={{ ...inputStyle, flex: 2, minWidth: 200, fontFamily: 'monospace', fontSize: 11 }} />
                  <input placeholder="Document name" value={newFp.name} onChange={(e) => setNewFp((f) => ({ ...f, name: e.target.value }))} style={{ ...inputStyle, flex: 1, minWidth: 140 }} />
                  <select value={newFp.label} onChange={(e) => setNewFp((f) => ({ ...f, label: e.target.value }))} style={inputStyle}>
                    {LABEL_OPTIONS.map((l) => <option key={l} value={l}>{l}</option>)}
                  </select>
                  <input placeholder="Notes (optional)" value={newFp.notes} onChange={(e) => setNewFp((f) => ({ ...f, notes: e.target.value }))} style={{ ...inputStyle, flex: 1, minWidth: 120 }} />
                  <button type="button" onClick={addFingerprint} disabled={saving || newFp.hash.length !== 64 || !newFp.name.trim()}>
                    Register
                  </button>
                </div>
                {fingerprints.length === 0 ? (
                  <div style={{ color: 'var(--text-muted)' }}>No fingerprints registered.</div>
                ) : (
                  <table>
                    <thead><tr><th>SHA256</th><th>Name</th><th>Label</th><th>Notes</th><th style={{ width: 40 }}></th></tr></thead>
                    <tbody>
                      {fingerprints.map((fp: any, i: number) => (
                        <tr key={i}>
                          <td><code style={{ fontSize: 10 }}>{fp.hash?.slice(0, 16)}…</code></td>
                          <td style={{ fontSize: 13 }}>{fp.name}</td>
                          <td><Badge text={fp.label || '—'} /></td>
                          <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{fp.notes || '—'}</td>
                          <td>
                            <button type="button" onClick={() => deleteFingerprint(fp.hash)} style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 16 }}>×</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </>
            )}

            {/* ── Paths ── */}
            {tab === 'paths' && (
              <>
                <p style={{ color: 'var(--text-muted)', fontSize: 13, marginBottom: 16 }}>
                  Directories that will be scanned when a DLP scan is triggered. Absolute paths only.
                </p>
                <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
                  <input
                    placeholder="/path/to/scan"
                    value={newPath}
                    onChange={(e) => setNewPath(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && addPath()}
                    style={{ ...inputStyle, flex: 1, fontFamily: 'monospace' }}
                  />
                  <button type="button" onClick={addPath} disabled={!newPath.trim().startsWith('/')}>Add Path</button>
                </div>
                {paths.length === 0 ? (
                  <div style={{ color: 'var(--text-muted)' }}>No DLP scan paths configured.</div>
                ) : (
                  <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                    {paths.map((p, i) => (
                      <li key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                        <code style={{ flex: 1, fontSize: 13 }}>{p}</code>
                        <button
                          type="button"
                          onClick={() => savePaths(paths.filter((_, j) => j !== i))}
                          style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 16 }}
                        >×</button>
                      </li>
                    ))}
                  </ul>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── PolicyEditor sub-component ───────────────────────────────────────────────

function PolicyEditor({
  policy, onChange, onSave, onCancel, saving,
}: {
  policy: any;
  onChange: (p: any) => void;
  onSave: () => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const toggleArr = (field: string, value: string) => {
    const arr: string[] = policy[field] || [];
    onChange({ ...policy, [field]: arr.includes(value) ? arr.filter((x: string) => x !== value) : [...arr, value] });
  };

  const inputStyle: React.CSSProperties = {
    padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)',
    background: 'var(--bg-secondary)', color: 'inherit', fontSize: 13, width: '100%',
  };

  return (
    <div style={{ maxWidth: 600, display: 'flex', flexDirection: 'column', gap: 14 }}>
      <h3 style={{ margin: 0, fontSize: 15 }}>{policy.id ? `Edit: ${policy.name}` : 'New Policy'}</h3>

      <div style={{ display: 'flex', gap: 8 }}>
        <div style={{ flex: 2 }}>
          <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>Name</label>
          <input value={policy.name} onChange={(e) => onChange({ ...policy, name: e.target.value })} style={inputStyle} />
        </div>
        <div style={{ flex: 1 }}>
          <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>ID</label>
          <input value={policy.id} onChange={(e) => onChange({ ...policy, id: e.target.value })} style={{ ...inputStyle, fontFamily: 'monospace', fontSize: 11 }} />
        </div>
      </div>

      <div>
        <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>Min Severity</label>
        <select value={policy.min_severity} onChange={(e) => onChange({ ...policy, min_severity: e.target.value })} style={inputStyle}>
          {['low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      <div>
        <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>Channels</label>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {CHANNEL_OPTIONS.map((c) => (
            <label key={c} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 13, cursor: 'pointer' }}>
              <input type="checkbox" checked={(policy.channels || []).includes(c)} onChange={() => toggleArr('channels', c)} />
              {c}
            </label>
          ))}
        </div>
      </div>

      <div>
        <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>Actions (most restrictive wins)</label>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {ACTION_OPTIONS.map((a) => (
            <label key={a} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 13, cursor: 'pointer' }}>
              <input type="checkbox" checked={(policy.actions || []).includes(a)} onChange={() => toggleArr('actions', a)} />
              <span style={{ color: ACTION_COLOR[a] }}>{a}</span>
            </label>
          ))}
        </div>
      </div>

      <div>
        <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>Quarantine Directory</label>
        <input placeholder="/var/lib/edr/dlp/quarantine" value={policy.quarantine_dir || ''} onChange={(e) => onChange({ ...policy, quarantine_dir: e.target.value })} style={{ ...inputStyle, fontFamily: 'monospace' }} />
      </div>

      <div>
        <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>Escalation NATS Subject</label>
        <input value={policy.escalation_subject || 'dlp.escalation'} onChange={(e) => onChange({ ...policy, escalation_subject: e.target.value })} style={{ ...inputStyle, fontFamily: 'monospace' }} />
      </div>

      <div>
        <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>Pattern IDs (comma-separated, leave empty = all)</label>
        <input
          value={(policy.pattern_ids || []).join(', ')}
          onChange={(e) => onChange({ ...policy, pattern_ids: e.target.value.split(',').map((s: string) => s.trim()).filter(Boolean) })}
          placeholder="aws_key, private_key, ..."
          style={inputStyle}
        />
      </div>

      <div>
        <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>Scope — Limit to paths (comma-separated, empty = all)</label>
        <input
          value={(policy.scope_paths || []).join(', ')}
          onChange={(e) => onChange({ ...policy, scope_paths: e.target.value.split(',').map((s: string) => s.trim()).filter(Boolean) })}
          placeholder="/home, /data, ..."
          style={{ ...inputStyle, fontFamily: 'monospace' }}
        />
      </div>

      <div>
        <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>Scope — Limit to processes (comma-separated, empty = all)</label>
        <input
          value={(policy.scope_processes || []).join(', ')}
          onChange={(e) => onChange({ ...policy, scope_processes: e.target.value.split(',').map((s: string) => s.trim()).filter(Boolean) })}
          placeholder="dropbox, rclone, ..."
          style={inputStyle}
        />
      </div>

      <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
        <input type="checkbox" checked={!!policy.enabled} onChange={(e) => onChange({ ...policy, enabled: e.target.checked })} />
        Enabled
      </label>

      <div style={{ display: 'flex', gap: 8, paddingTop: 4 }}>
        <button type="button" onClick={onSave} disabled={saving}>{saving ? 'Saving...' : 'Save Policy'}</button>
        <button type="button" onClick={onCancel} style={{ background: 'none', border: '1px solid var(--border)' }}>Cancel</button>
      </div>
    </div>
  );
}

// ─── ThresholdInput helper ────────────────────────────────────────────────────

function ThresholdInput({
  label, hint, value, onChange,
}: {
  label: string;
  hint: string;
  value: number;
  onChange: (v: number) => void;
}) {
  return (
    <div>
      <label style={{ fontSize: 13, display: 'block', marginBottom: 4 }}>{label}</label>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>{hint}</div>
      <input
        type="number"
        min={1}
        value={value}
        onChange={(e) => onChange(Math.max(1, parseInt(e.target.value, 10) || 1))}
        style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'inherit', fontSize: 13, width: 120 }}
      />
    </div>
  );
}
