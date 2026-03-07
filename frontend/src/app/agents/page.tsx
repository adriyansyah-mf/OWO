'use client';

import { useCallback, useEffect, useState } from 'react';
import { getAuthHeaders, getApiBase, useAuth } from '@/contexts/AuthContext';

type AgentStatus = 'pending' | 'approved' | 'online' | 'offline' | 'isolated' | 'rejected';

type Agent = {
  id: string;
  hostname: string;
  ip_address?: string;
  os?: string;
  os_version?: string;
  agent_version?: string;
  groups?: string[];
  tags?: string[];
  status: AgentStatus;
  tenant_id: string;
  enrolled_at: string;
  last_seen_at?: string;
  approved_at?: string;
  approved_by?: string;
};

type Stats = {
  total: number;
  online: number;
  offline: number;
  pending: number;
  isolated: number;
  rejected: number;
};

const STATUS_COLOR: Record<AgentStatus, string> = {
  online:   'var(--green)',
  approved: 'var(--blue, #3b82f6)',
  pending:  'var(--yellow)',
  offline:  'var(--text-muted)',
  isolated: 'var(--orange, #f97316)',
  rejected: 'var(--red)',
};

const STATUS_ORDER: AgentStatus[] = ['online', 'pending', 'isolated', 'offline', 'approved', 'rejected'];

const inputStyle: React.CSSProperties = {
  padding: '6px 10px', borderRadius: 6,
  border: '1px solid var(--border)',
  background: 'var(--bg-secondary)',
  color: 'inherit', fontSize: 13,
};

const Badge = ({ text, color }: { text: string; color?: string }) => (
  <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 12, fontSize: 11,
    fontWeight: 600, background: color ? color + '22' : 'var(--bg-secondary)',
    color: color || 'var(--text-muted)', marginRight: 4 }}>
    {text}
  </span>
);

const Msg = ({ msg }: { msg: { type: 'ok' | 'err'; text: string } | null }) =>
  msg ? (
    <div style={{ padding: '10px 14px', borderRadius: 8, marginBottom: 14, fontSize: 13,
      background: msg.type === 'ok' ? 'var(--green-dim)' : 'var(--red-dim)',
      color: msg.type === 'ok' ? 'var(--green)' : 'var(--red)' }}>
      {msg.text}
    </div>
  ) : null;

export default function AgentsPage() {
  const api = getApiBase() || 'http://localhost:8080';
  const { isAdmin, canWrite } = useAuth();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [statusFilter, setStatusFilter] = useState<AgentStatus | ''>('');
  const [editingTags, setEditingTags] = useState<Agent | null>(null);
  const [tagsForm, setTagsForm] = useState({ groups: '', tags: '' });

  const showMsg = (type: 'ok' | 'err', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  };

  const fetchAgents = useCallback(() => {
    fetch(`${api}/api/v1/agents`, { headers: getAuthHeaders() })
      .then((r) => r.json()).then((d) => setAgents(Array.isArray(d) ? d : [])).catch(() => {});
  }, [api]);

  const fetchStats = useCallback(() => {
    fetch(`${api}/api/v1/agents/stats`, { headers: getAuthHeaders() })
      .then((r) => r.json()).then((d) => { if (d && typeof d === 'object') setStats(d); }).catch(() => {});
  }, [api]);

  useEffect(() => {
    setLoading(true);
    Promise.all([fetchAgents(), fetchStats()]).finally(() => setLoading(false));
    const iv = setInterval(() => { fetchAgents(); fetchStats(); }, 15000);
    return () => clearInterval(iv);
  }, [fetchAgents, fetchStats]);

  const setStatus = async (agentId: string, status: AgentStatus) => {
    setSaving(true);
    try {
      const res = await fetch(`${api}/api/v1/agents/${agentId}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify({ status }),
      });
      if (!res.ok) { showMsg('err', (await res.json())?.error || `Failed (${res.status})`); return; }
      fetchAgents();
      fetchStats();
      showMsg('ok', `Agent status set to "${status}".`);
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  const saveTags = async () => {
    if (!editingTags) return;
    setSaving(true);
    const groups = tagsForm.groups.split(',').map((s) => s.trim()).filter(Boolean);
    const tags = tagsForm.tags.split(',').map((s) => s.trim()).filter(Boolean);
    try {
      const res = await fetch(`${api}/api/v1/agents/${editingTags.id}/tags`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify({ groups, tags }),
      });
      if (!res.ok) { showMsg('err', (await res.json())?.error || `Failed (${res.status})`); return; }
      setEditingTags(null);
      fetchAgents();
      showMsg('ok', 'Tags updated.');
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  const deleteAgent = async (id: string, hostname: string) => {
    if (!confirm(`Remove agent "${hostname}"? It will need to re-enroll.`)) return;
    setSaving(true);
    try {
      const res = await fetch(`${api}/api/v1/agents/${id}`, { method: 'DELETE', headers: getAuthHeaders() });
      if (!res.ok) { showMsg('err', (await res.json())?.error || `Failed (${res.status})`); return; }
      fetchAgents();
      fetchStats();
      showMsg('ok', `Agent "${hostname}" removed.`);
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  const filtered = statusFilter
    ? agents.filter((a) => a.status === statusFilter)
    : agents;

  const sorted = [...filtered].sort((a, b) =>
    STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status)
  );

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Agents</span>
        <span className="card-subtitle" style={{ marginLeft: 12 }}>
          {agents.length} enrolled
        </span>
      </div>

      <div className="table-wrap">
        {loading ? (
          <div style={{ padding: 24, color: 'var(--text-muted)' }}>Loading...</div>
        ) : (
          <div style={{ padding: 16 }}>
            <Msg msg={message} />

            {/* Stats row */}
            {stats && (
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 20 }}>
                {([
                  { key: 'online',   label: 'Online',   color: STATUS_COLOR.online },
                  { key: 'pending',  label: 'Pending',  color: STATUS_COLOR.pending },
                  { key: 'offline',  label: 'Offline',  color: STATUS_COLOR.offline },
                  { key: 'isolated', label: 'Isolated', color: STATUS_COLOR.isolated },
                  { key: 'rejected', label: 'Rejected', color: STATUS_COLOR.rejected },
                ] as const).map(({ key, label, color }) => (
                  <button key={key} type="button"
                    onClick={() => setStatusFilter(statusFilter === key ? '' : key)}
                    style={{ padding: '8px 16px', borderRadius: 8, border: `1px solid ${color}44`,
                      background: statusFilter === key ? color + '22' : 'var(--bg-secondary)',
                      cursor: 'pointer', color: 'inherit', textAlign: 'center' }}>
                    <div style={{ fontSize: 22, fontWeight: 700, color }}>{stats[key]}</div>
                    <div style={{ fontSize: 11, color }}>{label}</div>
                  </button>
                ))}
              </div>
            )}

            {/* Pending approval banner */}
            {agents.filter((a) => a.status === 'pending').length > 0 && (
              <div style={{ padding: '10px 14px', borderRadius: 8, marginBottom: 16, fontSize: 13,
                background: 'var(--yellow)22', color: 'var(--yellow)',
                border: '1px solid var(--yellow)44' }}>
                {agents.filter((a) => a.status === 'pending').length} agent(s) waiting for approval.
                Review and approve below.
              </div>
            )}

            {/* Tags edit inline */}
            {editingTags && (
              <div style={{ padding: 16, border: '1px solid var(--blue, #3b82f6)', borderRadius: 8,
                background: 'var(--bg-secondary)', marginBottom: 16 }}>
                <div style={{ fontWeight: 600, marginBottom: 10, fontSize: 14 }}>
                  Tags: {editingTags.hostname}
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                  <div>
                    <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                      Groups (comma-separated)
                    </label>
                    <input value={tagsForm.groups}
                      onChange={(e) => setTagsForm((f) => ({ ...f, groups: e.target.value }))}
                      placeholder="servers, linux, prod" style={{ ...inputStyle, width: 200 }} />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                      Tags (comma-separated)
                    </label>
                    <input value={tagsForm.tags}
                      onChange={(e) => setTagsForm((f) => ({ ...f, tags: e.target.value }))}
                      placeholder="critical, pci-scope" style={{ ...inputStyle, width: 200 }} />
                  </div>
                  <button type="button" onClick={saveTags} disabled={saving}>Save</button>
                  <button type="button" onClick={() => setEditingTags(null)}
                    style={{ background: 'none', border: '1px solid var(--border)' }}>Cancel</button>
                </div>
              </div>
            )}

            {sorted.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', padding: '20px 0' }}>
                {statusFilter
                  ? `No ${statusFilter} agents.`
                  : 'No agents enrolled yet. Run the OWO agent on an endpoint to see it here.'}
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Hostname</th>
                    <th>OS</th>
                    <th>IP</th>
                    <th>Version</th>
                    <th>Status</th>
                    <th>Groups / Tags</th>
                    <th>Last Seen</th>
                    <th>Enrolled</th>
                    {canWrite && <th style={{ width: 180 }}>Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((agent) => (
                    <tr key={agent.id}>
                      <td>
                        <div style={{ fontWeight: 600, fontSize: 13 }}>{agent.hostname}</div>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                          {agent.id}
                        </div>
                      </td>
                      <td style={{ fontSize: 12 }}>
                        {agent.os || '—'}
                        {agent.os_version && <span style={{ color: 'var(--text-muted)' }}> {agent.os_version}</span>}
                      </td>
                      <td style={{ fontSize: 12, fontFamily: 'monospace' }}>{agent.ip_address || '—'}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{agent.agent_version || '—'}</td>
                      <td>
                        <Badge text={agent.status} color={STATUS_COLOR[agent.status]} />
                      </td>
                      <td style={{ fontSize: 11 }}>
                        {(agent.groups || []).map((g) => <Badge key={g} text={g} color="var(--blue, #3b82f6)" />)}
                        {(agent.tags || []).map((t) => <Badge key={t} text={t} />)}
                        {!agent.groups?.length && !agent.tags?.length && (
                          <span style={{ color: 'var(--text-muted)' }}>—</span>
                        )}
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleString() : 'Never'}
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {new Date(agent.enrolled_at).toLocaleDateString()}
                      </td>
                      {canWrite && (
                        <td>
                          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                            {agent.status === 'pending' && (
                              <>
                                <button type="button"
                                  onClick={() => setStatus(agent.id, 'approved')}
                                  disabled={saving}
                                  style={{ fontSize: 11, padding: '3px 8px', background: 'var(--green)22',
                                    border: '1px solid var(--green)44', borderRadius: 4, color: 'var(--green)', cursor: 'pointer' }}>
                                  Approve
                                </button>
                                <button type="button"
                                  onClick={() => setStatus(agent.id, 'rejected')}
                                  disabled={saving}
                                  style={{ fontSize: 11, padding: '3px 8px', background: 'var(--red)22',
                                    border: '1px solid var(--red)44', borderRadius: 4, color: 'var(--red)', cursor: 'pointer' }}>
                                  Reject
                                </button>
                              </>
                            )}
                            {agent.status === 'online' && (
                              <button type="button"
                                onClick={() => setStatus(agent.id, 'isolated')}
                                disabled={saving}
                                style={{ fontSize: 11, padding: '3px 8px', background: 'var(--orange, #f97316)22',
                                  border: '1px solid var(--orange, #f97316)44', borderRadius: 4,
                                  color: 'var(--orange, #f97316)', cursor: 'pointer' }}>
                                Isolate
                              </button>
                            )}
                            {agent.status === 'isolated' && (
                              <button type="button"
                                onClick={() => setStatus(agent.id, 'approved')}
                                disabled={saving}
                                style={{ fontSize: 11, padding: '3px 8px', background: 'var(--green)22',
                                  border: '1px solid var(--green)44', borderRadius: 4, color: 'var(--green)', cursor: 'pointer' }}>
                                Release
                              </button>
                            )}
                            <button type="button"
                              onClick={() => {
                                setEditingTags(agent);
                                setTagsForm({
                                  groups: (agent.groups || []).join(', '),
                                  tags: (agent.tags || []).join(', '),
                                });
                              }}
                              style={{ fontSize: 11, padding: '3px 8px', background: 'none',
                                border: '1px solid var(--border)', borderRadius: 4, cursor: 'pointer',
                                color: 'inherit' }}>
                              Tags
                            </button>
                            {isAdmin && (
                              <button type="button"
                                onClick={() => deleteAgent(agent.id, agent.hostname)}
                                disabled={saving}
                                style={{ background: 'none', border: 'none', color: 'var(--red)',
                                  cursor: 'pointer', fontSize: 16, lineHeight: 1 }}>
                                ×
                              </button>
                            )}
                          </div>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {/* Enrollment instructions */}
            <details style={{ marginTop: 24 }}>
              <summary style={{ cursor: 'pointer', fontSize: 13, color: 'var(--text-muted)', userSelect: 'none' }}>
                Agent enrollment instructions
              </summary>
              <div style={{ padding: '12px 0', fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.7 }}>
                <p>Run the OWO agent on the endpoint. It will POST to:</p>
                <pre style={{ background: 'var(--bg-secondary)', padding: 10, borderRadius: 6, overflowX: 'auto' }}>
{`POST /api/v1/agents/enroll
{
  "hostname": "<hostname>",
  "ip_address": "<ip>",
  "os": "linux",
  "os_version": "Ubuntu 22.04",
  "agent_version": "1.0.0",
  "tenant_id": "default"
}`}
                </pre>
                <p>The server returns the agent ID and a one-time <code>enroll_token</code>.</p>
                <p>The agent uses this token as a Bearer token for heartbeat:</p>
                <pre style={{ background: 'var(--bg-secondary)', padding: 10, borderRadius: 6, overflowX: 'auto' }}>
{`POST /api/v1/agents/<id>/heartbeat
Authorization: Bearer <enroll_token>
{ "ip_address": "<ip>", "agent_version": "1.0.0" }`}
                </pre>
                <p>New agents start in <strong>pending</strong> status. An admin must approve them before they are active.</p>
              </div>
            </details>
          </div>
        )}
      </div>
    </div>
  );
}
