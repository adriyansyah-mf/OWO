'use client';

import { useCallback, useEffect, useState } from 'react';
import { getAuthHeaders, getApiBase, useAuth } from '@/contexts/AuthContext';

type ConditionField = 'severity' | 'rule_id' | 'host_id' | 'mitre_tag' | 'attack_chain' | 'source_ip' | 'tenant_id';
type ConditionOp = 'eq' | 'contains' | 'startswith' | 'in';
type ActionType = 'isolate_host' | 'notify' | 'tag_ioc' | 'create_ticket';

type Condition = {
  field: ConditionField;
  op: ConditionOp;
  value: string;
};

type Action = {
  type: ActionType;
  params?: Record<string, string>;
};

type Playbook = {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  conditions: Condition[];
  condition_mode: 'all' | 'any';
  actions: Action[];
  created_at: string;
  updated_at: string;
  fire_count: number;
  last_fired_at?: string;
};

type FiredEvent = {
  playbook_id: string;
  playbook_name: string;
  alert_id?: string;
  host_id?: string;
  tenant_id?: string;
  actions_run: string[];
  fired_at: string;
};

type TabId = 'playbooks' | 'history';

const FIELD_OPTIONS: { value: ConditionField; label: string }[] = [
  { value: 'severity', label: 'Severity' },
  { value: 'rule_id', label: 'Rule ID' },
  { value: 'host_id', label: 'Host ID' },
  { value: 'mitre_tag', label: 'MITRE Tag' },
  { value: 'attack_chain', label: 'Attack Chain' },
  { value: 'source_ip', label: 'Source IP' },
  { value: 'tenant_id', label: 'Tenant ID' },
];

const OP_OPTIONS: { value: ConditionOp; label: string }[] = [
  { value: 'eq', label: 'equals' },
  { value: 'contains', label: 'contains' },
  { value: 'startswith', label: 'starts with' },
  { value: 'in', label: 'in (comma-sep)' },
];

const ACTION_OPTIONS: { value: ActionType; label: string; desc: string }[] = [
  { value: 'isolate_host', label: 'Isolate Host', desc: 'Send isolate command via NATS' },
  { value: 'notify', label: 'Send Notification', desc: 'Fire webhook channels' },
  { value: 'tag_ioc', label: 'Tag IOC', desc: 'Add source IP to IOC store' },
  { value: 'create_ticket', label: 'Create Ticket', desc: 'Placeholder for ticketing' },
];

const inputStyle: React.CSSProperties = {
  padding: '7px 10px', borderRadius: 6, border: '1px solid var(--border)',
  background: 'var(--bg-secondary)', color: 'inherit', fontSize: 13,
};

const Msg = ({ msg }: { msg: { type: 'ok' | 'err'; text: string } | null }) =>
  msg ? (
    <div style={{ padding: '10px 14px', borderRadius: 8, marginBottom: 14, fontSize: 13,
      background: msg.type === 'ok' ? 'var(--green-dim)' : 'var(--red-dim)',
      color: msg.type === 'ok' ? 'var(--green)' : 'var(--red)' }}>
      {msg.text}
    </div>
  ) : null;

const emptyPlaybook = (): Partial<Playbook> => ({
  name: '', description: '', enabled: true, condition_mode: 'all',
  conditions: [{ field: 'severity', op: 'eq', value: 'critical' }],
  actions: [{ type: 'notify', params: { message: 'Alert: {{severity}} — {{title}} on {{host_id}}' } }],
});

export default function PlaybooksPage() {
  const api = getApiBase() || 'http://localhost:8080';
  const { canWrite } = useAuth();
  const [tab, setTab] = useState<TabId>('playbooks');
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [history, setHistory] = useState<FiredEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [editingPB, setEditingPB] = useState<Partial<Playbook> | null>(null);
  const [saving, setSaving] = useState(false);

  const showMsg = (type: 'ok' | 'err', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  };

  const fetchPlaybooks = useCallback(() => {
    setLoading(true);
    fetch(`${api}/api/v1/playbooks`, { headers: getAuthHeaders() })
      .then((r) => r.json())
      .then((d) => setPlaybooks(Array.isArray(d) ? d.sort((a: Playbook, b: Playbook) => a.name.localeCompare(b.name)) : []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [api]);

  const fetchHistory = useCallback(() => {
    fetch(`${api}/api/v1/playbooks/history?limit=100`, { headers: getAuthHeaders() })
      .then((r) => r.json())
      .then((d) => setHistory(Array.isArray(d) ? d : []))
      .catch(() => {});
  }, [api]);

  useEffect(() => {
    if (tab === 'playbooks') fetchPlaybooks();
    if (tab === 'history') fetchHistory();
  }, [tab, fetchPlaybooks, fetchHistory]);

  const toggleEnabled = async (pb: Playbook) => {
    try {
      const res = await fetch(`${api}/api/v1/playbooks/${pb.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify({ enabled: !pb.enabled }),
      });
      if (!res.ok) { showMsg('err', 'Failed to update'); return; }
      fetchPlaybooks();
    } catch {}
  };

  const savePlaybook = async () => {
    if (!editingPB?.name) return;
    setSaving(true);
    try {
      const isNew = !editingPB.id;
      const res = await fetch(`${api}/api/v1/playbooks${isNew ? '' : '/' + editingPB.id}`, {
        method: isNew ? 'POST' : 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(editingPB),
      });
      if (!res.ok) { showMsg('err', (await res.json())?.error || 'Failed'); return; }
      fetchPlaybooks();
      setEditingPB(null);
      showMsg('ok', isNew ? 'Playbook created.' : 'Playbook updated.');
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  const deletePlaybook = async (id: string, name: string) => {
    if (!confirm(`Delete playbook "${name}"?`)) return;
    try {
      const res = await fetch(`${api}/api/v1/playbooks/${id}`, { method: 'DELETE', headers: getAuthHeaders() });
      if (!res.ok) { showMsg('err', 'Failed'); return; }
      fetchPlaybooks();
      showMsg('ok', 'Playbook deleted.');
    } catch {}
  };

  const enabledCount = playbooks.filter((p) => p.enabled).length;

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Playbooks</span>
        {enabledCount > 0 && (
          <span style={{ marginLeft: 12, fontSize: 11, fontWeight: 700, color: 'var(--green)',
            background: 'var(--green-dim)', padding: '3px 8px', borderRadius: 12 }}>
            {enabledCount} active
          </span>
        )}
        <div className="filter-tabs" style={{ marginLeft: 16 }}>
          {(['playbooks', 'history'] as TabId[]).map((t) => (
            <div key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}
              style={{ textTransform: 'capitalize' }}>
              {t === 'history' ? 'Execution History' : 'Playbooks'}
            </div>
          ))}
        </div>
      </div>

      <div className="table-wrap">
        <div style={{ padding: 16 }}>
          <Msg msg={message} />

          {/* ── Playbooks list ── */}
          {tab === 'playbooks' && (
            <>
              {canWrite && (
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
                  <button type="button" onClick={() => setEditingPB(emptyPlaybook())}>
                    + New Playbook
                  </button>
                </div>
              )}

              {editingPB && (
                <PlaybookEditor
                  playbook={editingPB}
                  onChange={setEditingPB}
                  onSave={savePlaybook}
                  onCancel={() => setEditingPB(null)}
                  saving={saving}
                />
              )}

              {loading ? (
                <div style={{ color: 'var(--text-muted)', padding: 16 }}>Loading...</div>
              ) : playbooks.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', padding: 16 }}>No playbooks configured.</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {playbooks.map((pb) => (
                    <div key={pb.id} style={{ padding: '12px 16px', borderRadius: 8,
                      border: `1px solid ${pb.enabled ? 'var(--green)' : 'var(--border)'}`,
                      background: 'var(--bg-secondary)', display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                          <span style={{ fontWeight: 600, fontSize: 14 }}>{pb.name}</span>
                          <span style={{ fontSize: 11, padding: '1px 6px', borderRadius: 4, fontWeight: 600,
                            background: pb.enabled ? 'var(--green-dim)' : 'var(--bg-primary, var(--bg))',
                            color: pb.enabled ? 'var(--green)' : 'var(--text-muted)',
                            border: `1px solid ${pb.enabled ? 'var(--green)' : 'var(--border)'}` }}>
                            {pb.enabled ? 'ENABLED' : 'DISABLED'}
                          </span>
                        </div>
                        {pb.description && (
                          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>{pb.description}</div>
                        )}
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 4 }}>
                          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                            {pb.condition_mode === 'any' ? 'ANY of:' : 'ALL of:'}
                          </span>
                          {pb.conditions?.map((c, i) => (
                            <span key={i} style={{ fontSize: 11, fontFamily: 'monospace',
                              background: 'var(--bg-primary, var(--bg))', border: '1px solid var(--border)',
                              borderRadius: 3, padding: '1px 6px' }}>
                              {c.field} {c.op} "{c.value}"
                            </span>
                          ))}
                        </div>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Actions:</span>
                          {pb.actions?.map((a, i) => (
                            <span key={i} style={{ fontSize: 11, background: 'rgba(59,130,246,0.1)',
                              border: '1px solid rgba(59,130,246,0.3)', color: 'var(--blue, #3b82f6)',
                              borderRadius: 3, padding: '1px 6px' }}>
                              {a.type}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 6, flexShrink: 0 }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          Fired: <strong style={{ color: 'inherit' }}>{pb.fire_count}</strong>
                          {pb.last_fired_at && ` · last ${new Date(pb.last_fired_at).toLocaleString()}`}
                        </div>
                        {canWrite && (
                          <div style={{ display: 'flex', gap: 4 }}>
                            <button type="button" onClick={() => toggleEnabled(pb)} style={{ fontSize: 11, padding: '3px 8px' }}>
                              {pb.enabled ? 'Disable' : 'Enable'}
                            </button>
                            <button type="button" onClick={() => setEditingPB({ ...pb })} style={{ fontSize: 11, padding: '3px 8px' }}>
                              Edit
                            </button>
                            <button type="button" onClick={() => deletePlaybook(pb.id, pb.name)}
                              style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 16, padding: '2px 4px' }}>
                              ×
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}

          {/* ── Execution History ── */}
          {tab === 'history' && (
            <>
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
                <button type="button" onClick={fetchHistory}>Refresh</button>
              </div>
              {history.length === 0 ? (
                <div style={{ color: 'var(--text-muted)' }}>No playbook executions recorded yet.</div>
              ) : (
                <table>
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Playbook</th>
                      <th>Host</th>
                      <th>Alert ID</th>
                      <th>Actions Run</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((ev, i) => (
                      <tr key={i}>
                        <td style={{ fontSize: 11, whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                          {new Date(ev.fired_at).toLocaleString()}
                        </td>
                        <td style={{ fontWeight: 600, fontSize: 13 }}>{ev.playbook_name}</td>
                        <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{ev.host_id || '—'}</td>
                        <td style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-muted)' }}>
                          {ev.alert_id ? ev.alert_id.slice(-8) : '—'}
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                            {ev.actions_run?.map((a, j) => (
                              <span key={j} style={{ fontSize: 11,
                                background: a.includes('err') ? 'var(--red-dim)' : 'var(--green-dim)',
                                color: a.includes('err') ? 'var(--red)' : 'var(--green)',
                                border: `1px solid ${a.includes('err') ? 'var(--red)' : 'var(--green)'}`,
                                borderRadius: 3, padding: '1px 6px', fontFamily: 'monospace' }}>
                                {a}
                              </span>
                            ))}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── PlaybookEditor ───────────────────────────────────────────────────────────

function PlaybookEditor({
  playbook: pb,
  onChange,
  onSave,
  onCancel,
  saving,
}: {
  playbook: Partial<Playbook>;
  onChange: (pb: Partial<Playbook>) => void;
  onSave: () => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const inputStyle: React.CSSProperties = {
    padding: '6px 9px', borderRadius: 6, border: '1px solid var(--border)',
    background: 'var(--bg-primary, var(--bg))', color: 'inherit', fontSize: 13,
  };

  const addCondition = () =>
    onChange({ ...pb, conditions: [...(pb.conditions || []), { field: 'severity', op: 'eq', value: 'critical' }] });

  const updateCondition = (i: number, partial: Partial<Condition>) => {
    const conds = [...(pb.conditions || [])];
    conds[i] = { ...conds[i], ...partial };
    onChange({ ...pb, conditions: conds });
  };

  const removeCondition = (i: number) =>
    onChange({ ...pb, conditions: (pb.conditions || []).filter((_, idx) => idx !== i) });

  const addAction = () =>
    onChange({ ...pb, actions: [...(pb.actions || []), { type: 'notify', params: {} }] });

  const updateAction = (i: number, partial: Partial<Action>) => {
    const acts = [...(pb.actions || [])];
    acts[i] = { ...acts[i], ...partial };
    onChange({ ...pb, actions: acts });
  };

  const removeAction = (i: number) =>
    onChange({ ...pb, actions: (pb.actions || []).filter((_, idx) => idx !== i) });

  return (
    <div style={{ padding: 16, border: '1px solid var(--blue, #3b82f6)', borderRadius: 8,
      background: 'var(--bg-secondary)', marginBottom: 16 }}>
      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14 }}>
        {pb.id ? `Edit: ${pb.name}` : 'New Playbook'}
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
        <div style={{ flex: 2, minWidth: 200 }}>
          <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Name *</label>
          <input value={pb.name || ''} onChange={(e) => onChange({ ...pb, name: e.target.value })}
            placeholder="e.g. Auto-Isolate on Critical" style={{ ...inputStyle, width: '100%' }} />
        </div>
        <div style={{ flex: 3, minWidth: 200 }}>
          <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Description</label>
          <input value={pb.description || ''} onChange={(e) => onChange({ ...pb, description: e.target.value })}
            placeholder="What does this playbook do?" style={{ ...inputStyle, width: '100%' }} />
        </div>
        <div>
          <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Mode</label>
          <select value={pb.condition_mode || 'all'} onChange={(e) => onChange({ ...pb, condition_mode: e.target.value as 'all' | 'any' })}
            style={inputStyle}>
            <option value="all">ALL conditions (AND)</option>
            <option value="any">ANY condition (OR)</option>
          </select>
        </div>
        <label style={{ display: 'flex', alignItems: 'flex-end', gap: 6, fontSize: 13, cursor: 'pointer', paddingBottom: 4 }}>
          <input type="checkbox" checked={pb.enabled ?? true} onChange={(e) => onChange({ ...pb, enabled: e.target.checked })} />
          Enabled
        </label>
      </div>

      {/* Conditions */}
      <div style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6, color: 'var(--text-muted)' }}>CONDITIONS</div>
        {(pb.conditions || []).map((cond, i) => (
          <div key={i} style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 6 }}>
            <select value={cond.field} onChange={(e) => updateCondition(i, { field: e.target.value as ConditionField })}
              style={{ ...inputStyle, width: 130 }}>
              {FIELD_OPTIONS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
            </select>
            <select value={cond.op} onChange={(e) => updateCondition(i, { op: e.target.value as ConditionOp })}
              style={{ ...inputStyle, width: 120 }}>
              {OP_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
            <input value={cond.value} onChange={(e) => updateCondition(i, { value: e.target.value })}
              placeholder="value" style={{ ...inputStyle, flex: 1, minWidth: 100 }} />
            <button type="button" onClick={() => removeCondition(i)}
              style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 18, padding: '0 4px' }}>
              ×
            </button>
          </div>
        ))}
        <button type="button" onClick={addCondition} style={{ fontSize: 11, padding: '3px 10px' }}>+ Add Condition</button>
      </div>

      {/* Actions */}
      <div style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6, color: 'var(--text-muted)' }}>ACTIONS</div>
        {(pb.actions || []).map((act, i) => (
          <div key={i} style={{ marginBottom: 8, padding: 10, background: 'var(--bg-secondary)',
            border: '1px solid var(--border)', borderRadius: 6 }}>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: act.type !== 'isolate_host' ? 8 : 0 }}>
              <select value={act.type} onChange={(e) => updateAction(i, { type: e.target.value as ActionType, params: {} })}
                style={{ ...inputStyle, width: 160 }}>
                {ACTION_OPTIONS.map((a) => <option key={a.value} value={a.value}>{a.label}</option>)}
              </select>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', flex: 1 }}>
                {ACTION_OPTIONS.find((a) => a.value === act.type)?.desc}
              </span>
              <button type="button" onClick={() => removeAction(i)}
                style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 18, padding: '0 4px' }}>
                ×
              </button>
            </div>
            {act.type === 'notify' && (
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                <div style={{ flex: 2, minWidth: 200 }}>
                  <label style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>
                    Message template (use {'{{host_id}}'}, {'{{severity}}'}, {'{{title}}'}, etc.)
                  </label>
                  <input value={act.params?.message || ''}
                    onChange={(e) => updateAction(i, { params: { ...act.params, message: e.target.value } })}
                    placeholder="Alert: {{severity}} — {{title}} on {{host_id}}"
                    style={{ ...inputStyle, width: '100%' }} />
                </div>
                <div>
                  <label style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>
                    Channels (empty = all enabled)
                  </label>
                  <input value={act.params?.channels || ''}
                    onChange={(e) => updateAction(i, { params: { ...act.params, channels: e.target.value } })}
                    placeholder="slack-ops, teams-soc" style={{ ...inputStyle, width: 160 }} />
                </div>
              </div>
            )}
            {act.type === 'tag_ioc' && (
              <div style={{ display: 'flex', gap: 6 }}>
                <div>
                  <label style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>IOC field</label>
                  <select value={act.params?.ioc_field || 'source_ip'}
                    onChange={(e) => updateAction(i, { params: { ...act.params, ioc_field: e.target.value } })}
                    style={inputStyle}>
                    <option value="source_ip">source_ip</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>Severity</label>
                  <select value={act.params?.severity || 'high'}
                    onChange={(e) => updateAction(i, { params: { ...act.params, severity: e.target.value } })}
                    style={inputStyle}>
                    <option value="critical">critical</option>
                    <option value="high">high</option>
                    <option value="medium">medium</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block', marginBottom: 2 }}>Source label</label>
                  <input value={act.params?.source || 'auto-playbook'}
                    onChange={(e) => updateAction(i, { params: { ...act.params, source: e.target.value } })}
                    style={{ ...inputStyle, width: 120 }} />
                </div>
              </div>
            )}
          </div>
        ))}
        <button type="button" onClick={addAction} style={{ fontSize: 11, padding: '3px 10px' }}>+ Add Action</button>
      </div>

      <div style={{ display: 'flex', gap: 8 }}>
        <button type="button" onClick={onSave} disabled={saving || !pb.name}>
          {saving ? 'Saving...' : pb.id ? 'Update Playbook' : 'Create Playbook'}
        </button>
        <button type="button" onClick={onCancel}
          style={{ background: 'none', border: '1px solid var(--border)' }}>Cancel</button>
      </div>
    </div>
  );
}
