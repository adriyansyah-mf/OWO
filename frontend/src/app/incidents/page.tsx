'use client';

import { useCallback, useEffect, useState } from 'react';
import { getAuthHeaders, getApiBase, useAuth } from '@/contexts/AuthContext';

type IncidentStatus = 'open' | 'investigating' | 'resolved';

type Incident = {
  id: string;
  title: string;
  tenant_id: string;
  host_id: string;
  severity: string;
  status: IncidentStatus;
  alert_count: number;
  alert_ids?: string[];
  rule_ids?: string[];
  mitre_tags?: string[];
  attack_chain?: string;
  notes?: string;
  assigned_to?: string;
  created_at: string;
  updated_at: string;
  first_alert_at: string;
  last_alert_at: string;
  resolved_at?: string;
  mttr?: string;
};

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)',
  high: 'var(--orange, #f97316)',
  medium: 'var(--yellow)',
  low: 'var(--text-muted)',
};

const STATUS_COLOR: Record<IncidentStatus, string> = {
  open: 'var(--red)',
  investigating: 'var(--yellow)',
  resolved: 'var(--green)',
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

export default function IncidentsPage() {
  const api = getApiBase() || 'http://localhost:8080';
  const { canWrite, isAdmin } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [filterStatus, setFilterStatus] = useState<IncidentStatus | ''>('');
  const [filterHost, setFilterHost] = useState('');
  const [editingID, setEditingID] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const showMsg = (type: 'ok' | 'err', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  };

  const fetchIncidents = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams();
    if (filterStatus) params.set('status', filterStatus);
    if (filterHost) params.set('host_id', filterHost);
    fetch(`${api}/api/v1/incidents?${params}&limit=200`, { headers: getAuthHeaders() })
      .then((r) => r.json())
      .then((d) => setIncidents(Array.isArray(d) ? d.sort((a: Incident, b: Incident) =>
        new Date(b.last_alert_at).getTime() - new Date(a.last_alert_at).getTime()) : []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [api, filterStatus, filterHost]);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);

  const updateIncident = async (id: string, updates: { status?: string; notes?: string; assigned_to?: string }) => {
    setSaving(true);
    try {
      const res = await fetch(`${api}/api/v1/incidents/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(updates),
      });
      if (!res.ok) { showMsg('err', (await res.json())?.error || `Failed (${res.status})`); return; }
      fetchIncidents();
      setEditingID(null);
      showMsg('ok', 'Incident updated.');
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  const deleteIncident = async (id: string) => {
    if (!confirm('Delete this incident? This cannot be undone.')) return;
    try {
      const res = await fetch(`${api}/api/v1/incidents/${id}`, { method: 'DELETE', headers: getAuthHeaders() });
      if (!res.ok) { showMsg('err', (await res.json())?.error || 'Failed'); return; }
      fetchIncidents();
      showMsg('ok', 'Incident deleted.');
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
  };

  const openCount = incidents.filter((i) => i.status === 'open').length;
  const investigatingCount = incidents.filter((i) => i.status === 'investigating').length;
  const criticalCount = incidents.filter((i) => i.severity === 'critical' && i.status !== 'resolved').length;

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Incidents</span>
        <div style={{ display: 'flex', gap: 8, marginLeft: 16 }}>
          {openCount > 0 && (
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--red)',
              background: 'var(--red-dim)', padding: '3px 8px', borderRadius: 12 }}>
              {openCount} open
            </span>
          )}
          {investigatingCount > 0 && (
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--yellow)',
              background: 'rgba(234,179,8,0.15)', padding: '3px 8px', borderRadius: 12 }}>
              {investigatingCount} investigating
            </span>
          )}
          {criticalCount > 0 && (
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--red)',
              background: 'var(--red-dim)', padding: '3px 8px', borderRadius: 12 }}>
              {criticalCount} critical
            </span>
          )}
        </div>
      </div>

      <div className="table-wrap">
        <div style={{ padding: 16 }}>
          <Msg msg={message} />

          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 12 }}>
            <div className="filter-tabs">
              {(['', 'open', 'investigating', 'resolved'] as (IncidentStatus | '')[]).map((s) => (
                <div key={s || 'all'} className={`tab ${filterStatus === s ? 'active' : ''}`}
                  onClick={() => setFilterStatus(s)}>
                  {s === '' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
                </div>
              ))}
            </div>
            <input placeholder="Filter by host..." value={filterHost}
              onChange={(e) => setFilterHost(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchIncidents()}
              style={{ ...inputStyle, width: 160 }} />
            <button type="button" onClick={fetchIncidents}>Refresh</button>
          </div>

          {loading ? (
            <div style={{ color: 'var(--text-muted)', padding: 16 }}>Loading...</div>
          ) : incidents.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', padding: 16 }}>No incidents found.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {incidents.map((inc) => (
                <IncidentCard
                  key={inc.id}
                  incident={inc}
                  isEditing={editingID === inc.id}
                  canWrite={canWrite}
                  isAdmin={isAdmin}
                  saving={saving}
                  onEdit={() => setEditingID(editingID === inc.id ? null : inc.id)}
                  onUpdate={updateIncident}
                  onDelete={deleteIncident}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function IncidentCard({
  incident: inc,
  isEditing,
  canWrite,
  isAdmin,
  saving,
  onEdit,
  onUpdate,
  onDelete,
}: {
  incident: Incident;
  isEditing: boolean;
  canWrite: boolean;
  isAdmin: boolean;
  saving: boolean;
  onEdit: () => void;
  onUpdate: (id: string, updates: { status?: string; notes?: string; assigned_to?: string }) => void;
  onDelete: (id: string) => void;
}) {
  const [form, setForm] = useState({
    status: inc.status,
    notes: inc.notes || '',
    assigned_to: inc.assigned_to || '',
  });

  const inputStyle: React.CSSProperties = {
    padding: '6px 9px', borderRadius: 6, border: '1px solid var(--border)',
    background: 'var(--bg-secondary)', color: 'inherit', fontSize: 12,
  };

  return (
    <div style={{ borderRadius: 10, border: `1px solid ${inc.status === 'resolved' ? 'var(--border)' : SEV_COLOR[inc.severity] || 'var(--border)'}`,
      background: 'var(--bg-secondary)', overflow: 'hidden' }}>
      <div style={{ padding: '12px 16px', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
        {/* Severity indicator */}
        <div style={{ width: 4, alignSelf: 'stretch', borderRadius: 2, flexShrink: 0,
          background: inc.status === 'resolved' ? 'var(--border)' : SEV_COLOR[inc.severity] || 'var(--border)' }} />

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
            <span style={{ fontWeight: 600, fontSize: 14 }}>{inc.title}</span>
            {inc.attack_chain && (
              <span style={{ fontSize: 11, fontWeight: 700, background: 'var(--red)', color: '#fff',
                padding: '2px 8px', borderRadius: 4 }}>
                {inc.attack_chain}
              </span>
            )}
          </div>

          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>
            <span>Host: <span style={{ color: 'inherit', fontFamily: 'monospace' }}>{inc.host_id || '—'}</span></span>
            <span>Alerts: <strong style={{ color: 'inherit' }}>{inc.alert_count}</strong></span>
            <span>Last alert: {new Date(inc.last_alert_at).toLocaleString()}</span>
            {inc.mttr && <span style={{ color: 'var(--green)' }}>MTTR: {inc.mttr}</span>}
            {inc.assigned_to && <span>Assigned: <strong style={{ color: 'inherit' }}>{inc.assigned_to}</strong></span>}
          </div>

          {/* MITRE tags */}
          {inc.mitre_tags && inc.mitre_tags.length > 0 && (
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 6 }}>
              {inc.mitre_tags.map((t) => (
                <span key={t} style={{ fontSize: 10, fontFamily: 'monospace', background: 'rgba(59,130,246,0.15)',
                  color: 'var(--blue, #3b82f6)', border: '1px solid rgba(59,130,246,0.3)',
                  borderRadius: 3, padding: '1px 6px' }}>{t}</span>
              ))}
            </div>
          )}

          {inc.notes && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic', marginTop: 4 }}>
              {inc.notes}
            </div>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 6, flexShrink: 0 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: SEV_COLOR[inc.severity] || 'inherit',
              textTransform: 'uppercase' }}>{inc.severity}</span>
            <span style={{ fontSize: 11, fontWeight: 700, color: STATUS_COLOR[inc.status],
              textTransform: 'capitalize' }}>{inc.status}</span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {new Date(inc.created_at).toLocaleString()}
          </div>
          <div style={{ display: 'flex', gap: 4 }}>
            {canWrite && (
              <button type="button" onClick={onEdit} style={{ fontSize: 12, padding: '3px 10px' }}>
                {isEditing ? 'Close' : 'Edit'}
              </button>
            )}
            {isAdmin && (
              <button type="button" onClick={() => onDelete(inc.id)}
                style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 16, lineHeight: 1, padding: '3px 4px' }}>
                ×
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Quick status actions */}
      {!isEditing && canWrite && inc.status !== 'resolved' && (
        <div style={{ borderTop: '1px solid var(--border)', padding: '8px 16px', display: 'flex', gap: 6 }}>
          {inc.status === 'open' && (
            <button type="button" style={{ fontSize: 11, padding: '3px 10px', background: 'rgba(234,179,8,0.15)',
              border: '1px solid var(--yellow)', color: 'var(--yellow)' }}
              onClick={() => onUpdate(inc.id, { status: 'investigating' })}>
              Investigate
            </button>
          )}
          {(inc.status === 'open' || inc.status === 'investigating') && (
            <button type="button" style={{ fontSize: 11, padding: '3px 10px', background: 'var(--green-dim)',
              border: '1px solid var(--green)', color: 'var(--green)' }}
              onClick={() => onUpdate(inc.id, { status: 'resolved' })}>
              Resolve
            </button>
          )}
        </div>
      )}

      {/* Edit form */}
      {isEditing && (
        <div style={{ borderTop: '1px solid var(--border)', padding: '12px 16px',
          background: 'var(--bg-primary, var(--bg))' }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Status</label>
              <select value={form.status} onChange={(e) => setForm((f) => ({ ...f, status: e.target.value as IncidentStatus }))}
                style={inputStyle}>
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
              </select>
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Assigned To</label>
              <input value={form.assigned_to} onChange={(e) => setForm((f) => ({ ...f, assigned_to: e.target.value }))}
                placeholder="analyst username" style={{ ...inputStyle, width: 140 }} />
            </div>
            <div style={{ flex: 1, minWidth: 200 }}>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Notes</label>
              <input value={form.notes} onChange={(e) => setForm((f) => ({ ...f, notes: e.target.value }))}
                placeholder="Investigation notes..." style={{ ...inputStyle, width: '100%' }} />
            </div>
            <button type="button" onClick={() => onUpdate(inc.id, form)} disabled={saving}>
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
