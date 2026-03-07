'use client';

import { useCallback, useEffect, useState } from 'react';
import { getAuthHeaders, getApiBase, useAuth, type UserRole } from '@/contexts/AuthContext';

type User = {
  id: string;
  username: string;
  role: UserRole;
  email?: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  last_login_at?: string;
};

type AuditEvent = {
  timestamp: string;
  action: string;
  username: string;
  role: string;
  remote_addr: string;
  detail: string;
};

type NotifyChannel = {
  id: string;
  name: string;
  type: 'generic' | 'slack' | 'teams';
  url: string;
  enabled: boolean;
  default_template?: string;
  send_count: number;
  last_sent_at?: string;
  last_error?: string;
  created_at: string;
};

type TabId = 'users' | 'audit' | 'notifications';

const ROLE_LABELS: Record<UserRole, { label: string; color: string; desc: string }> = {
  admin:    { label: 'Admin',     color: 'var(--red)',              desc: 'Full access including user management' },
  analyst:  { label: 'Analyst',   color: 'var(--blue, #3b82f6)',   desc: 'Read all + IR actions + rule/DLP management' },
  readonly: { label: 'Read Only', color: 'var(--text-muted)',       desc: 'Read alerts, hosts, scan results only' },
  auditor:  { label: 'Auditor',   color: 'var(--yellow)',           desc: 'Read all including audit logs and user list' },
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

export default function SettingsPage() {
  const api = getApiBase() || 'http://localhost:8080';
  const { isAdmin } = useAuth();
  const [tab, setTab] = useState<TabId>('users');
  const [users, setUsers] = useState<User[]>([]);
  const [auditLog, setAuditLog] = useState<AuditEvent[]>([]);
  const [channels, setChannels] = useState<NotifyChannel[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'analyst' as UserRole, email: '' });
  const [showNewForm, setShowNewForm] = useState(false);
  const [newChannel, setNewChannel] = useState({ name: '', type: 'generic' as NotifyChannel['type'], url: '', enabled: true, default_template: '' });
  const [showChannelForm, setShowChannelForm] = useState(false);
  const [testingChannel, setTestingChannel] = useState<string | null>(null);

  const showMsg = (type: 'ok' | 'err', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  };

  const fetchUsers = useCallback(() => {
    fetch(`${api}/api/v1/users`, { headers: getAuthHeaders() })
      .then((r) => r.json()).then((d) => setUsers(Array.isArray(d) ? d : [])).catch(() => {});
  }, [api]);

  const fetchAudit = useCallback(() => {
    fetch(`${api}/api/v1/admin/audit?limit=200`, { headers: getAuthHeaders() })
      .then((r) => r.json()).then((d) => setAuditLog(Array.isArray(d) ? d : [])).catch(() => {});
  }, [api]);

  const fetchChannels = useCallback(() => {
    fetch(`${api}/api/v1/notify/channels`, { headers: getAuthHeaders() })
      .then((r) => r.json()).then((d) => setChannels(Array.isArray(d) ? d : [])).catch(() => {});
  }, [api]);

  useEffect(() => {
    setLoading(true);
    Promise.all([fetchUsers()]).finally(() => setLoading(false));
  }, [fetchUsers]);

  useEffect(() => {
    if (tab === 'audit') fetchAudit();
    if (tab === 'notifications') fetchChannels();
  }, [tab, fetchAudit, fetchChannels]);

  if (!isAdmin) {
    return (
      <div className="card">
        <div className="card-header"><span className="card-title">Settings</span></div>
        <div style={{ padding: 32, color: 'var(--text-muted)' }}>Access denied. Admin role required.</div>
      </div>
    );
  }

  const createUser = async () => {
    if (!newUser.username || !newUser.password) return;
    setSaving(true);
    try {
      const res = await fetch(`${api}/api/v1/users`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(newUser),
      });
      if (!res.ok) { showMsg('err', (await res.json())?.error || `Failed (${res.status})`); return; }
      fetchUsers();
      setShowNewForm(false);
      setNewUser({ username: '', password: '', role: 'analyst', email: '' });
      showMsg('ok', `User "${newUser.username}" created.`);
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  const updateUser = async (id: string, updates: Partial<User> & { password?: string }) => {
    setSaving(true);
    try {
      const res = await fetch(`${api}/api/v1/users/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(updates),
      });
      if (!res.ok) { showMsg('err', (await res.json())?.error || `Failed (${res.status})`); return; }
      fetchUsers();
      setEditingUser(null);
      showMsg('ok', 'User updated.');
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  const createChannel = async () => {
    if (!newChannel.name || !newChannel.url) return;
    setSaving(true);
    try {
      const res = await fetch(`${api}/api/v1/notify/channels`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(newChannel),
      });
      if (!res.ok) { showMsg('err', (await res.json())?.error || `Failed (${res.status})`); return; }
      fetchChannels();
      setShowChannelForm(false);
      setNewChannel({ name: '', type: 'generic', url: '', enabled: true, default_template: '' });
      showMsg('ok', `Channel "${newChannel.name}" created.`);
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  const deleteChannel = async (id: string, name: string) => {
    if (!confirm(`Delete channel "${name}"?`)) return;
    try {
      const res = await fetch(`${api}/api/v1/notify/channels/${id}`, { method: 'DELETE', headers: getAuthHeaders() });
      if (!res.ok) { showMsg('err', 'Failed'); return; }
      fetchChannels();
      showMsg('ok', `Channel "${name}" deleted.`);
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
  };

  const testChannel = async (id: string) => {
    setTestingChannel(id);
    try {
      const res = await fetch(`${api}/api/v1/notify/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify({ channel_id: id }),
      });
      const d = await res.json();
      if (d.ok) { showMsg('ok', 'Test notification sent successfully.'); }
      else { showMsg('err', `Test failed: ${d.error || `HTTP ${d.status_code}`}`); }
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setTestingChannel(null); }
  };

  const deleteUser = async (id: string, username: string) => {
    if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
    setSaving(true);
    try {
      const res = await fetch(`${api}/api/v1/users/${id}`, { method: 'DELETE', headers: getAuthHeaders() });
      if (!res.ok) { showMsg('err', (await res.json())?.error || `Failed (${res.status})`); return; }
      fetchUsers();
      showMsg('ok', `User "${username}" deleted.`);
    } catch (e) { showMsg('err', e instanceof Error ? e.message : 'Failed'); }
    finally { setSaving(false); }
  };

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Settings</span>
        <div className="filter-tabs" style={{ marginLeft: 16 }}>
          {(['users', 'notifications', 'audit'] as TabId[]).map((t) => (
            <div key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}
              style={{ textTransform: 'capitalize' }}>
              {t === 'audit' ? 'Admin Audit Log' : t === 'notifications' ? 'Notifications' : 'User Management'}
            </div>
          ))}
        </div>
      </div>

      <div className="table-wrap">
        {loading ? (
          <div style={{ padding: 24, color: 'var(--text-muted)' }}>Loading...</div>
        ) : (
          <div style={{ padding: 16 }}>
            <Msg msg={message} />

            {/* ── User Management ── */}
            {tab === 'users' && (
              <>
                {/* Role reference */}
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 20 }}>
                  {(Object.entries(ROLE_LABELS) as [UserRole, typeof ROLE_LABELS[UserRole]][]).map(([role, info]) => (
                    <div key={role} style={{ padding: '8px 12px', borderRadius: 8, border: '1px solid var(--border)',
                      background: 'var(--bg-secondary)', minWidth: 160 }}>
                      <div style={{ fontWeight: 600, color: info.color, fontSize: 13, marginBottom: 2 }}>{info.label}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{info.desc}</div>
                    </div>
                  ))}
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
                  <button type="button" onClick={() => setShowNewForm((v) => !v)}>
                    {showNewForm ? 'Cancel' : '+ New User'}
                  </button>
                </div>

                {showNewForm && (
                  <div style={{ padding: 16, border: '1px solid var(--border)', borderRadius: 8,
                    background: 'var(--bg-secondary)', marginBottom: 16 }}>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                      <input placeholder="Username" value={newUser.username}
                        onChange={(e) => setNewUser((u) => ({ ...u, username: e.target.value }))}
                        style={{ ...inputStyle, width: 130 }} />
                      <input type="password" placeholder="Password" value={newUser.password}
                        onChange={(e) => setNewUser((u) => ({ ...u, password: e.target.value }))}
                        style={{ ...inputStyle, width: 130 }} />
                      <select value={newUser.role}
                        onChange={(e) => setNewUser((u) => ({ ...u, role: e.target.value as UserRole }))}
                        style={inputStyle}>
                        {Object.keys(ROLE_LABELS).map((r) => <option key={r} value={r}>{r}</option>)}
                      </select>
                      <input placeholder="Email (optional)" value={newUser.email}
                        onChange={(e) => setNewUser((u) => ({ ...u, email: e.target.value }))}
                        style={{ ...inputStyle, width: 180 }} />
                      <button type="button" onClick={createUser}
                        disabled={saving || !newUser.username || !newUser.password}>
                        {saving ? 'Creating...' : 'Create User'}
                      </button>
                    </div>
                  </div>
                )}

                {editingUser && (
                  <UserEditForm
                    user={editingUser}
                    onSave={(updates) => updateUser(editingUser.id, updates)}
                    onCancel={() => setEditingUser(null)}
                    saving={saving}
                  />
                )}

                <table>
                  <thead>
                    <tr>
                      <th>Username</th>
                      <th>Role</th>
                      <th>Email</th>
                      <th>Status</th>
                      <th>Last Login</th>
                      <th>Created</th>
                      <th style={{ width: 120 }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((u) => (
                      <tr key={u.id}>
                        <td style={{ fontWeight: 600 }}>{u.username}</td>
                        <td>
                          <span style={{ color: ROLE_LABELS[u.role]?.color, fontWeight: 600, fontSize: 12 }}>
                            {u.role}
                          </span>
                        </td>
                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{u.email || '—'}</td>
                        <td>
                          <span style={{ fontSize: 11, color: u.enabled ? 'var(--green)' : 'var(--red)',
                            fontWeight: 600 }}>
                            {u.enabled ? 'Active' : 'Disabled'}
                          </span>
                        </td>
                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Never'}
                        </td>
                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {new Date(u.created_at).toLocaleDateString()}
                        </td>
                        <td>
                          <button type="button" onClick={() => setEditingUser(u)} style={{ marginRight: 6 }}>
                            Edit
                          </button>
                          <button type="button" onClick={() => deleteUser(u.id, u.username)}
                            style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 16 }}>
                            ×
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}

            {/* ── Notifications ── */}
            {tab === 'notifications' && (
              <>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16 }}>
                  Configure webhook channels for playbook notifications. Supports Slack, Microsoft Teams, and generic JSON webhooks.
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
                  <button type="button" onClick={() => setShowChannelForm((v) => !v)}>
                    {showChannelForm ? 'Cancel' : '+ Add Channel'}
                  </button>
                </div>
                {showChannelForm && (
                  <div style={{ padding: 16, border: '1px solid var(--border)', borderRadius: 8,
                    background: 'var(--bg-secondary)', marginBottom: 16 }}>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                      <div>
                        <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Name *</label>
                        <input value={newChannel.name} onChange={(e) => setNewChannel((c) => ({ ...c, name: e.target.value }))}
                          placeholder="e.g. slack-soc" style={{ ...inputStyle, width: 130 }} />
                      </div>
                      <div>
                        <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Type</label>
                        <select value={newChannel.type} onChange={(e) => setNewChannel((c) => ({ ...c, type: e.target.value as NotifyChannel['type'] }))}
                          style={inputStyle}>
                          <option value="generic">Generic JSON</option>
                          <option value="slack">Slack</option>
                          <option value="teams">Microsoft Teams</option>
                        </select>
                      </div>
                      <div style={{ flex: 1, minWidth: 240 }}>
                        <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Webhook URL *</label>
                        <input type="password" value={newChannel.url} onChange={(e) => setNewChannel((c) => ({ ...c, url: e.target.value }))}
                          placeholder="https://hooks.slack.com/..." style={{ ...inputStyle, width: '100%' }} />
                      </div>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, cursor: 'pointer' }}>
                        <input type="checkbox" checked={newChannel.enabled}
                          onChange={(e) => setNewChannel((c) => ({ ...c, enabled: e.target.checked }))} />
                        Enabled
                      </label>
                      <button type="button" onClick={createChannel}
                        disabled={saving || !newChannel.name || !newChannel.url}>
                        {saving ? 'Creating...' : 'Create'}
                      </button>
                    </div>
                  </div>
                )}
                {channels.length === 0 ? (
                  <div style={{ color: 'var(--text-muted)' }}>No notification channels configured.</div>
                ) : (
                  <table>
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Sent</th>
                        <th>Last Sent</th>
                        <th>Last Error</th>
                        <th style={{ width: 120 }}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {channels.map((ch) => (
                        <tr key={ch.id}>
                          <td style={{ fontWeight: 600 }}>{ch.name}</td>
                          <td style={{ fontSize: 12 }}>
                            <span style={{ fontFamily: 'monospace', background: 'var(--bg-secondary)',
                              padding: '2px 6px', borderRadius: 4, border: '1px solid var(--border)' }}>
                              {ch.type}
                            </span>
                          </td>
                          <td>
                            <span style={{ fontSize: 11, fontWeight: 600, color: ch.enabled ? 'var(--green)' : 'var(--text-muted)' }}>
                              {ch.enabled ? 'Active' : 'Disabled'}
                            </span>
                          </td>
                          <td style={{ fontSize: 12 }}>{ch.send_count || 0}</td>
                          <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                            {ch.last_sent_at ? new Date(ch.last_sent_at).toLocaleString() : '—'}
                          </td>
                          <td style={{ fontSize: 11, color: 'var(--red)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {ch.last_error || '—'}
                          </td>
                          <td>
                            <button type="button" onClick={() => testChannel(ch.id)}
                              disabled={testingChannel === ch.id}
                              style={{ marginRight: 6, fontSize: 11 }}>
                              {testingChannel === ch.id ? 'Testing...' : 'Test'}
                            </button>
                            <button type="button" onClick={() => deleteChannel(ch.id, ch.name)}
                              style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 16 }}>
                              ×
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </>
            )}

            {/* ── Admin Audit Log ── */}
            {tab === 'audit' && (
              <>
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
                  <button type="button" onClick={fetchAudit}>Refresh</button>
                </div>
                {auditLog.length === 0 ? (
                  <div style={{ color: 'var(--text-muted)' }}>No admin audit events yet.</div>
                ) : (
                  <table>
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Action</th>
                        <th>User</th>
                        <th>Role</th>
                        <th>Detail</th>
                        <th>Remote</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditLog.map((ev, i) => (
                        <tr key={i}>
                          <td style={{ fontSize: 11, whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                            {new Date(ev.timestamp).toLocaleString()}
                          </td>
                          <td style={{ fontSize: 12, fontFamily: 'monospace', fontWeight: 600 }}>{ev.action}</td>
                          <td style={{ fontSize: 12 }}>{ev.username}</td>
                          <td>
                            <span style={{ fontSize: 11, color: ROLE_LABELS[ev.role as UserRole]?.color }}>
                              {ev.role}
                            </span>
                          </td>
                          <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{ev.detail || '—'}</td>
                          <td style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                            {ev.remote_addr}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function UserEditForm({
  user, onSave, onCancel, saving,
}: {
  user: User;
  onSave: (updates: Partial<User> & { password?: string }) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const [form, setForm] = useState({
    role: user.role,
    email: user.email || '',
    enabled: user.enabled,
    password: '',
  });
  const inputStyle: React.CSSProperties = {
    padding: '7px 10px', borderRadius: 6, border: '1px solid var(--border)',
    background: 'var(--bg-secondary)', color: 'inherit', fontSize: 13,
  };
  return (
    <div style={{ padding: 16, border: '1px solid var(--blue, #3b82f6)', borderRadius: 8,
      background: 'var(--bg-secondary)', marginBottom: 16 }}>
      <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 14 }}>Edit: {user.username}</div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <div>
          <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Role</label>
          <select value={form.role} onChange={(e) => setForm((f) => ({ ...f, role: e.target.value as UserRole }))}
            style={inputStyle}>
            {Object.keys(ROLE_LABELS).map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </div>
        <div>
          <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Email</label>
          <input value={form.email} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
            placeholder="email (optional)" style={{ ...inputStyle, width: 180 }} />
        </div>
        <div>
          <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>New Password</label>
          <input type="password" value={form.password}
            onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
            placeholder="leave empty to keep current" style={{ ...inputStyle, width: 180 }} />
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, cursor: 'pointer' }}>
          <input type="checkbox" checked={form.enabled}
            onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))} />
          Enabled
        </label>
        <button type="button" onClick={() => onSave(form)} disabled={saving}>
          {saving ? 'Saving...' : 'Save'}
        </button>
        <button type="button" onClick={onCancel}
          style={{ background: 'none', border: '1px solid var(--border)' }}>Cancel</button>
      </div>
    </div>
  );
}
