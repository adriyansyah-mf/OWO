'use client';

import { useEffect, useState } from 'react';
import { getAuthHeaders, getApiBase } from '@/contexts/AuthContext';

type Policy = {
  enabled: boolean;
  mode: string;
  allowed_extensions: string[];
  blocked_extensions: string[];
  removable_paths: string[];
};

export default function DeviceControlPage() {
  const [policy, setPolicy] = useState<Policy>({
    enabled: false,
    mode: 'allow',
    allowed_extensions: [],
    blocked_extensions: [],
    removable_paths: [],
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const api = getApiBase() || 'http://localhost:8080';

  const fetchPolicy = () => {
    const headers = getAuthHeaders();
    fetch(`${api}/api/v1/policies/device-control`, { headers })
      .then((r) => r.json())
      .then((d) => setPolicy({
        enabled: !!d.enabled,
        mode: d.mode || 'allow',
        allowed_extensions: Array.isArray(d.allowed_extensions) ? d.allowed_extensions : [],
        blocked_extensions: Array.isArray(d.blocked_extensions) ? d.blocked_extensions : [],
        removable_paths: Array.isArray(d.removable_paths) ? d.removable_paths : ['/media', '/run/media', '/mnt'],
      }))
      .catch(() => setMessage({ type: 'err', text: 'Failed to load policy' }))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchPolicy();
  }, [api]);

  const savePolicy = () => {
    setSaving(true);
    setMessage(null);
    const headers = getAuthHeaders();
    headers['Content-Type'] = 'application/json';
    fetch(`${api}/api/v1/policies/device-control`, {
      method: 'PUT',
      headers,
      body: JSON.stringify(policy),
    })
      .then((r) => {
        if (!r.ok) throw new Error('Save failed');
        return r.json();
      })
      .then((d) => {
        setPolicy(d);
        setMessage({ type: 'ok', text: 'Policy saved. Agents will receive the update via NATS.' });
      })
      .catch(() => setMessage({ type: 'err', text: 'Failed to save policy' }))
      .finally(() => setSaving(false));
  };

  const updateList = (key: 'allowed_extensions' | 'blocked_extensions' | 'removable_paths', value: string[]) => {
    setPolicy((p) => ({ ...p, [key]: value }));
  };

  const addToList = (key: 'allowed_extensions' | 'blocked_extensions' | 'removable_paths', val: string) => {
    const v = val.trim();
    if (!v) return;
    const item = key === 'removable_paths' ? v : (v.startsWith('.') ? v : '.' + v);
    setPolicy((p) => {
      const arr = [...(p[key] || [])];
      if (!arr.includes(item)) arr.push(item);
      return { ...p, [key]: arr };
    });
  };

  const removeFromList = (key: 'allowed_extensions' | 'blocked_extensions' | 'removable_paths', idx: number) => {
    setPolicy((p) => {
      const arr = [...(p[key] || [])];
      arr.splice(idx, 1);
      return { ...p, [key]: arr };
    });
  };

  if (loading) {
    return (
      <div className="card">
        <div style={{ padding: 24, color: 'var(--text-muted)' }}>Loading...</div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Device Control (USB / Removable Media)</span>
        <span className="card-subtitle" style={{ marginLeft: 8 }}>
          CrowdStrike-style: control which file extensions can be copied to USB, etc.
        </span>
      </div>

      <div style={{ padding: 24 }}>
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

        <div style={{ marginBottom: 20 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={policy.enabled}
              onChange={(e) => setPolicy((p) => ({ ...p, enabled: e.target.checked }))}
            />
            <span>Enable Device Control</span>
          </label>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
            Requires write_events: true in agent config. Monitors writes to removable paths.
          </div>
        </div>

        <div style={{ marginBottom: 20 }}>
          <label style={{ display: 'block', marginBottom: 8 }}>Mode</label>
          <select
            value={policy.mode}
            onChange={(e) => setPolicy((p) => ({ ...p, mode: e.target.value }))}
            style={{ padding: 8, borderRadius: 6, minWidth: 160 }}
          >
            <option value="allow">Allow list (only listed extensions allowed)</option>
            <option value="block">Block list (listed extensions blocked)</option>
          </select>
        </div>

        <div style={{ marginBottom: 20 }}>
          <label style={{ display: 'block', marginBottom: 8 }}>
            {policy.mode === 'allow' ? 'Allowed extensions' : 'Blocked extensions'}
          </label>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            <input
              type="text"
              placeholder="e.g. .pdf or pdf"
              style={{ flex: 1, padding: 8, borderRadius: 6 }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  addToList(policy.mode === 'allow' ? 'allowed_extensions' : 'blocked_extensions', (e.target as HTMLInputElement).value);
                  (e.target as HTMLInputElement).value = '';
                }
              }}
            />
            <button
              type="button"
              onClick={(e) => {
                const inp = (e.target as HTMLElement).previousElementSibling as HTMLInputElement;
                if (inp) {
                  addToList(policy.mode === 'allow' ? 'allowed_extensions' : 'blocked_extensions', inp.value);
                  inp.value = '';
                }
              }}
            >
              Add
            </button>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {(policy.mode === 'allow' ? policy.allowed_extensions : policy.blocked_extensions).map((ext, i) => (
              <span
                key={i}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 4,
                  padding: '4px 8px',
                  background: 'var(--bg-secondary)',
                  borderRadius: 6,
                  fontSize: 12,
                }}
              >
                {ext}
                <button
                  type="button"
                  onClick={() => removeFromList(policy.mode === 'allow' ? 'allowed_extensions' : 'blocked_extensions', i)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 14 }}
                >
                  ×
                </button>
              </span>
            ))}
          </div>
        </div>

        <div style={{ marginBottom: 20 }}>
          <label style={{ display: 'block', marginBottom: 8 }}>Removable paths (USB mount points)</label>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            <input
              type="text"
              placeholder="e.g. /media"
              style={{ flex: 1, padding: 8, borderRadius: 6 }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  addToList('removable_paths', (e.target as HTMLInputElement).value);
                  (e.target as HTMLInputElement).value = '';
                }
              }}
            />
            <button
              type="button"
              onClick={(e) => {
                const inp = (e.target as HTMLElement).previousElementSibling as HTMLInputElement;
                if (inp) {
                  addToList('removable_paths', inp.value);
                  inp.value = '';
                }
              }}
            >
              Add
            </button>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {policy.removable_paths.map((p, i) => (
              <span
                key={i}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 4,
                  padding: '4px 8px',
                  background: 'var(--bg-secondary)',
                  borderRadius: 6,
                  fontSize: 12,
                }}
              >
                {p}
                <button
                  type="button"
                  onClick={() => removeFromList('removable_paths', i)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 14 }}
                >
                  ×
                </button>
              </span>
            ))}
          </div>
        </div>

        <button onClick={savePolicy} disabled={saving} style={{ padding: '10px 20px', borderRadius: 8 }}>
          {saving ? 'Saving...' : 'Save Policy'}
        </button>
      </div>
    </div>
  );
}
