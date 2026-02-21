'use client';

import { useEffect, useState } from 'react';
import { getAuthHeaders, getApiBase } from '@/contexts/AuthContext';

type RuleMeta = {
  id: string;
  title: string;
  level: string;
  status: string;
  file: string;
};

function severityPill(level: string) {
  const c = level === 'critical' || level === 'high' ? 'critical' : level === 'medium' ? 'warning' : 'info';
  return <span className={`status-pill ${c}`}>● {level || 'medium'}</span>;
}

export default function RulesPage() {
  const [rules, setRules] = useState<RuleMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [yamlInput, setYamlInput] = useState('');
  const [showUpload, setShowUpload] = useState(false);
  const [error, setError] = useState('');
  const api = getApiBase() || 'http://localhost:8080';

  const fetchRules = () => {
    const headers = getAuthHeaders();
    fetch(`${api}/api/v1/rules`, { headers })
      .then(r => r.json())
      .then((data: RuleMeta[]) => setRules(Array.isArray(data) ? data : []))
      .catch(() => setRules([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleUpload = async () => {
    if (!yamlInput.trim()) {
      setError('YAML content required');
      return;
    }
    setUploading(true);
    setError('');
    try {
      const res = await fetch(`${api}/api/v1/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify({ yaml: yamlInput.trim() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError((data as any)?.error || res.statusText);
        return;
      }
      setYamlInput('');
      setShowUpload(false);
      fetchRules();
    } catch (e) {
      setError(String(e));
    } finally {
      setUploading(false);
    }
  };

  const handleDelete = async (id: string) => {
    setDeleting(id);
    try {
      const res = await fetch(`${api}/api/v1/rules/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      if (res.ok) fetchRules();
    } finally {
      setDeleting(null);
    }
  };

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Sigma Rules</span>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button
            className="btn-primary"
            style={{ fontSize: 12, padding: '6px 12px' }}
            onClick={() => setShowUpload(!showUpload)}
          >
            + Deploy Rule
          </button>
          <span className="card-subtitle" style={{ marginLeft: 4 }}>{rules.length} rules</span>
        </div>
      </div>

      {showUpload && (
        <div style={{ padding: 16, borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)' }}>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8, color: 'var(--text-primary)' }}>Upload Sigma YAML</div>
          <textarea
            value={yamlInput}
            onChange={(e) => setYamlInput(e.target.value)}
            placeholder="Paste Sigma rule YAML (title, id, detection, condition, level required)..."
            style={{
              width: '100%',
              minHeight: 180,
              padding: 12,
              background: 'var(--bg-primary)',
              border: '1px solid var(--border)',
              borderRadius: 8,
              fontSize: 12,
              fontFamily: "'JetBrains Mono', monospace",
              color: 'var(--text-primary)',
              resize: 'vertical',
            }}
          />
          {error && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 6 }}>{error}</div>}
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <button
              className="btn-primary"
              style={{ fontSize: 12, padding: '6px 14px' }}
              onClick={handleUpload}
              disabled={uploading}
            >
              {uploading ? 'Deploying...' : 'Deploy'}
            </button>
            <button
              style={{ fontSize: 12, padding: '6px 14px', background: 'var(--bg-hover)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-secondary)', cursor: 'pointer' }}
              onClick={() => { setShowUpload(false); setYamlInput(''); setError(''); }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Title</th>
              <th>Level</th>
              <th>Status</th>
              <th>File</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} style={{ padding: 24, color: 'var(--text-muted)' }}>Loading...</td></tr>
            ) : rules.length === 0 ? (
              <tr><td colSpan={6} style={{ padding: 24, color: 'var(--text-muted)' }}>No rules. Deploy a Sigma rule above.</td></tr>
            ) : (
              rules.map((r) => (
                <tr key={r.id}>
                  <td className="mono" style={{ fontSize: 12 }}>{r.id}</td>
                  <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{r.title}</td>
                  <td>{severityPill(r.level)}</td>
                  <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{r.status || '—'}</td>
                  <td className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{r.file}</td>
                  <td>
                    <button
                      className="status-pill critical"
                      style={{ fontSize: 10, padding: '2px 8px', border: 'none', cursor: deleting ? 'wait' : 'pointer' }}
                      disabled={!!deleting}
                      onClick={() => handleDelete(r.id)}
                    >
                      {deleting === r.id ? '...' : 'Delete'}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      <div style={{ padding: 12, fontSize: 11, color: 'var(--text-muted)', borderTop: '1px solid var(--border)' }}>
        Rules are loaded from <code style={{ background: 'var(--bg-secondary)', padding: '1px 4px', borderRadius: 4 }}>sigma/rules/</code>. New rules take effect immediately via detection reload.
      </div>
    </div>
  );
}
