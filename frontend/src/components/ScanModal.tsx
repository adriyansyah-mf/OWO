'use client';

import { useEffect, useState } from 'react';
import { getAuthHeaders, getApiBase } from '@/contexts/AuthContext';

type ScanType = 'scan' | 'deep_scan' | 'av_scan' | 'dlp_scan';

export default function ScanModal({
  open,
  scanType,
  onClose,
}: {
  open: boolean;
  scanType: ScanType;
  onClose: () => void;
}) {
  const [hosts, setHosts] = useState<any[]>([]);
  const [selectedHost, setSelectedHost] = useState<string>('');
  const [avPaths, setAvPaths] = useState<string[]>(['/tmp', '/var/tmp', '/home']);
  const [dlpPaths, setDlpPaths] = useState<string[]>(['/tmp', '/var/tmp', '/home']);
  const [newPath, setNewPath] = useState('');
  const [newDlpPath, setNewDlpPath] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const api = getApiBase() || 'http://localhost:8080';

  useEffect(() => {
    if (open) {
      setError(null);
      setSuccess(false);
      setSelectedHost('');
      fetch(`${api}/api/v1/hosts`, { headers: getAuthHeaders() })
        .then((r) => r.json())
        .then((h) => setHosts(Array.isArray(h) ? h : []))
        .catch(() => setHosts([]));
      if (scanType === 'av_scan') {
        fetch(`${api}/api/v1/settings/clamav-paths`, { headers: getAuthHeaders() })
          .then((r) => r.json())
          .then((p) => setAvPaths(Array.isArray(p) ? p : ['/tmp', '/var/tmp', '/home']))
          .catch(() => {});
      }
      if (scanType === 'dlp_scan') {
        fetch(`${api}/api/v1/settings/dlp-paths`, { headers: getAuthHeaders() })
          .then((r) => r.json())
          .then((p) => setDlpPaths(Array.isArray(p) ? p : ['/tmp', '/var/tmp', '/home']))
          .catch(() => {});
      }
    }
  }, [open, api, scanType]);

  const saveAvPaths = async () => {
    const res = await fetch(`${api}/api/v1/settings/clamav-paths`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify(avPaths),
    });
    return res.ok;
  };

  const addPath = () => {
    const p = newPath.trim();
    if (p && p.startsWith('/') && !avPaths.includes(p)) {
      setAvPaths([...avPaths, p]);
      setNewPath('');
    }
  };

  const removePath = (i: number) => {
    setAvPaths(avPaths.filter((_, j) => j !== i));
  };

  const addDlpPath = () => {
    const p = newDlpPath.trim();
    if (p && p.startsWith('/') && !dlpPaths.includes(p)) {
      setDlpPaths([...dlpPaths, p]);
      setNewDlpPath('');
    }
  };

  const removeDlpPath = (i: number) => {
    setDlpPaths(dlpPaths.filter((_, j) => j !== i));
  };

  const saveDlpPaths = async () => {
    const res = await fetch(`${api}/api/v1/settings/dlp-paths`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify(dlpPaths),
    });
    return res.ok;
  };

  const runScan = async () => {
    if (!selectedHost) {
      setError('Pilih endpoint terlebih dahulu');
      return;
    }
    setLoading(true);
    setError(null);
    if (scanType === 'av_scan') {
      void saveAvPaths(); // background, jangan block
    }
    if (scanType === 'dlp_scan') {
      void saveDlpPaths();
    }
    const paths: Record<ScanType, string> = {
      scan: '/api/v1/ir/scan',
      deep_scan: '/api/v1/ir/deep-scan',
      av_scan: '/api/v1/ir/av-scan',
      dlp_scan: '/api/v1/ir/dlp-scan',
    };
    const path = paths[scanType];
    const body: Record<string, unknown> = { host_id: selectedHost };
    if (scanType === 'av_scan' && avPaths.length > 0) {
      body.paths = avPaths;
    }
    if (scanType === 'dlp_scan' && dlpPaths.length > 0) {
      body.paths = dlpPaths;
    }
    const res = await fetch(`${api}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify(body),
    });
    setLoading(false);
    if (res.ok) {
      setSuccess(true);
      setTimeout(() => onClose(), 1200);
    } else {
      const data = await res.json().catch(() => ({}));
      setError(data.error || data.message || 'Gagal menjalankan scan');
    }
  };

  if (!open) return null;

  const labels: Record<ScanType, string> = {
    scan: 'New Scan',
    deep_scan: 'Deep Scan',
    av_scan: 'AV Scan',
    dlp_scan: 'DLP Scan',
  };
  const descs: Record<ScanType, string> = {
    scan: 'Process snapshot langsung',
    deep_scan: 'Process snapshot + triage (/tmp, /var/log, /etc)',
    av_scan: 'ClamAV scan. Atur path di bawah. Auto-install jika belum ada.',
    dlp_scan: 'Data Loss Prevention: scan konten sensitif (CC, SSN, API key, dll).',
  };
  const label = labels[scanType];
  const desc = descs[scanType];

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{label}</h3>
          <button className="modal-close" onClick={onClose} aria-label="Tutup">
            ×
          </button>
        </div>
        <div className="modal-body">
          <p style={{ color: 'var(--text-muted)', fontSize: 13, marginBottom: 16 }}>{desc}</p>
          <label style={{ display: 'block', marginBottom: 8, fontSize: 13 }}>Endpoint</label>
          {scanType === 'av_scan' && (
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 13 }}>Path yang di-scan</label>
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                <input
                  type="text"
                  value={newPath}
                  onChange={(e) => setNewPath(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addPath())}
                  placeholder="/tmp atau path lain"
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    borderRadius: 8,
                    border: '1px solid var(--border)',
                    background: 'var(--bg-secondary)',
                    color: 'var(--text)',
                    fontSize: 13,
                  }}
                />
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={addPath}
                  style={{ padding: '8px 12px' }}
                >
                  Tambah
                </button>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 4 }}>
                {avPaths.map((p, i) => (
                  <span
                    key={i}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                      padding: '4px 10px',
                      background: 'var(--bg-hover)',
                      borderRadius: 6,
                      fontSize: 12,
                    }}
                  >
                    <code>{p}</code>
                    <button
                      type="button"
                      onClick={() => removePath(i)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-muted)',
                        cursor: 'pointer',
                        padding: 0,
                        fontSize: 14,
                        lineHeight: 1,
                      }}
                      aria-label="Hapus"
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
              <button
                type="button"
                className="btn-secondary"
                onClick={saveAvPaths}
                style={{ marginTop: 8, fontSize: 12, padding: '6px 12px' }}
              >
                Simpan path
              </button>
            </div>
          )}
          {scanType === 'dlp_scan' && (
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 13 }}>Path yang di-scan</label>
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                <input
                  type="text"
                  value={newDlpPath}
                  onChange={(e) => setNewDlpPath(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addDlpPath())}
                  placeholder="/tmp atau path lain"
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    borderRadius: 8,
                    border: '1px solid var(--border)',
                    background: 'var(--bg-secondary)',
                    color: 'var(--text)',
                    fontSize: 13,
                  }}
                />
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={addDlpPath}
                  style={{ padding: '8px 12px' }}
                >
                  Tambah
                </button>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 4 }}>
                {dlpPaths.map((p, i) => (
                  <span
                    key={i}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                      padding: '4px 10px',
                      background: 'var(--bg-hover)',
                      borderRadius: 6,
                      fontSize: 12,
                    }}
                  >
                    <code>{p}</code>
                    <button
                      type="button"
                      onClick={() => removeDlpPath(i)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-muted)',
                        cursor: 'pointer',
                        padding: 0,
                        fontSize: 14,
                        lineHeight: 1,
                      }}
                      aria-label="Hapus"
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
              <button
                type="button"
                className="btn-secondary"
                onClick={saveDlpPaths}
                style={{ marginTop: 8, fontSize: 12, padding: '6px 12px' }}
              >
                Simpan path
              </button>
            </div>
          )}
          <label style={{ display: 'block', marginBottom: 8, fontSize: 13 }}>Endpoint</label>
          <select
            value={selectedHost}
            onChange={(e) => setSelectedHost(e.target.value)}
            style={{
              width: '100%',
              padding: '10px 12px',
              borderRadius: 8,
              border: '1px solid var(--border)',
              background: 'var(--bg-secondary)',
              color: 'var(--text)',
              fontSize: 14,
            }}
          >
            <option value="">— Pilih host —</option>
            {hosts.map((h: any) => (
              <option key={h.id} value={h.id}>
                {h.hostname || h.id}
              </option>
            ))}
          </select>
          {error && (
            <p style={{ color: 'var(--red)', fontSize: 12, marginTop: 8 }}>{error}</p>
          )}
          {success && (
            <p style={{ color: 'var(--green)', fontSize: 12, marginTop: 8 }}>
              {scanType === 'av_scan'
                ? 'AV Scan dikirim. Cek halaman AV Scan Results.'
                : scanType === 'dlp_scan'
                  ? 'DLP Scan dikirim. Cek halaman DLP.'
                  : 'Scan dikirim ke agent. Cek Process Tree / Alerts.'}
            </p>
          )}
        </div>
        <div className="modal-footer">
          <button className="btn-secondary" onClick={onClose}>
            Batal
          </button>
          <button
            className="btn-primary"
            onClick={runScan}
            disabled={loading || !selectedHost}
          >
            {loading ? 'Mengirim...' : `Jalankan ${label}`}
          </button>
        </div>
      </div>
    </div>
  );
}
