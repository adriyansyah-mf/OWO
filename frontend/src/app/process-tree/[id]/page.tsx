'use client';

import { useParams } from 'next/navigation';
import { useEffect, useState, useMemo } from 'react';
import Link from 'next/link';
import { getAuthHeaders, getApiBase } from '@/contexts/AuthContext';

async function killProcess(api: string, hostId: string, pid: number) {
  const res = await fetch(`${api}/api/v1/ir/kill`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({ host_id: hostId, pid }),
  });
  return res.ok;
}

// Hexagon points (flat-top): r=radius, cx,cy=center
function hexPoints(cx: number, cy: number, r: number): string {
  const pts: [number, number][] = [];
  for (let i = 0; i < 6; i++) {
    const a = (Math.PI / 3) * i;
    pts.push([cx + r * Math.cos(a), cy + r * Math.sin(a)]);
  }
  return pts.map(([x, y]) => `${x},${y}`).join(' ');
}

export default function ProcessTreePage() {
  const params = useParams();
  const hostId = params.id as string;
  const [tree, setTree] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [killing, setKilling] = useState<number | null>(null);
  const [view, setView] = useState<'grid' | 'hex'>('grid');
  const api = getApiBase() || 'http://localhost:8080';

  useEffect(() => {
    const headers = getAuthHeaders();
    fetch(`${getApiBase() || 'http://localhost:8080'}/api/v1/hosts/${hostId}/process-tree`, { headers })
      .then(r => r.ok ? r.json() : null)
      .then(data => data && Array.isArray(data) ? setTree(data) : setTree([]))
      .catch(() => setTree([]))
      .finally(() => setLoading(false));
  }, [hostId]);

  const getName = (p: any) => p.name || (p.exe ? p.exe.split('/').pop() : '') || `PID ${p.pid}`;

  // Hex layout: level-order tree placement, hexagons per process
  const hexLayout = useMemo(() => {
    if (tree.length === 0) return [];
    const byPpid = new Map<number | null, any[]>();
    tree.forEach((p: any) => {
      const pp = p.ppid === 0 ? null : p.ppid;
      if (!byPpid.has(pp)) byPpid.set(pp, []);
      byPpid.get(pp)!.push(p);
    });
    const R = 48;
    const rowH = R * 2.1;
    const positions: { p: any; x: number; y: number }[] = [];
    type Slot = { pid: number | null; x: number; w: number };
    let slots: Slot[] = [{ pid: null, x: 0, w: 700 }];
    let y = R + 20;

    while (slots.length > 0) {
      const nextSlots: Slot[] = [];
      for (const { pid, x, w } of slots) {
        const children = byPpid.get(pid) || [];
        const step = w / Math.max(children.length, 1);
        children.forEach((p: any, i: number) => {
          const px = x + step * (i + 0.5);
          positions.push({ p, x: px, y });
          nextSlots.push({ pid: p.pid, x: px - step * 0.4, w: step * 0.8 });
        });
      }
      y += rowH;
      slots = nextSlots;
    }
    return positions;
  }, [tree]);

  const svgW = 800;
  const svgH = Math.max(400, hexLayout.length ? hexLayout[hexLayout.length - 1]?.y + 90 : 400);

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Process Tree — {hostId}</span>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <div className="filter-tabs" style={{ margin: 0 }}>
            <div className={`tab ${view === 'grid' ? 'active' : ''}`} onClick={() => setView('grid')}>Grid</div>
            <div className={`tab ${view === 'hex' ? 'active' : ''}`} onClick={() => setView('hex')}>Hex</div>
          </div>
          <button
            className="status-pill info"
            style={{ fontSize: 11, border: 'none', cursor: 'pointer', padding: '4px 10px' }}
            onClick={async () => {
              await fetch(`${api}/api/v1/ir/collect`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                body: JSON.stringify({ host_id: hostId, paths: ['/tmp', '/var/log'], artifact_name: 'triage' }),
              });
            }}
          >
            Collect Triage
          </button>
          <Link href="/hosts" className="status-pill info" style={{ fontSize: 11, textDecoration: 'none' }}>
            ← Back to Endpoints
          </Link>
        </div>
      </div>
      <div style={{ padding: 20 }}>
        {loading ? (
          <p style={{ color: 'var(--text-muted)' }}>Loading...</p>
        ) : tree.length === 0 ? (
          <p style={{ color: 'var(--text-muted)' }}>No process data. Agent may not have reported execve events yet.</p>
        ) : view === 'hex' ? (
          <div style={{ overflow: 'auto', maxHeight: 500 }}>
            <svg width={svgW} height={svgH} style={{ display: 'block' }}>
              {hexLayout.map(({ p, x, y }, i) => {
                const r = 42;
                const isHigh = p.risk === 'high' || (p.mitre?.length || p.gtfobins?.length);
                return (
                  <g key={`${p.pid}-${p.start_ts}`} transform={`translate(${x}, ${y})`}>
                    <polygon
                      points={hexPoints(0, 0, r)}
                      fill={isHigh ? 'var(--red-dim)' : 'var(--bg-secondary)'}
                      stroke={isHigh ? 'var(--red)' : 'var(--border)'}
                      strokeWidth={2}
                    />
                    <text x={0} y={-8} textAnchor="middle" fill="var(--text-primary)" fontSize={11} fontFamily="JetBrains Mono, monospace">
                      {getName(p).slice(0, 12)}
                    </text>
                    <text x={0} y={8} textAnchor="middle" fill="var(--text-muted)" fontSize={10}>
                      PID {p.pid}
                    </text>
                    <g
                      cursor={killing ? 'wait' : 'pointer'}
                      onClick={async (e) => {
                        e.stopPropagation();
                        if (killing) return;
                        setKilling(p.pid);
                        await killProcess(api, hostId, p.pid);
                        setTree(prev => prev.filter(n => n.pid !== p.pid));
                        setKilling(null);
                      }}
                    >
                      <rect x={-28} y={18} width={56} height={18} rx={4} fill="var(--red-dim)" stroke="var(--red)" strokeWidth={1} />
                      <text x={0} y={30} textAnchor="middle" fill="var(--red)" fontSize={9} fontWeight={600}>Kill</text>
                    </g>
                  </g>
                );
              })}
            </svg>
          </div>
        ) : (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
            {tree.map((p: any) => (
              <div
                key={`${p.pid}-${p.start_ts}`}
                style={{
                  width: 160,
                  padding: 14,
                  borderRadius: 8,
                  border: '2px solid',
                  borderColor: p.risk === 'high' ? 'var(--red)' : 'var(--border)',
                  background: p.risk === 'high' ? 'var(--red-dim)' : 'var(--bg-secondary)',
                  textAlign: 'center',
                }}
              >
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }} title={p.exe}>
                  {getName(p)}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>PID: {p.pid}</div>
                {(p.mitre?.length || p.gtfobins?.length) ? (
                  <div style={{ fontSize: 10, color: 'var(--yellow)', marginTop: 4 }}>
                    {[...(p.mitre || []), ...(p.gtfobins || [])].join(', ')}
                  </div>
                ) : null}
                <button
                  className="status-pill critical"
                  style={{ fontSize: 10, padding: '2px 8px', border: 'none', cursor: 'pointer', marginTop: 8 }}
                  disabled={killing !== null}
                  onClick={async () => {
                    setKilling(p.pid);
                    await killProcess(api, hostId, p.pid);
                    setTree(prev => prev.filter(n => n.pid !== p.pid));
                    setKilling(null);
                  }}
                >
                  Kill
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
