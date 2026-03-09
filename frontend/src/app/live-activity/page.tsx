'use client';

import { useEffect, useRef, useState } from 'react';
import { getAuthHeaders, getApiBase } from '@/contexts/AuthContext';

type EventType = 'all' | 'execve' | 'network' | 'file' | 'privilege' | 'process';

interface LiveEvent {
  agent_hostname?: string;
  agent_name?: string;
  tenant_id?: string;
  timestamp?: string;
  event?: {
    event_type?: string;
    pid?: number;
    ppid?: number;
    uid?: number;
    comm?: string;
    exe?: string;
    cmdline?: string;
    file_path?: string;
    remote_addr?: string;
    remote_port?: number;
    local_port?: number;
    protocol?: string;
    path?: string;
  };
}

const EVENT_TYPE_LABELS: Record<string, string> = {
  execve:    'EXEC',
  process:   'PROC',
  network:   'NET',
  file:      'FILE',
  privilege: 'PRIV',
  exit:      'EXIT',
  module:    'MOD',
  write:     'WRITE',
};

const EVENT_TYPE_COLORS: Record<string, string> = {
  execve:    'var(--accent)',
  process:   'var(--accent)',
  network:   '#3b82f6',
  file:      'var(--yellow)',
  privilege: 'var(--red)',
  exit:      'var(--text-muted)',
  module:    '#a855f7',
  write:     'var(--text-secondary)',
};

function eventSummary(ev: LiveEvent['event']): string {
  if (!ev) return '—';
  const type = ev.event_type || '';
  if (type === 'execve' || type === 'process') {
    return ev.cmdline || ev.exe || ev.comm || '—';
  }
  if (type === 'network') {
    const proto = ev.protocol ? `[${ev.protocol}] ` : '';
    if (ev.remote_addr) return `${proto}→ ${ev.remote_addr}:${ev.remote_port ?? '?'}`;
    return `${proto}local:${ev.local_port ?? '?'}`;
  }
  if (type === 'file') return ev.file_path || ev.path || '—';
  if (type === 'privilege') return `uid=${ev.uid} ${ev.comm || ''}`;
  if (type === 'write') return ev.path || ev.comm || '—';
  if (type === 'module') return ev.path || ev.comm || '—';
  return ev.cmdline || ev.path || ev.comm || '—';
}

function formatTs(ts?: string): string {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) +
      '.' + String(d.getMilliseconds()).padStart(3, '0');
  } catch { return ts; }
}

export default function LiveActivityPage() {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [filter, setFilter] = useState<EventType>('all');
  const [paused, setPaused] = useState(false);
  const [connected, setConnected] = useState(false);
  const pausedRef = useRef(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  const filtered = filter === 'all'
    ? events
    : events.filter(e => {
        const t = e.event?.event_type || '';
        if (filter === 'process') return t === 'execve' || t === 'process';
        return t === filter;
      });

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [events, autoScroll]);

  useEffect(() => {
    const api = getApiBase() || 'http://localhost:8080';
    const headers = getAuthHeaders();
    const token = (headers as Record<string, string>)['Authorization']?.replace('Bearer ', '');
    const url = `${api}/api/v1/live-activity${token ? `?token=${encodeURIComponent(token)}` : ''}`;

    const es = new EventSource(url);
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.onmessage = (e) => {
      if (pausedRef.current) return;
      try {
        const ev: LiveEvent = JSON.parse(e.data);
        setEvents(prev => {
          const next = [...prev, ev];
          return next.length > 1000 ? next.slice(-1000) : next;
        });
      } catch { /* ignore */ }
    };
    return () => es.close();
  }, []);

  const counts = {
    all: events.length,
    process: events.filter(e => { const t = e.event?.event_type || ''; return t === 'execve' || t === 'process'; }).length,
    network: events.filter(e => e.event?.event_type === 'network').length,
    file: events.filter(e => e.event?.event_type === 'file').length,
    privilege: events.filter(e => e.event?.event_type === 'privilege').length,
  };

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 48px)' }}>
      <div className="card-header" style={{ flexShrink: 0 }}>
        <span className="card-title">Live Activity</span>
        <span className={`status-pill ${connected ? 'safe' : ''}`} style={!connected ? { background: '#1e2535', color: 'var(--text-muted)' } : undefined}>
          ● {connected ? 'Streaming' : 'Disconnected'}
        </span>
        <div className="filter-tabs" style={{ marginLeft: 12 }}>
          {(['all', 'process', 'network', 'file', 'privilege'] as EventType[]).map(t => (
            <div
              key={t}
              className={`tab${filter === t ? ' active' : ''}`}
              onClick={() => setFilter(t)}
              style={{ textTransform: 'capitalize' }}
            >
              {t}{t !== 'all' && counts[t as keyof typeof counts] > 0 && (
                <span style={{ marginLeft: 4, fontSize: 10, opacity: 0.7 }}>({counts[t as keyof typeof counts]})</span>
              )}
            </div>
          ))}
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{filtered.length} events</span>
          <button
            className={`btn btn-secondary`}
            style={{ fontSize: 11, padding: '3px 10px' }}
            onClick={() => setAutoScroll(v => !v)}
          >
            {autoScroll ? 'Auto-scroll ON' : 'Auto-scroll OFF'}
          </button>
          <button
            className="btn btn-secondary"
            style={{ fontSize: 11, padding: '3px 10px' }}
            onClick={() => setPaused(v => !v)}
          >
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
          <button
            className="btn btn-secondary"
            style={{ fontSize: 11, padding: '3px 10px' }}
            onClick={() => setEvents([])}
          >
            Clear
          </button>
        </div>
      </div>

      <div style={{ flex: 1, overflow: 'auto', fontFamily: 'monospace', fontSize: 12 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead style={{ position: 'sticky', top: 0, background: 'var(--bg-secondary)', zIndex: 1 }}>
            <tr>
              <th style={{ padding: '6px 12px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 500, borderBottom: '1px solid var(--border)', width: 110 }}>Time</th>
              <th style={{ padding: '6px 12px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 500, borderBottom: '1px solid var(--border)', width: 60 }}>Type</th>
              <th style={{ padding: '6px 12px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 500, borderBottom: '1px solid var(--border)', width: 130 }}>Host</th>
              <th style={{ padding: '6px 12px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 500, borderBottom: '1px solid var(--border)', width: 60 }}>PID</th>
              <th style={{ padding: '6px 12px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 500, borderBottom: '1px solid var(--border)' }}>Details</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={5} style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
                  {connected ? 'Waiting for events...' : 'Not connected to event stream'}
                </td>
              </tr>
            ) : (
              filtered.map((ev, i) => {
                const type = ev.event?.event_type || 'unknown';
                const color = EVENT_TYPE_COLORS[type] || 'var(--text-muted)';
                const label = EVENT_TYPE_LABELS[type] || type.toUpperCase().slice(0, 5);
                return (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border)', opacity: 0.9 }}>
                    <td style={{ padding: '3px 12px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {formatTs(ev.timestamp || ev.event?.event_type)}
                    </td>
                    <td style={{ padding: '3px 12px' }}>
                      <span style={{
                        color,
                        fontWeight: 600,
                        fontSize: 10,
                        background: `${color}18`,
                        padding: '1px 5px',
                        borderRadius: 3,
                        border: `1px solid ${color}44`,
                      }}>
                        {label}
                      </span>
                    </td>
                    <td style={{ padding: '3px 12px', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 130 }}>
                      {ev.agent_hostname || '—'}
                    </td>
                    <td style={{ padding: '3px 12px', color: 'var(--text-muted)' }}>
                      {ev.event?.pid ?? '—'}
                    </td>
                    <td style={{ padding: '3px 12px', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 600 }}
                      title={eventSummary(ev.event)}>
                      {eventSummary(ev.event)}
                    </td>
                  </tr>
                );
              })
            )}
            <tr ref={bottomRef as React.RefObject<HTMLTableRowElement>} />
          </tbody>
        </table>
      </div>
    </div>
  );
}
