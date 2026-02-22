'use client';

import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { useAuth, getAuthHeaders, getApiBase } from '@/contexts/AuthContext';
import { useSearch } from '@/contexts/SearchContext';
import Sidebar from './Sidebar';
import ScanModal from './ScanModal';

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { token, isLoading } = useAuth();
  const { query, setQuery } = useSearch();
  const [alertsCount, setAlertsCount] = useState(0);
  const [hostsCount, setHostsCount] = useState(0);
  const [scanModalOpen, setScanModalOpen] = useState(false);
  const [scanModalType, setScanModalType] = useState<'scan' | 'deep_scan' | 'av_scan' | 'dlp_scan'>('scan');

  useEffect(() => {
    if (!isLoading && !token && pathname !== '/login') {
      router.replace('/login');
    }
  }, [isLoading, token, pathname, router]);

  useEffect(() => {
    if (!token) return;
    const api = getApiBase() || 'http://localhost:8080';
    const headers = getAuthHeaders();
    const refresh = () => {
      Promise.all([
        fetch(`${api}/api/v1/alerts`, { headers }).then(r => r.json()).catch(() => []),
        fetch(`${api}/api/v1/hosts`, { headers }).then(r => r.json()).catch(() => []),
      ]).then(([a, h]) => {
        setAlertsCount(Array.isArray(a) ? a.length : 0);
        setHostsCount(Array.isArray(h) ? h.length : 0);
      });
    };
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, [token]);

  if (pathname === '/login') {
    return <>{children}</>;
  }

  if (isLoading) {
    return (
      <div className="login-page">
        <p style={{ color: 'var(--text-muted)' }}>Loading...</p>
      </div>
    );
  }

  if (!token) {
    return (
      <div className="login-page">
        <p style={{ color: 'var(--text-muted)' }}>Redirecting to login...</p>
      </div>
    );
  }

  const pageTitles: Record<string, { title: string; breadcrumb: string }> = {
    '/': { title: 'Security Dashboard', breadcrumb: 'Workspace › Overview' },
    '/alerts': { title: 'Threat Alerts', breadcrumb: 'Workspace › Alerts' },
    '/hosts': { title: 'Endpoint Status', breadcrumb: 'Workspace › Endpoints' },
    '/rules': { title: 'Sigma Rules', breadcrumb: 'Workspace › Rules' },
    '/av-scan': { title: 'AV Scan Results', breadcrumb: 'Workspace › AV Scan' },
    '/dlp': { title: 'Data Loss Prevention', breadcrumb: 'Workspace › DLP' },
    '/device-control': { title: 'Device Control', breadcrumb: 'Workspace › Device Control' },
  };
  const pathKey = pathname === '/' ? '/' : pathname.startsWith('/hosts') ? '/hosts' : pathname.startsWith('/alerts') ? '/alerts' : pathname.startsWith('/rules') ? '/rules' : pathname.startsWith('/av-scan') ? '/av-scan' : pathname.startsWith('/dlp') ? '/dlp' : pathname.startsWith('/device-control') ? '/device-control' : pathname.startsWith('/process-tree') ? '/process-tree' : '/';
  const meta = pageTitles[pathKey] || { title: 'EDR Platform', breadcrumb: 'Workspace' };
  if (pathname.startsWith('/process-tree')) {
    meta.title = `Process Tree — ${pathname.split('/').pop() || ''}`;
    meta.breadcrumb = 'Workspace › Endpoints › Process Tree';
  }

  const openScanModal = (type: 'scan' | 'deep_scan' | 'av_scan' | 'dlp_scan') => {
    setScanModalType(type);
    setScanModalOpen(true);
  };

  return (
    <>
      <Sidebar alertsCount={alertsCount} hostsCount={hostsCount} onOpenScanModal={openScanModal} />
      <div className="main">
        <div className="topbar">
          <div>
            <div className="page-title">{meta.title}</div>
            <div className="breadcrumb"><span>{meta.breadcrumb}</span></div>
          </div>
          <div className="online-indicator" style={{ marginLeft: 'auto', marginRight: 8 }}>
            <div className="online-dot" />
            Live monitoring active
          </div>
          <div className="search-bar">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
            <input
              type="text"
              placeholder="Search endpoints, threats, IPs..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <div className="topbar-actions">
            <div className="icon-btn" title="Notifications">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>
              <div className="notif-dot" />
            </div>
            <div className="icon-btn" title="Terminal">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
            </div>
            <button className="btn-primary" onClick={() => openScanModal('scan')}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5}><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
              New Scan
            </button>
          </div>
        </div>
        <div className="content">
          {children}
        </div>
      </div>
      <ScanModal
        open={scanModalOpen}
        scanType={scanModalType}
        onClose={() => setScanModalOpen(false)}
      />
    </>
  );
}
