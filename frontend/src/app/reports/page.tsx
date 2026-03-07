'use client'

import { useState } from 'react'

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8080'

function getToken() {
  if (typeof window === 'undefined') return ''
  return localStorage.getItem('token') ?? ''
}

function authHeaders(contentType = true) {
  const h: Record<string, string> = { Authorization: `Bearer ${getToken()}` }
  if (contentType) h['Content-Type'] = 'application/json'
  return h
}

// ─── Types ────────────────────────────────────────────────────────────────────

interface ReportParams {
  type: string
  from: string
  to: string
  tenant_id: string
  limit: number
}

interface NameCount { name: string; count: number }
interface DayCount  { day: string;  count: number }
interface HostCount { host: string; count: number }

interface AlertSummaryData {
  total: number
  by_severity: Record<string, number>
  by_rule: NameCount[]
  by_host: HostCount[]
  by_day: DayCount[]
}

interface IncidentSummaryData {
  total: number
  by_status: Record<string, number>
  by_severity: Record<string, number>
  by_tenant: Record<string, number>
  top_hosts: HostCount[]
  top_chains: NameCount[]
  avg_mttr_mins: number
  open_oldest?: string
}

interface TacticCoverage {
  tactic: string
  detected: number
  total: number
  pct: number
}

interface MitreCoverageData {
  techniques_detected: number
  total_known: number
  coverage_pct: number
  tactics: TacticCoverage[]
  top_techniques: NameCount[]
}

interface DLPSummaryData {
  total_scans: number
  total_matches: number
  by_pattern: Record<string, number>
  by_host: HostCount[]
  by_severity: Record<string, number>
  by_action: Record<string, number>
}

interface HostRiskEntry { host_id: string; risk_score: number; critical: number; high: number; medium: number; low: number }

interface HostRiskData { hosts: HostRiskEntry[] }

interface Report {
  id: string
  type: string
  title: string
  generated_at: string
  data: unknown
}

// ─── Sub-components ───────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: 'bg-red-900 text-red-200',
  high: 'bg-orange-900 text-orange-200',
  medium: 'bg-yellow-900 text-yellow-200',
  low: 'bg-blue-900 text-blue-200',
}

function StatRow({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex justify-between py-1.5 border-b border-gray-800 text-sm">
      <span className="text-gray-400">{label}</span>
      <span className="font-medium text-white">{value}</span>
    </div>
  )
}

function SevBar({ counts }: { counts: Record<string, number> }) {
  const order = ['critical', 'high', 'medium', 'low']
  const total = Object.values(counts).reduce((a, b) => a + b, 0)
  if (!total) return <div className="text-gray-500 text-sm">No data</div>
  return (
    <div className="space-y-2">
      {order.filter(s => counts[s]).map(sev => (
        <div key={sev} className="flex items-center gap-3">
          <span className={`text-xs px-2 py-0.5 rounded w-20 text-center font-semibold ${SEV_COLOR[sev]}`}>{sev}</span>
          <div className="flex-1 bg-gray-800 rounded h-2">
            <div
              className={`h-2 rounded ${sev === 'critical' ? 'bg-red-600' : sev === 'high' ? 'bg-orange-600' : sev === 'medium' ? 'bg-yellow-500' : 'bg-blue-600'}`}
              style={{ width: `${Math.round((counts[sev] / total) * 100)}%` }}
            />
          </div>
          <span className="text-sm text-gray-300 w-10 text-right">{counts[sev]}</span>
        </div>
      ))}
    </div>
  )
}

function BarList({ items, labelKey, valueKey }: { items: unknown[]; labelKey: string; valueKey: string }) {
  const typed = items as Record<string, unknown>[]
  const max = typed.reduce((m, i) => Math.max(m, Number(i[valueKey] ?? 0)), 0)
  if (!typed.length) return <div className="text-gray-500 text-sm">No data</div>
  return (
    <div className="space-y-2">
      {typed.slice(0, 10).map((item, i) => (
        <div key={i} className="flex items-center gap-2">
          <span className="text-sm text-gray-300 w-48 truncate">{String(item[labelKey] ?? '')}</span>
          <div className="flex-1 bg-gray-800 rounded h-1.5">
            <div className="h-1.5 bg-indigo-500 rounded" style={{ width: `${max ? Math.round((Number(item[valueKey]) / max) * 100) : 0}%` }} />
          </div>
          <span className="text-sm text-gray-400 w-10 text-right">{String(item[valueKey] ?? '')}</span>
        </div>
      ))}
    </div>
  )
}

function AlertSummaryView({ data }: { data: AlertSummaryData }) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-3xl font-bold text-white">{data.total}</div>
          <div className="text-gray-400 text-sm mt-1">Total Alerts</div>
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-3xl font-bold text-red-400">{data.by_severity?.critical ?? 0}</div>
          <div className="text-gray-400 text-sm mt-1">Critical</div>
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-3xl font-bold text-orange-400">{data.by_severity?.high ?? 0}</div>
          <div className="text-gray-400 text-sm mt-1">High</div>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <div className="text-sm font-semibold text-gray-300 mb-3">Alerts by Severity</div>
          <SevBar counts={data.by_severity ?? {}} />
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <div className="text-sm font-semibold text-gray-300 mb-3">Top Rules</div>
          <BarList items={data.by_rule ?? []} labelKey="name" valueKey="count" />
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <div className="text-sm font-semibold text-gray-300 mb-3">Top Hosts</div>
          <BarList items={data.by_host ?? []} labelKey="host" valueKey="count" />
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <div className="text-sm font-semibold text-gray-300 mb-3">Alerts by Day (last 30d)</div>
          {(data.by_day ?? []).length === 0 ? (
            <div className="text-gray-500 text-sm">No data</div>
          ) : (
            <div className="space-y-1 max-h-64 overflow-y-auto">
              {(data.by_day ?? []).map((d, i) => (
                <div key={i} className="flex justify-between text-sm">
                  <span className="text-gray-400 font-mono">{d.day}</span>
                  <span className="text-white">{d.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function IncidentSummaryView({ data }: { data: IncidentSummaryData }) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-3xl font-bold text-white">{data.total}</div>
          <div className="text-gray-400 text-sm mt-1">Total</div>
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-3xl font-bold text-yellow-400">{data.by_status?.open ?? 0}</div>
          <div className="text-gray-400 text-sm mt-1">Open</div>
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-3xl font-bold text-green-400">{data.by_status?.resolved ?? 0}</div>
          <div className="text-gray-400 text-sm mt-1">Resolved</div>
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-3xl font-bold text-blue-400">{Math.round(data.avg_mttr_mins ?? 0)}</div>
          <div className="text-gray-400 text-sm mt-1">Avg MTTR (min)</div>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <div className="text-sm font-semibold text-gray-300 mb-3">By Severity</div>
          <SevBar counts={data.by_severity ?? {}} />
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <div className="text-sm font-semibold text-gray-300 mb-3">Top Hosts</div>
          <BarList items={data.top_hosts ?? []} labelKey="host" valueKey="count" />
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <div className="text-sm font-semibold text-gray-300 mb-3">Top Attack Chains</div>
          <BarList items={data.top_chains ?? []} labelKey="name" valueKey="count" />
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <div className="text-sm font-semibold text-gray-300 mb-3">By Tenant</div>
          {Object.entries(data.by_tenant ?? {}).length === 0 ? (
            <div className="text-gray-500 text-sm">No data</div>
          ) : (
            Object.entries(data.by_tenant ?? {}).map(([k, v]) => (
              <StatRow key={k} label={k} value={v} />
            ))
          )}
        </div>
      </div>
    </div>
  )
}

function MitreCoverageView({ data }: { data: MitreCoverageData }) {
  const pct = data.coverage_pct ?? 0
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-3xl font-bold text-white">{data.techniques_detected}</div>
          <div className="text-gray-400 text-sm mt-1">Techniques Detected</div>
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-3xl font-bold text-gray-300">{data.total_known}</div>
          <div className="text-gray-400 text-sm mt-1">Known Techniques</div>
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-3xl font-bold text-indigo-400">{pct.toFixed(1)}%</div>
          <div className="text-gray-400 text-sm mt-1">Coverage</div>
        </div>
      </div>
      {/* Coverage bar */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
        <div className="text-sm font-semibold text-gray-300 mb-3">Overall Coverage</div>
        <div className="flex items-center gap-3">
          <div className="flex-1 bg-gray-800 rounded h-3">
            <div className="h-3 bg-indigo-600 rounded" style={{ width: `${Math.min(pct, 100)}%` }} />
          </div>
          <span className="text-indigo-300 font-semibold text-sm w-16 text-right">{pct.toFixed(1)}%</span>
        </div>
      </div>
      {/* Tactic breakdown */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
        <div className="text-sm font-semibold text-gray-300 mb-3">Coverage by Tactic</div>
        <div className="space-y-2">
          {(data.tactics ?? []).map((t, i) => (
            <div key={i} className="flex items-center gap-3">
              <span className="text-xs text-gray-300 w-48 truncate">{t.tactic}</span>
              <div className="flex-1 bg-gray-800 rounded h-1.5">
                <div
                  className={`h-1.5 rounded ${t.pct >= 50 ? 'bg-green-600' : t.pct >= 20 ? 'bg-yellow-500' : 'bg-red-700'}`}
                  style={{ width: `${Math.min(t.pct, 100)}%` }}
                />
              </div>
              <span className="text-xs text-gray-400 w-20 text-right">{t.detected}/{t.total} ({t.pct.toFixed(0)}%)</span>
            </div>
          ))}
        </div>
      </div>
      {/* Top techniques */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
        <div className="text-sm font-semibold text-gray-300 mb-3">Top Techniques Detected</div>
        <BarList items={data.top_techniques ?? []} labelKey="name" valueKey="count" />
      </div>
    </div>
  )
}

function DLPSummaryView({ data }: { data: DLPSummaryData }) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-3xl font-bold text-white">{data.total_scans}</div>
          <div className="text-gray-400 text-sm mt-1">Total Scans</div>
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-3xl font-bold text-red-400">{data.total_matches}</div>
          <div className="text-gray-400 text-sm mt-1">Total Matches</div>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <div className="text-sm font-semibold text-gray-300 mb-3">By Pattern</div>
          {Object.entries(data.by_pattern ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => (
            <StatRow key={k} label={k} value={v} />
          ))}
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <div className="text-sm font-semibold text-gray-300 mb-3">Top Hosts</div>
          <BarList items={data.by_host ?? []} labelKey="host" valueKey="count" />
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <div className="text-sm font-semibold text-gray-300 mb-3">By Severity</div>
          <SevBar counts={data.by_severity ?? {}} />
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <div className="text-sm font-semibold text-gray-300 mb-3">By Action</div>
          {Object.entries(data.by_action ?? {}).map(([k, v]) => (
            <StatRow key={k} label={k} value={v} />
          ))}
        </div>
      </div>
    </div>
  )
}

function HostRiskView({ data }: { data: HostRiskData }) {
  const hosts = data.hosts ?? []
  if (!hosts.length) return <div className="text-gray-500 text-sm p-4">No host risk data.</div>
  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
            <th className="px-4 py-3 text-left">Host</th>
            <th className="px-4 py-3 text-center">Risk Score</th>
            <th className="px-4 py-3 text-center">Critical</th>
            <th className="px-4 py-3 text-center">High</th>
            <th className="px-4 py-3 text-center">Medium</th>
            <th className="px-4 py-3 text-center">Low</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((h, i) => (
            <tr key={i} className="border-b border-gray-800 hover:bg-gray-800/50">
              <td className="px-4 py-3 font-medium text-white">{h.host_id}</td>
              <td className="px-4 py-3 text-center">
                <span className={`px-2 py-0.5 rounded text-xs font-semibold ${h.risk_score >= 70 ? 'bg-red-900 text-red-200' : h.risk_score >= 40 ? 'bg-orange-900 text-orange-200' : 'bg-gray-700 text-gray-300'}`}>
                  {h.risk_score}
                </span>
              </td>
              <td className="px-4 py-3 text-center text-red-400">{h.critical}</td>
              <td className="px-4 py-3 text-center text-orange-400">{h.high}</td>
              <td className="px-4 py-3 text-center text-yellow-400">{h.medium}</td>
              <td className="px-4 py-3 text-center text-blue-400">{h.low}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ReportView({ report }: { report: Report }) {
  const d = report.data as Record<string, unknown>
  switch (report.type) {
    case 'alert_summary':    return <AlertSummaryView data={d as unknown as AlertSummaryData} />
    case 'incident_summary': return <IncidentSummaryView data={d as unknown as IncidentSummaryData} />
    case 'mitre_coverage':   return <MitreCoverageView data={d as unknown as MitreCoverageData} />
    case 'dlp_summary':      return <DLPSummaryView data={d as unknown as DLPSummaryData} />
    case 'host_risk':        return <HostRiskView data={d as unknown as HostRiskData} />
    default:                 return <pre className="text-xs text-gray-300 overflow-x-auto">{JSON.stringify(report.data, null, 2)}</pre>
  }
}

// ─── Main Page ────────────────────────────────────────────────────────────────

const REPORT_TYPES = [
  { value: 'alert_summary',    label: 'Alert Summary' },
  { value: 'incident_summary', label: 'Incident Summary' },
  { value: 'mitre_coverage',   label: 'MITRE ATT&CK Coverage' },
  { value: 'dlp_summary',      label: 'DLP Summary' },
  { value: 'host_risk',        label: 'Host Risk' },
]

export default function ReportsPage() {
  const [params, setParams] = useState<ReportParams>({
    type: 'alert_summary',
    from: '',
    to: '',
    tenant_id: '',
    limit: 20,
  })
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [exporting, setExporting] = useState(false)

  const setP = (k: keyof ReportParams, v: string | number) =>
    setParams(p => ({ ...p, [k]: v }))

  const generate = async () => {
    setLoading(true)
    setError('')
    try {
      const body: Record<string, unknown> = { type: params.type, limit: params.limit }
      if (params.from) body.from = new Date(params.from).toISOString()
      if (params.to) body.to = new Date(params.to).toISOString()
      if (params.tenant_id) body.tenant_id = params.tenant_id
      const res = await fetch(`${API}/api/v1/reports/generate`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(body),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error((err as Record<string, string>).error ?? `HTTP ${res.status}`)
      }
      setReport(await res.json())
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Request failed')
    } finally {
      setLoading(false)
    }
  }

  const exportCSV = async (type: 'alerts' | 'incidents') => {
    setExporting(true)
    try {
      const res = await fetch(`${API}/api/v1/reports/export?type=${type}`, {
        headers: { Authorization: `Bearer ${getToken()}` },
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${type}.csv`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Export failed')
    } finally {
      setExporting(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-6">
      <div className="max-w-screen-xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white">Reports</h1>
            <p className="text-gray-400 text-sm mt-1">Compliance and operational reporting</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => exportCSV('alerts')}
              disabled={exporting}
              className="px-3 py-2 rounded bg-gray-800 hover:bg-gray-700 border border-gray-700 text-sm disabled:opacity-50"
            >
              Export Alerts CSV
            </button>
            <button
              onClick={() => exportCSV('incidents')}
              disabled={exporting}
              className="px-3 py-2 rounded bg-gray-800 hover:bg-gray-700 border border-gray-700 text-sm disabled:opacity-50"
            >
              Export Incidents CSV
            </button>
          </div>
        </div>

        {/* Parameters */}
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 mb-6">
          <div className="text-sm font-semibold text-gray-300 mb-3">Report Parameters</div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Report Type</label>
              <select
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                value={params.type}
                onChange={e => setP('type', e.target.value)}
              >
                {REPORT_TYPES.map(rt => (
                  <option key={rt.value} value={rt.value}>{rt.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">From</label>
              <input
                type="datetime-local"
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                value={params.from}
                onChange={e => setP('from', e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">To</label>
              <input
                type="datetime-local"
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                value={params.to}
                onChange={e => setP('to', e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Tenant ID</label>
              <input
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                placeholder="All tenants"
                value={params.tenant_id}
                onChange={e => setP('tenant_id', e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Top-N Limit</label>
              <select
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                value={params.limit}
                onChange={e => setP('limit', Number(e.target.value))}
              >
                {[10, 20, 50, 100].map(n => (
                  <option key={n} value={n}>{n}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="mt-4">
            <button
              onClick={generate}
              disabled={loading}
              className="px-6 py-2 rounded bg-indigo-700 hover:bg-indigo-600 disabled:opacity-50 text-sm font-semibold"
            >
              {loading ? 'Generating…' : 'Generate Report'}
            </button>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-950 border border-red-800 rounded text-red-300 text-sm">{error}</div>
        )}

        {report && (
          <div>
            {/* Report Header */}
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-lg font-semibold text-white">{report.title}</h2>
                <div className="text-xs text-gray-500 mt-0.5">
                  Generated: {new Date(report.generated_at).toLocaleString()}
                  {report.id && <span className="ml-2 font-mono text-gray-600">{report.id}</span>}
                </div>
              </div>
            </div>
            <ReportView report={report} />
          </div>
        )}

        {!report && !loading && !error && (
          <div className="bg-gray-900 rounded-lg border border-gray-800 p-12 text-center">
            <div className="text-gray-500 text-sm">Select a report type and click Generate Report.</div>
          </div>
        )}
      </div>
    </div>
  )
}
