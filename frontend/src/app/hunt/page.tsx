'use client'

import { useState, useCallback } from 'react'

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8080'

function getToken() {
  if (typeof window === 'undefined') return ''
  return localStorage.getItem('token') ?? ''
}

function authHeaders() {
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` }
}

const SEV_COLOR: Record<string, string> = {
  critical: 'bg-red-900 text-red-200',
  high: 'bg-orange-900 text-orange-200',
  medium: 'bg-yellow-900 text-yellow-200',
  low: 'bg-blue-900 text-blue-200',
}

interface HuntQuery {
  from?: string
  to?: string
  host_id?: string
  tenant_id?: string
  severity?: string
  rule_id?: string
  mitre_tag?: string
  attack_chain?: string
  keyword?: string
  offset?: number
  limit?: number
}

interface Facets {
  by_severity: Record<string, number>
  by_host: Record<string, number>
  by_rule: Record<string, number>
  by_mitre: Record<string, number>
}

interface HuntResult {
  total: number
  hits: Record<string, unknown>[]
  facets: Facets
}

interface SavedHunt {
  id: string
  name: string
  description?: string
  query: HuntQuery
  created_at: string
  run_count: number
  last_run_at?: string
}

const EMPTY_QUERY: HuntQuery = {
  from: '', to: '', host_id: '', tenant_id: '', severity: '',
  rule_id: '', mitre_tag: '', attack_chain: '', keyword: '',
  offset: 0, limit: 50,
}

function FacetPanel({ facets }: { facets: Facets }) {
  const sections: { title: string; data: Record<string, number> }[] = [
    { title: 'By Severity', data: facets.by_severity ?? {} },
    { title: 'By Host', data: facets.by_host ?? {} },
    { title: 'By Rule', data: facets.by_rule ?? {} },
    { title: 'By MITRE', data: facets.by_mitre ?? {} },
  ]
  return (
    <div className="space-y-4">
      {sections.map(s => {
        const entries = Object.entries(s.data).sort((a, b) => b[1] - a[1]).slice(0, 8)
        if (!entries.length) return null
        const max = entries[0][1]
        return (
          <div key={s.title}>
            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">{s.title}</div>
            <div className="space-y-1">
              {entries.map(([k, v]) => (
                <div key={k} className="flex items-center gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex justify-between text-xs mb-0.5">
                      <span className="truncate text-gray-300">{k}</span>
                      <span className="text-gray-500 ml-1">{v}</span>
                    </div>
                    <div className="h-1 bg-gray-700 rounded">
                      <div
                        className="h-1 bg-indigo-500 rounded"
                        style={{ width: `${Math.round((v / max) * 100)}%` }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}

export default function HuntPage() {
  const [query, setQuery] = useState<HuntQuery>({ ...EMPTY_QUERY })
  const [result, setResult] = useState<HuntResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const [savedHunts, setSavedHunts] = useState<SavedHunt[]>([])
  const [savedLoaded, setSavedLoaded] = useState(false)
  const [showSaved, setShowSaved] = useState(false)
  const [saveForm, setSaveForm] = useState({ name: '', description: '' })
  const [showSaveForm, setShowSaveForm] = useState(false)
  const [saveError, setSaveError] = useState('')

  const setQ = (k: keyof HuntQuery, v: string | number) =>
    setQuery(q => ({ ...q, [k]: v }))

  const executeQuery = useCallback(async (q: HuntQuery) => {
    setLoading(true)
    setError('')
    try {
      const body: Record<string, unknown> = {}
      if (q.from) body.from = q.from
      if (q.to) body.to = q.to
      if (q.host_id) body.host_id = q.host_id
      if (q.tenant_id) body.tenant_id = q.tenant_id
      if (q.severity) body.severity = q.severity
      if (q.rule_id) body.rule_id = q.rule_id
      if (q.mitre_tag) body.mitre_tag = q.mitre_tag
      if (q.attack_chain) body.attack_chain = q.attack_chain
      if (q.keyword) body.keyword = q.keyword
      body.offset = q.offset ?? 0
      body.limit = q.limit ?? 50

      const res = await fetch(`${API}/api/v1/hunt`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(body),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setResult(await res.json())
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Request failed')
    } finally {
      setLoading(false)
    }
  }, [])

  const loadSavedHunts = async () => {
    try {
      const res = await fetch(`${API}/api/v1/hunt/saved`, { headers: authHeaders() })
      if (res.ok) setSavedHunts(await res.json())
      setSavedLoaded(true)
    } catch { /* ignore */ }
  }

  const handleShowSaved = () => {
    setShowSaved(s => !s)
    if (!savedLoaded) loadSavedHunts()
  }

  const runSaved = async (id: string) => {
    setLoading(true)
    setError('')
    try {
      const res = await fetch(`${API}/api/v1/hunt/saved/${id}/run`, {
        method: 'POST',
        headers: authHeaders(),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setResult(await res.json())
      setShowSaved(false)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Request failed')
    } finally {
      setLoading(false)
    }
  }

  const deleteSaved = async (id: string) => {
    await fetch(`${API}/api/v1/hunt/saved/${id}`, {
      method: 'DELETE', headers: authHeaders(),
    })
    setSavedHunts(s => s.filter(h => h.id !== id))
  }

  const saveCurrentQuery = async () => {
    setSaveError('')
    if (!saveForm.name.trim()) { setSaveError('Name required'); return }
    try {
      const res = await fetch(`${API}/api/v1/hunt/saved`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ name: saveForm.name, description: saveForm.description, query }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const saved = await res.json()
      setSavedHunts(s => [saved, ...s])
      setShowSaveForm(false)
      setSaveForm({ name: '', description: '' })
    } catch (e: unknown) {
      setSaveError(e instanceof Error ? e.message : 'Save failed')
    }
  }

  const prevPage = () => {
    const off = Math.max(0, (query.offset ?? 0) - (query.limit ?? 50))
    const q = { ...query, offset: off }
    setQuery(q)
    executeQuery(q)
  }

  const nextPage = () => {
    const q = { ...query, offset: (query.offset ?? 0) + (query.limit ?? 50) }
    setQuery(q)
    executeQuery(q)
  }

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-6">
      <div className="max-w-screen-xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white">Threat Hunt</h1>
            <p className="text-gray-400 text-sm mt-1">Query the alert ring buffer with multi-field filters</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleShowSaved}
              className="px-3 py-2 rounded bg-gray-800 hover:bg-gray-700 text-sm border border-gray-700"
            >
              {showSaved ? 'Hide Saved' : 'Saved Hunts'}
            </button>
            <button
              onClick={() => { setShowSaveForm(s => !s); setSaveError('') }}
              className="px-3 py-2 rounded bg-indigo-700 hover:bg-indigo-600 text-sm"
            >
              Save Query
            </button>
          </div>
        </div>

        {/* Save Form */}
        {showSaveForm && (
          <div className="mb-4 p-4 bg-gray-900 rounded-lg border border-gray-700">
            <div className="text-sm font-semibold mb-3">Save Current Query</div>
            <div className="flex gap-3 flex-wrap">
              <input
                className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm flex-1 min-w-48"
                placeholder="Hunt name *"
                value={saveForm.name}
                onChange={e => setSaveForm(f => ({ ...f, name: e.target.value }))}
              />
              <input
                className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm flex-1 min-w-48"
                placeholder="Description (optional)"
                value={saveForm.description}
                onChange={e => setSaveForm(f => ({ ...f, description: e.target.value }))}
              />
              <button onClick={saveCurrentQuery} className="px-4 py-1.5 rounded bg-indigo-700 hover:bg-indigo-600 text-sm">Save</button>
              <button onClick={() => setShowSaveForm(false)} className="px-4 py-1.5 rounded bg-gray-700 hover:bg-gray-600 text-sm">Cancel</button>
            </div>
            {saveError && <p className="text-red-400 text-xs mt-2">{saveError}</p>}
          </div>
        )}

        {/* Saved Hunts Panel */}
        {showSaved && (
          <div className="mb-4 p-4 bg-gray-900 rounded-lg border border-gray-700">
            <div className="text-sm font-semibold mb-3">Saved Hunts ({savedHunts.length})</div>
            {savedHunts.length === 0 ? (
              <p className="text-gray-500 text-sm">No saved hunts yet.</p>
            ) : (
              <div className="space-y-2">
                {savedHunts.map(sh => (
                  <div key={sh.id} className="flex items-center justify-between bg-gray-800 rounded p-3">
                    <div>
                      <div className="text-sm font-medium text-white">{sh.name}</div>
                      {sh.description && <div className="text-xs text-gray-400">{sh.description}</div>}
                      <div className="text-xs text-gray-500 mt-0.5">
                        Runs: {sh.run_count} · Created: {new Date(sh.created_at).toLocaleDateString()}
                        {sh.last_run_at && ` · Last: ${new Date(sh.last_run_at).toLocaleString()}`}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => runSaved(sh.id)}
                        className="px-3 py-1.5 rounded bg-indigo-700 hover:bg-indigo-600 text-xs"
                      >
                        Run
                      </button>
                      <button
                        onClick={() => { setQuery({ ...EMPTY_QUERY, ...sh.query }); setShowSaved(false) }}
                        className="px-3 py-1.5 rounded bg-gray-700 hover:bg-gray-600 text-xs"
                      >
                        Load
                      </button>
                      <button
                        onClick={() => deleteSaved(sh.id)}
                        className="px-3 py-1.5 rounded bg-red-900 hover:bg-red-800 text-xs"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Query Builder */}
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 mb-6">
          <div className="text-sm font-semibold text-gray-300 mb-3">Query Builder</div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1">From</label>
              <input
                type="datetime-local"
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                value={query.from ?? ''}
                onChange={e => setQ('from', e.target.value ? new Date(e.target.value).toISOString() : '')}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">To</label>
              <input
                type="datetime-local"
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                value={query.to ?? ''}
                onChange={e => setQ('to', e.target.value ? new Date(e.target.value).toISOString() : '')}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Host ID</label>
              <input
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                placeholder="e.g. host-01"
                value={query.host_id ?? ''}
                onChange={e => setQ('host_id', e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Tenant ID</label>
              <input
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                placeholder="e.g. acme"
                value={query.tenant_id ?? ''}
                onChange={e => setQ('tenant_id', e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Severity</label>
              <select
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                value={query.severity ?? ''}
                onChange={e => setQ('severity', e.target.value)}
              >
                <option value="">Any</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="high+">High+</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Rule ID (prefix)</label>
              <input
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                placeholder="e.g. proc_"
                value={query.rule_id ?? ''}
                onChange={e => setQ('rule_id', e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">MITRE Tag (prefix)</label>
              <input
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                placeholder="e.g. T1059"
                value={query.mitre_tag ?? ''}
                onChange={e => setQ('mitre_tag', e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Attack Chain (substring)</label>
              <input
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                placeholder="e.g. lateral"
                value={query.attack_chain ?? ''}
                onChange={e => setQ('attack_chain', e.target.value)}
              />
            </div>
            <div className="col-span-2 md:col-span-3 lg:col-span-4">
              <label className="text-xs text-gray-400 block mb-1">Keyword (title / message / rule name)</label>
              <input
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                placeholder="Free-text search..."
                value={query.keyword ?? ''}
                onChange={e => setQ('keyword', e.target.value)}
                onKeyDown={e => e.key === 'Enter' && executeQuery(query)}
              />
            </div>
          </div>
          <div className="flex items-center gap-3 mt-4">
            <button
              onClick={() => executeQuery(query)}
              disabled={loading}
              className="px-5 py-2 rounded bg-indigo-700 hover:bg-indigo-600 disabled:opacity-50 text-sm font-semibold"
            >
              {loading ? 'Hunting…' : 'Run Hunt'}
            </button>
            <button
              onClick={() => { setQuery({ ...EMPTY_QUERY }); setResult(null); setError('') }}
              className="px-4 py-2 rounded bg-gray-700 hover:bg-gray-600 text-sm"
            >
              Clear
            </button>
            <div className="flex items-center gap-2 ml-auto">
              <label className="text-xs text-gray-400">Limit</label>
              <select
                className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100"
                value={query.limit ?? 50}
                onChange={e => setQ('limit', Number(e.target.value))}
              >
                {[25, 50, 100, 250, 500].map(n => (
                  <option key={n} value={n}>{n}</option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-950 border border-red-800 rounded text-red-300 text-sm">{error}</div>
        )}

        {result && (
          <div className="flex gap-6">
            {/* Results */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between mb-3">
                <div className="text-sm text-gray-400">
                  <span className="text-white font-semibold">{result.total}</span> matches
                  {result.hits.length < result.total && (
                    <span> · showing {(query.offset ?? 0) + 1}–{(query.offset ?? 0) + result.hits.length}</span>
                  )}
                </div>
                {result.total > (query.limit ?? 50) && (
                  <div className="flex gap-2">
                    <button
                      onClick={prevPage}
                      disabled={(query.offset ?? 0) === 0}
                      className="px-3 py-1 rounded bg-gray-800 hover:bg-gray-700 text-xs disabled:opacity-40"
                    >
                      ← Prev
                    </button>
                    <button
                      onClick={nextPage}
                      disabled={(query.offset ?? 0) + (query.limit ?? 50) >= result.total}
                      className="px-3 py-1 rounded bg-gray-800 hover:bg-gray-700 text-xs disabled:opacity-40"
                    >
                      Next →
                    </button>
                  </div>
                )}
              </div>

              {result.hits.length === 0 ? (
                <div className="bg-gray-900 rounded-lg border border-gray-800 p-8 text-center text-gray-500">
                  No alerts matched your query.
                </div>
              ) : (
                <div className="space-y-2">
                  {result.hits.map((hit, i) => {
                    const sev = String(hit.severity ?? '')
                    const mitre = Array.isArray(hit.mitre) ? (hit.mitre as string[]) : []
                    return (
                      <div key={i} className="bg-gray-900 rounded-lg border border-gray-800 p-4">
                        <div className="flex items-start gap-3">
                          <span className={`text-xs px-2 py-0.5 rounded font-semibold mt-0.5 ${SEV_COLOR[sev] ?? 'bg-gray-700 text-gray-300'}`}>
                            {sev || '—'}
                          </span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-medium text-white">{String(hit.title ?? '(no title)')}</span>
                              {hit.rule_id && (
                                <span className="text-xs text-gray-500 font-mono">{String(hit.rule_id)}</span>
                              )}
                            </div>
                            <div className="text-sm text-gray-400 mt-0.5 truncate">{String(hit.message ?? '')}</div>
                            <div className="flex items-center gap-3 mt-2 text-xs text-gray-500 flex-wrap">
                              {hit.host_id && <span>Host: <span className="text-gray-300">{String(hit.host_id)}</span></span>}
                              {hit.tenant_id && <span>Tenant: <span className="text-gray-300">{String(hit.tenant_id)}</span></span>}
                              {hit.attack_chain && (
                                <span className="bg-purple-900 text-purple-200 px-1.5 py-0.5 rounded">
                                  {String(hit.attack_chain)}
                                </span>
                              )}
                              {hit.created_at && (
                                <span>{new Date(String(hit.created_at)).toLocaleString()}</span>
                              )}
                            </div>
                            {mitre.length > 0 && (
                              <div className="flex gap-1 flex-wrap mt-2">
                                {mitre.map((t, j) => (
                                  <span key={j} className="text-xs bg-gray-800 text-gray-300 px-1.5 py-0.5 rounded font-mono">
                                    {t}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

            {/* Facets Panel */}
            <div className="w-56 flex-shrink-0">
              <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 sticky top-4">
                <div className="text-sm font-semibold text-gray-300 mb-4">Facets</div>
                <FacetPanel facets={result.facets} />
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
