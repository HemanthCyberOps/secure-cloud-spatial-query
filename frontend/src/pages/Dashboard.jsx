import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts'
import {
  Search, MapPin, TrendingUp, Upload,
  RefreshCw, ChevronRight, Lock
} from 'lucide-react'

import Navbar from '../components/Navbar'
import StatsCards from '../components/StatsCards'
import UploadWizard from '../components/UploadWizard'
import { getStats, exactMatch, rangeQuery, knnQuery, homomorphicSum } from '../api/client'

const COLORS = ['#6366f1','#8b5cf6','#ec4899','#f59e0b','#10b981','#3b82f6','#ef4444']

const TABS = [
  { id: 'overview',  label: 'Overview',      icon: TrendingUp },
  { id: 'search',    label: 'Search',         icon: Search },
  { id: 'spatial',   label: 'Spatial KNN',    icon: MapPin },
  { id: 'upload',    label: 'Import Data',    icon: Upload },
]

export default function Dashboard() {
  const navigate = useNavigate()
  const [tab, setTab]           = useState('overview')
  const [stats, setStats]       = useState(null)
  const [billingSum, setBilling] = useState(null)
  const [loadingStats, setLS]   = useState(false)

  // Search state
  const [searchField, setSearchField]   = useState('name')
  const [searchValue, setSearchValue]   = useState('')
  const [rangeMin, setRangeMin]         = useState('')
  const [rangeMax, setRangeMax]         = useState('')
  const [searchResults, setSearchResults] = useState(null)
  const [searchLoading, setSL]          = useState(false)
  const [searchError, setSearchError]   = useState('')

  // KNN state
  const [knnLat, setKnnLat]   = useState('')
  const [knnLon, setKnnLon]   = useState('')
  const [knnK, setKnnK]       = useState(5)
  const [knnResults, setKnnResults] = useState(null)
  const [knnLoading, setKL]   = useState(false)
  const [knnError, setKnnError] = useState('')

  const token = localStorage.getItem('access_token')

  useEffect(() => {
    if (!token) { navigate('/'); return }
    loadStats()
  }, [token])

  const loadStats = useCallback(async () => {
    setLS(true)
    try {
      const [s, b] = await Promise.all([getStats(), homomorphicSum()])
      setStats(s.data)
      setBilling(b.data.decrypted_sum)
    } catch {
      // stats are non-critical
    } finally {
      setLS(false)
    }
  }, [])

  // ── Search handlers ────────────────────────────────────────────────────────

  const handleExactMatch = async () => {
    if (!searchValue.trim()) return
    setSL(true); setSearchError(''); setSearchResults(null)
    try {
      const res = await exactMatch(searchField, searchValue.trim())
      setSearchResults(res.data.results || [])
    } catch (e) {
      setSearchError(e.displayMessage || e.message || 'Query failed.')
    } finally { setSL(false) }
  }

  const handleRangeQuery = async () => {
    if (!rangeMin || !rangeMax) return
    setSL(true); setSearchError(''); setSearchResults(null)
    try {
      const res = await rangeQuery(Number(rangeMin), Number(rangeMax))
      setSearchResults(res.data.results || [])
    } catch (e) {
      setSearchError(e.displayMessage || e.message || 'Query failed.')
    } finally { setSL(false) }
  }

  const handleKnn = async () => {
    if (!knnLat || !knnLon) return
    setKL(true); setKnnError(''); setKnnResults(null)
    try {
      const res = await knnQuery(Number(knnLat), Number(knnLon), Number(knnK))
      setKnnResults(res.data.results || [])
    } catch (e) {
      setKnnError(e.displayMessage || e.message || 'KNN query failed.')
    } finally { setKL(false) }
  }

  // ── Chart data ─────────────────────────────────────────────────────────────

  const conditionData = stats
    ? Object.entries(stats.conditions_breakdown || {})
        .sort((a, b) => b[1] - a[1]).slice(0, 8)
        .map(([name, value]) => ({ name, value }))
    : []

  const insurerData = stats
    ? Object.entries(stats.insurers_breakdown || {})
        .map(([name, value]) => ({ name, value }))
    : []

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen flex flex-col bg-gray-50">
      <Navbar />

      <div className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 py-6 space-y-6">

        {/* Tab bar */}
        <div className="flex items-center gap-1 bg-white rounded-xl border border-gray-200 p-1 w-fit shadow-sm">
          {TABS.map(t => {
            const Icon = t.icon
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors
                  ${tab === t.id
                    ? 'bg-brand-600 text-white shadow-sm'
                    : 'text-gray-600 hover:bg-gray-100'}`}
              >
                <Icon className="w-4 h-4" />
                {t.label}
              </button>
            )
          })}
          <button
            onClick={loadStats}
            disabled={loadingStats}
            className="ml-2 p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100 transition-colors"
            title="Refresh stats"
          >
            <RefreshCw className={`w-4 h-4 ${loadingStats ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {/* ── OVERVIEW ── */}
        {tab === 'overview' && (
          <div className="space-y-6">
            <StatsCards stats={stats} billingSum={billingSum} />

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

              {/* Conditions bar chart */}
              <div className="card p-5">
                <h3 className="text-sm font-semibold text-gray-700 mb-4">Patients by Medical Condition</h3>
                {conditionData.length > 0
                  ? <ResponsiveContainer width="100%" height={220}>
                      <BarChart data={conditionData} margin={{ left: -10 }}>
                        <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                        <YAxis tick={{ fontSize: 11 }} />
                        <Tooltip />
                        <Bar dataKey="value" fill="#6366f1" radius={[4,4,0,0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  : <div className="h-[220px] flex items-center justify-center text-sm text-gray-400">
                      No data yet — import records to see charts.
                    </div>
                }
              </div>

              {/* Insurers pie chart */}
              <div className="card p-5">
                <h3 className="text-sm font-semibold text-gray-700 mb-4">Insurance Provider Distribution</h3>
                {insurerData.length > 0
                  ? <ResponsiveContainer width="100%" height={220}>
                      <PieChart>
                        <Pie data={insurerData} dataKey="value" nameKey="name"
                          cx="50%" cy="50%" outerRadius={80} label={({ name, percent }) =>
                            `${name} ${(percent * 100).toFixed(0)}%`
                          }>
                          {insurerData.map((_, i) => (
                            <Cell key={i} fill={COLORS[i % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  : <div className="h-[220px] flex items-center justify-center text-sm text-gray-400">
                      No data yet.
                    </div>
                }
              </div>
            </div>

            {/* Encryption proof strip */}
            <div className="card p-4 bg-brand-50 border-brand-200">
              <div className="flex items-start gap-3">
                <Lock className="w-5 h-5 text-brand-600 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-semibold text-brand-900">How VaultQuery protects your data</p>
                  <p className="text-xs text-brand-700 mt-1">
                    All <code className="bg-brand-100 px-1 rounded">billing_amount</code> values are encrypted
                    with <strong>Paillier Homomorphic Encryption</strong> before storage.
                    The total billing sum above was computed by adding ciphertexts together —
                    individual patient amounts were <strong>never decrypted</strong> to produce that result.
                    Even if the query server (Server 1) is compromised, it sees only ciphertext.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── SEARCH ── */}
        {tab === 'search' && (
          <div className="space-y-5">

            {/* Exact match */}
            <div className="card p-5 space-y-4">
              <h3 className="text-sm font-semibold text-gray-700">Exact Match Query</h3>
              <p className="text-xs text-gray-500">
                Uses the Multi-Level Bloom Filter for fast lookup, then confirms against the dataset.
              </p>
              <div className="flex gap-3 flex-wrap">
                <select value={searchField} onChange={e => setSearchField(e.target.value)}
                  className="input w-44">
                  {['name','gender','medical_condition','insurance_provider','blood_type','admission_type'].map(f => (
                    <option key={f} value={f}>{f}</option>
                  ))}
                </select>
                <input
                  type="text" value={searchValue}
                  onChange={e => setSearchValue(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleExactMatch()}
                  placeholder="Search value…"
                  className="input flex-1 min-w-[180px]"
                />
                <button onClick={handleExactMatch} disabled={searchLoading} className="btn-primary">
                  {searchLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                  Search
                </button>
              </div>
            </div>

            {/* Range query */}
            <div className="card p-5 space-y-4">
              <h3 className="text-sm font-semibold text-gray-700">Billing Range Query</h3>
              <p className="text-xs text-gray-500">
                Filters on encrypted billing amounts — decryption happens in-process, never exposed to the cloud.
              </p>
              <div className="flex gap-3 flex-wrap">
                <input type="number" value={rangeMin} onChange={e => setRangeMin(e.target.value)}
                  placeholder="Min ($)" className="input w-32" />
                <input type="number" value={rangeMax} onChange={e => setRangeMax(e.target.value)}
                  placeholder="Max ($)" className="input w-32" />
                <button onClick={handleRangeQuery} disabled={searchLoading} className="btn-primary">
                  {searchLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                  Query Range
                </button>
              </div>
            </div>

            {/* Error */}
            {searchError && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
                {searchError}
              </div>
            )}

            {/* Results */}
            {searchResults && (
              <div className="card overflow-hidden">
                <div className="px-5 py-3 border-b border-gray-100 flex items-center justify-between">
                  <span className="text-sm font-medium text-gray-700">
                    {searchResults.length} result{searchResults.length !== 1 ? 's' : ''} found
                  </span>
                  <span className="badge bg-green-100 text-green-700">
                    Safe fields only — no PII exposed
                  </span>
                </div>
                {searchResults.length > 0
                  ? <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead className="bg-gray-50 text-xs text-gray-500 uppercase">
                          <tr>
                            {Object.keys(searchResults[0]).map(k => (
                              <th key={k} className="px-4 py-3 text-left">{k}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100">
                          {searchResults.map((row, i) => (
                            <tr key={i} className="hover:bg-gray-50">
                              {Object.values(row).map((v, j) => (
                                <td key={j} className="px-4 py-2.5 text-gray-700">{String(v)}</td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  : <p className="px-5 py-8 text-center text-sm text-gray-400">No matching records found.</p>
                }
              </div>
            )}
          </div>
        )}

        {/* ── SPATIAL KNN ── */}
        {tab === 'spatial' && (
          <div className="space-y-5">
            <div className="card p-5 space-y-4">
              <h3 className="text-sm font-semibold text-gray-700">K-Nearest Neighbours Query</h3>
              <p className="text-xs text-gray-500">
                Find the k closest patients by geographic coordinates using Euclidean distance.
              </p>
              <div className="flex gap-3 flex-wrap">
                <input type="number" step="any" value={knnLat} onChange={e => setKnnLat(e.target.value)}
                  placeholder="Latitude" className="input w-36" />
                <input type="number" step="any" value={knnLon} onChange={e => setKnnLon(e.target.value)}
                  placeholder="Longitude" className="input w-36" />
                <input type="number" min={1} max={20} value={knnK} onChange={e => setKnnK(e.target.value)}
                  placeholder="k" className="input w-20" />
                <button onClick={handleKnn} disabled={knnLoading} className="btn-primary">
                  {knnLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <MapPin className="w-4 h-4" />}
                  Find Nearest
                </button>
              </div>
              <p className="text-xs text-gray-400">
                Try: Lat <code>0.0</code> Lon <code>0.0</code> k <code>5</code>
              </p>
            </div>

            {knnError && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
                {knnError}
              </div>
            )}

            {knnResults && (
              <div className="card overflow-hidden">
                <div className="px-5 py-3 border-b border-gray-100">
                  <span className="text-sm font-medium text-gray-700">
                    {knnResults.length} nearest record{knnResults.length !== 1 ? 's' : ''}
                  </span>
                </div>
                {knnResults.length > 0
                  ? <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead className="bg-gray-50 text-xs text-gray-500 uppercase">
                          <tr>
                            {Object.keys(knnResults[0]).map(k => (
                              <th key={k} className="px-4 py-3 text-left">{k}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100">
                          {knnResults.map((row, i) => (
                            <tr key={i} className="hover:bg-gray-50">
                              {Object.values(row).map((v, j) => (
                                <td key={j} className="px-4 py-2.5 text-gray-700">{String(v)}</td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  : <p className="px-5 py-8 text-center text-sm text-gray-400">No results.</p>
                }
              </div>
            )}
          </div>
        )}

        {/* ── UPLOAD ── */}
        {tab === 'upload' && (
          <UploadWizard onSuccess={() => { loadStats(); setTab('overview') }} />
        )}

      </div>
    </div>
  )
}
