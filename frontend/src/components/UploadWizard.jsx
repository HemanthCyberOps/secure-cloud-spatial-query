import { useState, useRef } from 'react'
import {
  Upload, FileSpreadsheet, ArrowRight, CheckCircle2,
  AlertCircle, Download, X, ChevronDown, RefreshCw,
  Lock
} from 'lucide-react'
import { uploadPreview, uploadConfirm, downloadTemplate } from '../api/client'

const STEPS = ['Upload File', 'Map Columns', 'Review & Import']

const OUR_FIELDS = [
  'name', 'age', 'gender', 'blood_type', 'medical_condition',
  'date_of_admission', 'doctor', 'hospital', 'insurance_provider',
  'billing_amount', 'room_number', 'admission_type', 'discharge_date',
  'medication', 'test_results', 'latitude', 'longitude',
]

export default function UploadWizard({ onSuccess }) {
  const [step, setStep]         = useState(0)
  const [dragging, setDragging] = useState(false)
  const [preview, setPreview]   = useState(null)
  const [mapping, setMapping]   = useState({})
  const [report, setReport]     = useState(null)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')
  const fileRef = useRef()

  // ── Step 0: pick file ──────────────────────────────────────────────────────

  const handleFile = async (f) => {
    if (!f) return
    const ext = f.name.split('.').pop().toLowerCase()
    if (!['csv', 'xlsx', 'xls'].includes(ext)) {
      setError('Only CSV and Excel (.xlsx / .xls) files are supported.')
      return
    }
    setError('')
    setLoading(true)
    try {
      const res = await uploadPreview(f)
      setPreview(res.data)
      setMapping(res.data.auto_mapping || {})
      setStep(1)
    } catch (e) {
      // Show the real backend error, not a generic message
      setError(e.displayMessage || e.message || 'Failed to read file.')
    } finally {
      setLoading(false)
    }
  }

  const onDrop = (e) => {
    e.preventDefault()
    setDragging(false)
    handleFile(e.dataTransfer.files[0])
  }

  const onFileInput = (e) => {
    handleFile(e.target.files[0])
    // Reset input so the same file can be re-selected after an error
    e.target.value = ''
  }

  // ── Step 1: column mapping ─────────────────────────────────────────────────

  const setMap = (fileCol, ourField) => {
    setMapping(prev => {
      const next = { ...prev }
      if (ourField === '') {
        delete next[fileCol]
      } else {
        // Enforce 1-to-1: remove any other column already mapped to this field
        Object.keys(next).forEach(k => {
          if (next[k] === ourField && k !== fileCol) delete next[k]
        })
        next[fileCol] = ourField
      }
      return next
    })
  }

  const mappedValues      = Object.values(mapping)
  const requiredMapped    = ['name', 'billing_amount'].every(f => mappedValues.includes(f))
  const mappedCount       = mappedValues.length

  // ── Step 2: confirm + ingest ───────────────────────────────────────────────

  const handleConfirm = async () => {
    setLoading(true)
    setError('')
    try {
      const res = await uploadConfirm(preview.upload_id, mapping)
      setReport(res.data)
      setStep(2)
      if (res.data.imported > 0 && onSuccess) onSuccess()
    } catch (e) {
      setError(e.displayMessage || e.message || 'Import failed.')
    } finally {
      setLoading(false)
    }
  }

  // ── Template download ──────────────────────────────────────────────────────

  const handleTemplate = async (fmt) => {
    try {
      const res = await downloadTemplate(fmt)
      const mime = fmt === 'excel'
        ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        : 'text/csv'
      const url = URL.createObjectURL(new Blob([res.data], { type: mime }))
      const a   = document.createElement('a')
      a.href    = url
      a.download = `vaultquery_template.${fmt === 'excel' ? 'xlsx' : 'csv'}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (e) {
      setError('Template download failed: ' + (e.displayMessage || e.message))
    }
  }

  // ── Reset ──────────────────────────────────────────────────────────────────

  const reset = () => {
    setStep(0); setPreview(null)
    setMapping({}); setReport(null); setError('')
    setLoading(false)
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="card p-6 space-y-6">

      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-gray-900">Bulk Data Import</h2>
          <p className="text-sm text-gray-500 mt-0.5">
            Upload a CSV or Excel file. Records are Paillier-encrypted automatically on import.
          </p>
        </div>
        <div className="flex gap-2 shrink-0">
          <button onClick={() => handleTemplate('csv')} className="btn-secondary text-xs">
            <Download className="w-3.5 h-3.5" /> CSV Template
          </button>
          <button onClick={() => handleTemplate('excel')} className="btn-secondary text-xs">
            <Download className="w-3.5 h-3.5" /> Excel Template
          </button>
        </div>
      </div>

      {/* ── Step indicator ── */}
      <div className="flex items-center gap-1">
        {STEPS.map((s, i) => (
          <div key={s} className="flex items-center gap-1">
            <div className={`flex items-center justify-center w-7 h-7 rounded-full text-xs font-bold shrink-0
              ${i < step  ? 'bg-green-500 text-white'
              : i === step ? 'bg-brand-600 text-white'
              : 'bg-gray-200 text-gray-500'}`}>
              {i < step ? <CheckCircle2 className="w-4 h-4" /> : i + 1}
            </div>
            <span className={`text-sm whitespace-nowrap
              ${i === step ? 'font-medium text-gray-900' : 'text-gray-400'}`}>
              {s}
            </span>
            {i < STEPS.length - 1 && (
              <ArrowRight className="w-4 h-4 text-gray-300 mx-2" />
            )}
          </div>
        ))}
      </div>

      {/* ── Error banner ── */}
      {error && (
        <div className="flex items-start gap-2 p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
          <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
          <span className="flex-1">{error}</span>
          <button onClick={() => setError('')} className="shrink-0 hover:text-red-900">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          STEP 0 — Drop zone
      ══════════════════════════════════════════════════════════════════════ */}
      {step === 0 && (
        <div
          onDragOver={e => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => !loading && fileRef.current.click()}
          className={`border-2 border-dashed rounded-xl p-14 text-center transition-colors
            ${loading ? 'cursor-wait border-brand-400 bg-brand-50'
            : dragging ? 'cursor-copy border-brand-500 bg-brand-50'
            : 'cursor-pointer border-gray-300 hover:border-brand-400 hover:bg-gray-50'}`}
        >
          <input
            ref={fileRef}
            type="file"
            accept=".csv,.xlsx,.xls"
            className="hidden"
            onChange={onFileInput}
          />

          {loading ? (
            <>
              <RefreshCw className="w-10 h-10 text-brand-500 animate-spin mx-auto mb-3" />
              <p className="text-sm font-medium text-brand-700">Reading and parsing file…</p>
              <p className="text-xs text-brand-500 mt-1">Detecting columns and generating preview</p>
            </>
          ) : (
            <>
              <FileSpreadsheet className="w-10 h-10 text-gray-400 mx-auto mb-3" />
              <p className="text-sm font-medium text-gray-700">
                {dragging ? 'Drop to upload' : 'Drop your file here, or click to browse'}
              </p>
              <p className="text-xs text-gray-400 mt-1">Supports .csv, .xlsx, .xls</p>
              <p className="text-xs text-gray-300 mt-3">
                Don't have a file? Download a template above.
              </p>
            </>
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          STEP 1 — Column mapping
      ══════════════════════════════════════════════════════════════════════ */}
      {step === 1 && preview && (
        <div className="space-y-5">

          {/* File summary bar */}
          <div className="flex items-center gap-3 p-3 bg-blue-50 border border-blue-100 rounded-lg text-sm">
            <FileSpreadsheet className="w-5 h-5 text-blue-500 shrink-0" />
            <div className="flex-1 min-w-0">
              <span className="font-medium text-blue-900 truncate block">{preview.filename}</span>
              <span className="text-blue-600 text-xs">
                {preview.total_rows} rows · {preview.columns.length} columns detected ·{' '}
                {mappedCount} mapped
              </span>
            </div>
            {requiredMapped
              ? <span className="badge bg-green-100 text-green-700 shrink-0">Ready to import</span>
              : <span className="badge bg-yellow-100 text-yellow-700 shrink-0">Map required fields</span>
            }
          </div>

          {/* Required fields reminder */}
          {!requiredMapped && (
            <div className="flex items-start gap-2 p-3 bg-yellow-50 border border-yellow-200 rounded-lg text-xs text-yellow-800">
              <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
              <span>
                You must map at least <strong>name</strong> and <strong>billing_amount</strong> before importing.
                Use the dropdowns below to assign your file's columns to these fields.
              </span>
            </div>
          )}

          {/* Column mapping table */}
          <div className="overflow-x-auto rounded-lg border border-gray-200">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-xs text-gray-500 uppercase tracking-wide">
                <tr>
                  <th className="px-4 py-3 text-left">Your Column</th>
                  <th className="px-4 py-3 text-left">Sample Value</th>
                  <th className="px-4 py-3 text-left w-52">Maps To (VaultQuery field)</th>
                  <th className="px-4 py-3 text-left">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {preview.columns.map(col => {
                  const sample   = preview.preview[0]?.[col]
                  const mapped   = mapping[col] || ''
                  const required = ['name', 'billing_amount'].includes(mapped)

                  return (
                    <tr key={col} className="hover:bg-gray-50">
                      {/* Column name */}
                      <td className="px-4 py-3 font-mono text-xs text-gray-800 whitespace-nowrap">
                        {col}
                      </td>

                      {/* Sample value */}
                      <td className="px-4 py-3 text-gray-500 text-xs max-w-[140px] truncate">
                        {sample != null && sample !== ''
                          ? String(sample)
                          : <span className="italic text-gray-300">—</span>
                        }
                      </td>

                      {/* Dropdown */}
                      <td className="px-4 py-3">
                        <select
                          value={mapped}
                          onChange={e => setMap(col, e.target.value)}
                          className="w-full px-2 py-1.5 text-xs border border-gray-300 rounded-md
                                     focus:outline-none focus:ring-2 focus:ring-brand-500 bg-white"
                        >
                          <option value="">— skip —</option>
                          {OUR_FIELDS.map(f => (
                            <option
                              key={f}
                              value={f}
                              disabled={mappedValues.includes(f) && mapping[col] !== f}
                            >
                              {f}{['name','billing_amount'].includes(f) ? ' *' : ''}
                            </option>
                          ))}
                        </select>
                      </td>

                      {/* Status badge */}
                      <td className="px-4 py-3">
                        {mapped
                          ? <span className={`badge ${required
                              ? 'bg-green-100 text-green-700'
                              : 'bg-blue-100 text-blue-700'}`}>
                              {required ? '✓ Required' : '✓ Mapped'}
                            </span>
                          : <span className="badge bg-gray-100 text-gray-400">Skipped</span>
                        }
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* Data preview */}
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
              Data Preview — first {preview.preview.length} rows
            </p>
            <div className="overflow-x-auto rounded-lg border border-gray-200">
              <table className="w-full text-xs">
                <thead className="bg-gray-50 text-gray-500">
                  <tr>
                    {preview.columns.map(c => (
                      <th key={c} className="px-3 py-2 text-left font-medium whitespace-nowrap">
                        {c}
                        {mapping[c] && (
                          <span className="ml-1 text-brand-500">→ {mapping[c]}</span>
                        )}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {preview.preview.map((row, i) => (
                    <tr key={i} className="hover:bg-gray-50">
                      {preview.columns.map(c => (
                        <td key={c} className="px-3 py-2 text-gray-600 whitespace-nowrap max-w-[160px] truncate">
                          {row[c] != null && row[c] !== '' ? String(row[c]) : ''}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Encryption note */}
          <div className="flex items-start gap-2 p-3 bg-brand-50 border border-brand-100 rounded-lg text-xs text-brand-700">
            <Lock className="w-4 h-4 mt-0.5 shrink-0" />
            <span>
              The <strong>billing_amount</strong> column will be encrypted with Paillier Homomorphic Encryption
              before being stored. All other fields are indexed in the Bloom filter for fast lookup.
            </span>
          </div>

          {/* Action buttons */}
          <div className="flex items-center justify-between pt-1">
            <button onClick={reset} className="btn-secondary">
              <X className="w-4 h-4" /> Start Over
            </button>
            <button
              onClick={handleConfirm}
              disabled={!requiredMapped || loading}
              className="btn-primary"
            >
              {loading
                ? <><RefreshCw className="w-4 h-4 animate-spin" /> Encrypting & Importing…</>
                : <><Upload className="w-4 h-4" /> Import {preview.total_rows} Rows</>
              }
            </button>
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          STEP 2 — Validation report
      ══════════════════════════════════════════════════════════════════════ */}
      {step === 2 && report && (
        <div className="space-y-5">

          {/* Summary numbers */}
          <div className="grid grid-cols-3 gap-4">
            <div className="p-4 bg-gray-50 rounded-xl text-center border border-gray-200">
              <p className="text-3xl font-bold text-gray-900">{report.total_rows}</p>
              <p className="text-xs text-gray-500 mt-1 font-medium">Total Rows</p>
            </div>
            <div className="p-4 bg-green-50 rounded-xl text-center border border-green-200">
              <p className="text-3xl font-bold text-green-700">{report.imported}</p>
              <p className="text-xs text-green-600 mt-1 font-medium">Imported & Encrypted</p>
            </div>
            <div className={`p-4 rounded-xl text-center border ${
              report.skipped > 0
                ? 'bg-red-50 border-red-200'
                : 'bg-gray-50 border-gray-200'}`}>
              <p className={`text-3xl font-bold ${report.skipped > 0 ? 'text-red-700' : 'text-gray-400'}`}>
                {report.skipped}
              </p>
              <p className={`text-xs mt-1 font-medium ${report.skipped > 0 ? 'text-red-600' : 'text-gray-400'}`}>
                Skipped
              </p>
            </div>
          </div>

          {/* Success banner */}
          {report.imported > 0 && (
            <div className="flex items-start gap-3 p-4 bg-green-50 border border-green-200 rounded-xl">
              <CheckCircle2 className="w-5 h-5 text-green-600 mt-0.5 shrink-0" />
              <div>
                <p className="text-sm font-semibold text-green-800">
                  {report.imported} record{report.imported !== 1 ? 's' : ''} successfully imported
                </p>
                <p className="text-xs text-green-700 mt-0.5">
                  Each billing_amount was encrypted with Paillier Homomorphic Encryption and stored.
                  The Bloom filter was updated for fast future lookups.
                  The Overview dashboard has been refreshed.
                </p>
              </div>
            </div>
          )}

          {/* Nothing imported */}
          {report.imported === 0 && (
            <div className="flex items-start gap-3 p-4 bg-yellow-50 border border-yellow-200 rounded-xl">
              <AlertCircle className="w-5 h-5 text-yellow-600 mt-0.5 shrink-0" />
              <div className="space-y-2">
                <p className="text-sm font-semibold text-yellow-800">No records were imported</p>
                <p className="text-xs text-yellow-700">
                  All rows were skipped. See the error list below for the exact reason per row.
                </p>
                {/* Explain the most common reason */}
                {report.errors?.every(e => e.reason.startsWith('Duplicate')) && (
                  <div className="mt-2 p-3 bg-white border border-yellow-200 rounded-lg text-xs text-gray-700 space-y-1">
                    <p className="font-semibold text-gray-800">💡 All rows are duplicates</p>
                    <p>Every record in this file already exists in VaultQuery (matched by patient name).</p>
                    <p className="mt-1">To add new data:</p>
                    <ul className="list-disc list-inside space-y-0.5 text-gray-600">
                      <li>Download the <strong>CSV Template</strong> and fill in new patient names</li>
                      <li>Or use a file with patients not already in the system</li>
                      <li>The sample file <code className="bg-gray-100 px-1 rounded">sample_new_patients.csv</code> in the dataset folder has 10 new records ready to import</li>
                    </ul>
                  </div>
                )}
                {report.errors?.some(e => e.reason.startsWith('Missing')) && (
                  <div className="mt-2 p-3 bg-white border border-yellow-200 rounded-lg text-xs text-gray-700">
                    <p className="font-semibold text-gray-800">💡 Missing required fields</p>
                    <p>Make sure <strong>name</strong> and <strong>billing_amount</strong> columns are mapped and have values in every row.</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Per-row error list */}
          {report.errors?.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-sm font-semibold text-gray-700">
                  Skipped rows — {report.errors.length}{report.errors.length === 50 ? '+' : ''} issues
                </p>
                <span className="text-xs text-gray-400">
                  Fix these in your file and re-import
                </span>
              </div>
              <div className="max-h-56 overflow-y-auto rounded-lg border border-red-100 divide-y divide-red-50 bg-white">
                {report.errors.map((e, i) => (
                  <div key={i} className="flex items-start gap-3 px-4 py-2.5 text-xs hover:bg-red-50">
                    <span className="text-gray-400 font-mono w-14 shrink-0 pt-0.5">Row {e.row}</span>
                    <span className="text-red-600">{e.reason}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="flex items-center justify-between pt-1">
            <button onClick={reset} className="btn-secondary">
              <Upload className="w-4 h-4" /> Import Another File
            </button>
            {report.imported > 0 && (
              <span className="text-xs text-gray-400">
                Dashboard updated automatically
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
