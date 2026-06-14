import axios from 'axios'

// ── Axios instances — one per backend server via Vite proxy ───────────────────
const s0 = axios.create({ baseURL: '/api0' })
const s1 = axios.create({ baseURL: '/api1' })

// Attach stored access token to every request automatically
;[s0, s1].forEach(instance => {
  instance.interceptors.request.use(cfg => {
    const token = localStorage.getItem('access_token')
    if (token) cfg.headers['Authorization'] = token
    return cfg
  })

  // Surface error messages from the backend clearly
  instance.interceptors.response.use(
    res => res,
    err => {
      const msg =
        err.response?.data?.error ||
        err.response?.data?.message ||
        err.message ||
        'Unknown error'
      err.displayMessage = msg
      return Promise.reject(err)
    }
  )
})

// ── Auth ───────────────────────────────────────────────────────────────────────
export const generateToken = (userId) =>
  s0.post('/generate_token', { user_id: userId })

export const generateQToken = (query) =>
  s0.post('/generate_query_token', { query })

// ── Stats / data ───────────────────────────────────────────────────────────────
export const getStats  = () => s0.get('/stats')
export const viewData  = () => s0.get('/view_data')

// ── Upload ─────────────────────────────────────────────────────────────────────

/**
 * Step 1 — send the file, get back column names + auto-mapping + preview rows.
 * IMPORTANT: do NOT set Content-Type manually — let the browser set it with
 * the correct multipart boundary automatically.
 */
export const uploadPreview = (file) => {
  const form = new FormData()
  form.append('file', file)
  // No Content-Type header — axios + browser handle multipart/form-data + boundary
  return s0.post('/upload/preview', form)
}

/**
 * Step 2 — confirm the column mapping and ingest all valid rows.
 */
export const uploadConfirm = (uploadId, mapping) =>
  s0.post('/upload/confirm', {
    upload_id: uploadId,
    column_mapping: mapping,
  })

/**
 * Download a CSV or Excel template.
 * responseType: 'blob' is required so axios doesn't try to parse binary as JSON.
 */
export const downloadTemplate = (fmt = 'csv') =>
  s0.get(`/upload/template?format=${fmt}`, { responseType: 'blob' })

// ── Queries (server 1) — each auto-fetches a fresh query token ────────────────

/**
 * Wraps a server-1 call with automatic query token generation.
 * fn receives the query token string and must return the axios promise.
 */
const withQToken = async (fn) => {
  const res = await generateQToken('query')
  return fn(res.data.query_token)
}

export const exactMatch = (field, value) =>
  withQToken(qt =>
    s1.post(
      '/exact_match',
      { field, value },
      { headers: { 'Query-Token': qt } }
    )
  )

export const rangeQuery = (minVal, maxVal) =>
  withQToken(qt =>
    s1.post(
      '/range_query',
      { min_value: minVal, max_value: maxVal },
      { headers: { 'Query-Token': qt } }
    )
  )

export const knnQuery = (lat, lon, k = 5) =>
  withQToken(qt =>
    s1.post(
      '/knn_query',
      { latitude: lat, longitude: lon, k },
      { headers: { 'Query-Token': qt } }
    )
  )

export const homomorphicSum = () =>
  withQToken(qt =>
    s1.post(
      '/homomorphic_sum',
      {},
      { headers: { 'Query-Token': qt } }
    )
  )
