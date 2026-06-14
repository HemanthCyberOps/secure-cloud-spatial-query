import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldCheck, Lock, User, AlertCircle } from 'lucide-react'
import { generateToken } from '../api/client'

export default function Login() {
  const [userId, setUserId]   = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')
  const navigate = useNavigate()

  const handleLogin = async (e) => {
    e.preventDefault()
    if (!userId.trim()) { setError('Please enter a user ID.'); return }
    setLoading(true)
    setError('')
    try {
      const res = await generateToken(userId.trim())
      localStorage.setItem('access_token', res.data.access_token)
      localStorage.setItem('user_id', userId.trim())
      navigate('/dashboard')
    } catch (err) {
      setError(err.response?.data?.error || 'Could not connect to VaultQuery server. Make sure Server 0 is running.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-brand-900 via-brand-700 to-brand-500 flex items-center justify-center p-4">
      <div className="w-full max-w-md">

        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-white/10 rounded-2xl mb-4 backdrop-blur">
            <ShieldCheck className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-white">VaultQuery</h1>
          <p className="text-brand-100 mt-1 text-sm">Secure Healthcare Analytics Platform</p>
        </div>

        {/* Card */}
        <div className="bg-white rounded-2xl shadow-2xl p-8">
          <h2 className="text-xl font-semibold text-gray-900 mb-1">Sign in</h2>
          <p className="text-sm text-gray-500 mb-6">
            Enter your user ID to access the encrypted data platform.
          </p>

          {error && (
            <div className="flex items-start gap-2 p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700 mb-4">
              <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
              {error}
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">User ID</label>
              <div className="relative">
                <User className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  value={userId}
                  onChange={e => setUserId(e.target.value)}
                  placeholder="e.g. alice, admin, analyst_1"
                  className="input pl-9"
                  autoFocus
                />
              </div>
            </div>

            <button type="submit" disabled={loading} className="btn-primary w-full justify-center py-2.5">
              {loading
                ? 'Authenticating…'
                : <><Lock className="w-4 h-4" /> Sign In Securely</>
              }
            </button>
          </form>

          {/* Info strip */}
          <div className="mt-6 pt-5 border-t border-gray-100">
            <p className="text-xs text-gray-400 text-center">
              All data is encrypted with Paillier Homomorphic Encryption.
              Queries run on ciphertext — plaintext is never exposed to the cloud.
            </p>
          </div>
        </div>

        {/* Quick demo hint */}
        <p className="text-center text-brand-100 text-xs mt-4">
          Demo: type any user ID (e.g. <code className="bg-white/20 px-1 rounded">admin</code>) to sign in
        </p>
      </div>
    </div>
  )
}
