import { ShieldCheck, LogOut } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

export default function Navbar() {
  const navigate = useNavigate()

  const handleLogout = () => {
    localStorage.clear()
    navigate('/')
  }

  const userId = localStorage.getItem('user_id') || 'User'

  return (
    <header className="bg-brand-900 text-white px-6 py-3 flex items-center justify-between shadow-lg">
      <div className="flex items-center gap-2">
        <ShieldCheck className="w-6 h-6 text-brand-100" />
        <span className="text-lg font-bold tracking-tight">VaultQuery</span>
        <span className="text-brand-100 text-xs ml-2 hidden sm:block">
          Secure Healthcare Analytics
        </span>
      </div>
      <div className="flex items-center gap-4">
        <span className="text-sm text-brand-100">
          Signed in as <span className="font-medium text-white">{userId}</span>
        </span>
        <button onClick={handleLogout} className="flex items-center gap-1 text-sm text-brand-100 hover:text-white transition-colors">
          <LogOut className="w-4 h-4" />
          Logout
        </button>
      </div>
    </header>
  )
}
