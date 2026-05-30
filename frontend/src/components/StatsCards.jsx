import { Users, DollarSign, Activity, Building2 } from 'lucide-react'

const icons = {
  patients: Users,
  billing:  DollarSign,
  conditions: Activity,
  insurers: Building2,
}

export default function StatsCards({ stats, billingSum }) {
  const cards = [
    {
      key: 'patients',
      label: 'Total Patients',
      value: stats?.total_records ?? '—',
      sub: 'Records in encrypted store',
      color: 'bg-blue-50 text-blue-600',
    },
    {
      key: 'billing',
      label: 'Total Billing (Encrypted Sum)',
      value: billingSum != null ? `$${Number(billingSum).toLocaleString(undefined, { maximumFractionDigits: 0 })}` : '—',
      sub: 'Computed via homomorphic addition',
      color: 'bg-green-50 text-green-600',
    },
    {
      key: 'conditions',
      label: 'Unique Conditions',
      value: stats ? Object.keys(stats.conditions_breakdown ?? {}).length : '—',
      sub: 'Distinct medical conditions',
      color: 'bg-purple-50 text-purple-600',
    },
    {
      key: 'insurers',
      label: 'Insurance Providers',
      value: stats ? Object.keys(stats.insurers_breakdown ?? {}).length : '—',
      sub: 'Distinct payers on record',
      color: 'bg-orange-50 text-orange-600',
    },
  ]

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      {cards.map(c => {
        const Icon = icons[c.key]
        return (
          <div key={c.key} className="card p-5 flex items-start gap-4">
            <div className={`p-2 rounded-lg ${c.color}`}>
              <Icon className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{c.value}</p>
              <p className="text-sm font-medium text-gray-700">{c.label}</p>
              <p className="text-xs text-gray-400 mt-0.5">{c.sub}</p>
            </div>
          </div>
        )
      })}
    </div>
  )
}
