import { useState, useEffect } from 'react'
import { Search, CheckCircle, AlertTriangle, Shield, Lock, Key, ChevronRight } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

function AnimatedNumber({ value, duration = 600 }: { value: number; duration?: number }) {
  const [display, setDisplay] = useState(0)
  useEffect(() => {
    const start = performance.now()
    const animate = (now: number) => {
      const elapsed = now - start
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(value * eased))
      if (progress < 1) requestAnimationFrame(animate)
    }
    requestAnimationFrame(animate)
  }, [value, duration])
  return <>{display}</>
}

function SecurityScoreGauge({ score }: { score: number }) {
  const r = 70
  const circumference = 2 * Math.PI * r
  const offset = circumference - (score / 100) * circumference
  const color = score >= 90 ? '#22C55E' : score >= 70 ? '#2563EB' : score >= 40 ? '#F59E0B' : '#EF4444'

  return (
    <svg width="180" height="180" viewBox="0 0 180 180">
      <circle cx="90" cy="90" r={r} fill="none" stroke="#E2E8F0" strokeWidth="10" />
      <circle cx="90" cy="90" r={r} fill="none" stroke={color} strokeWidth="10"
        strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={offset}
        transform="rotate(-90 90 90)" style={{ transition: 'stroke-dashoffset 800ms ease-out' }} />
      <text x="90" y="82" textAnchor="middle" fill="#0F172A" fontSize="36" fontWeight="600">{score}</text>
      <text x="90" y="102" textAnchor="middle" fill="#64748B" fontSize="13">/100</text>
    </svg>
  )
}

const issues = [
  { icon: AlertTriangle, color: '#F59E0B', bg: 'rgba(245, 158, 11, 0.1)', title: 'Update weak passwords', description: '2 passwords are too weak and easy to guess.', count: 2 },
  { icon: AlertTriangle, color: '#F59E0B', bg: 'rgba(245, 158, 11, 0.1)', title: 'Avoid password reuse', description: '3 passwords are reused across multiple sites.', count: 3 },
  { icon: Shield, color: '#2563EB', bg: 'rgba(37, 99, 235, 0.1)', title: 'Enable two-factor authentication', description: '2 accounts support 2FA but it is not enabled.', count: 2 },
]

const recommendations = [
  { icon: CheckCircle, color: '#22C55E', bg: 'rgba(34, 197, 94, 0.1)', title: 'Use unique passwords for each account', description: 'Never reuse the same password across different services.' },
  { icon: Shield, color: '#2563EB', bg: 'rgba(37, 99, 235, 0.1)', title: 'Enable 2FA wherever possible', description: 'Two-factor authentication adds an extra layer of security.' },
  { icon: Lock, color: '#F59E0B', bg: 'rgba(245, 158, 11, 0.1)', title: 'Change passwords every 90 days', description: 'Regular rotation reduces the risk of compromised credentials.' },
  { icon: Key, color: '#8B5CF6', bg: 'rgba(139, 92, 246, 0.1)', title: 'Use the password generator', description: 'Generate strong, random passwords that are hard to crack.' },
]

export default function SecurityCenter() {
  const navigate = useNavigate()
  const securityScore = 87

  return (
    <div className="animate-fade-in">
      <div className="flex items-center justify-between px-8" style={{ height: '56px', backgroundColor: '#F8FAFC', borderBottom: '1px solid #E2E8F0' }}>
        <h2 className="text-lg font-semibold" style={{ color: '#0F172A' }}>Security Center</h2>
      </div>

      <div className="p-8 space-y-6">
        <div className="grid grid-cols-3 gap-6">
          <div className="col-span-1 rounded-xl p-6 flex flex-col items-center"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}>
            <SecurityScoreGauge score={securityScore} />
            <p className="text-base font-semibold mt-2" style={{ color: '#22C55E' }}>Strong</p>
            <p className="text-sm mt-1" style={{ color: '#64748B' }}>Keep up the great work!</p>
            <div className="w-full mt-6 space-y-2">
              {[
                { label: 'Weak Passwords', value: 2, color: '#F59E0B' },
                { label: 'Reused Passwords', value: 3, color: '#F59E0B' },
                { label: 'Exposed Passwords', value: 0, color: '#22C55E' },
              ].map((metric) => (
                <div key={metric.label} className="flex items-center justify-between px-3 py-2 rounded-lg" style={{ backgroundColor: '#F8FAFC' }}>
                  <span className="text-xs" style={{ color: '#475569' }}>{metric.label}</span>
                  <span className="text-sm font-semibold" style={{ color: metric.color }}>
                    <AnimatedNumber value={metric.value} />
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="col-span-2 rounded-xl p-6"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <h3 className="text-base font-semibold" style={{ color: '#0F172A' }}>Issues</h3>
                <span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: '#FEF3C7', color: '#92400E' }}>7</span>
              </div>
            </div>
            <div className="space-y-2">
              {issues.map((issue, i) => {
                const Icon = issue.icon
                return (
                  <div key={i} className="flex items-start gap-3 p-3 rounded-lg transition-colors duration-150 cursor-pointer" style={{ backgroundColor: '#F8FAFC' }}
                    onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = '#F1F5F9' }}
                    onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = '#F8FAFC' }}>
                    <div className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5" style={{ backgroundColor: issue.bg }}>
                      <Icon size={16} style={{ color: issue.color }} />
                    </div>
                    <div className="flex-1">
                      <h4 className="text-sm font-medium" style={{ color: '#0F172A' }}>{issue.title}</h4>
                      <p className="text-xs mt-0.5" style={{ color: '#64748B' }}>{issue.description}</p>
                    </div>
                    <button onClick={() => navigate('/vault')} className="text-xs font-medium flex items-center gap-0.5 flex-shrink-0" style={{ color: '#2563EB' }}>
                      View <ChevronRight size={12} />
                    </button>
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        <div>
          <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Recommendations</h3>
          <div className="grid grid-cols-2 gap-4">
            {recommendations.map((rec, i) => {
              const Icon = rec.icon
              return (
                <div key={i} className="flex items-start gap-3 p-4 rounded-xl"
                  style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}>
                  <div className="w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0" style={{ backgroundColor: rec.bg }}>
                    <Icon size={20} style={{ color: rec.color }} />
                  </div>
                  <div>
                    <h4 className="text-sm font-medium" style={{ color: '#0F172A' }}>{rec.title}</h4>
                    <p className="text-xs mt-1" style={{ color: '#64748B' }}>{rec.description}</p>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
