import { useState, useEffect } from 'react'
import {
  CheckCircle,
  AlertTriangle,
  Shield,
  Lock,
  Key,
  ChevronRight,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth-store'
import { useI18n } from '@/hooks/use-i18n'
import { scannerCommands, type SecurityScore, type ScanResultView } from '@/lib/tauri'

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
  const color = score >= 90 ? 'var(--kestrel-success)' : score >= 70 ? 'var(--kestrel-primary)' : score >= 40 ? 'var(--kestrel-warning)' : 'var(--kestrel-danger)'

  return (
    <svg width="180" height="180" viewBox="0 0 180 180">
      <circle cx="90" cy="90" r={r} fill="none" stroke="var(--kestrel-border)" strokeWidth="10" />
      <circle
        cx="90" cy="90" r={r} fill="none" stroke={color} strokeWidth="10"
        strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={offset}
        transform="rotate(-90 90 90)"
        style={{ transition: 'stroke-dashoffset 800ms ease-out' }}
      />
      <text x="90" y="82" textAnchor="middle" fill="var(--kestrel-text)" fontSize="36" fontWeight="600">{score}</text>
      <text x="90" y="102" textAnchor="middle" fill="var(--kestrel-text-muted)" fontSize="13">/100</text>
    </svg>
  )
}

function ClockIcon(props: { size?: number; color?: string }) {
  return (
    <svg width={props.size || 16} height={props.size || 16} viewBox="0 0 24 24" fill="none" stroke={props.color || 'currentColor'} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <polyline points="12,6 12,12 16,14" />
    </svg>
  )
}

const recommendationKeys = [
  { icon: CheckCircle, color: 'var(--kestrel-success)', bg: 'var(--kestrel-success-subtle)', titleKey: 'rec.uniquePasswords' as const, descriptionKey: 'rec.uniquePasswordsDesc' as const },
  { icon: Shield, color: 'var(--kestrel-primary)', bg: 'var(--kestrel-primary-subtle)', titleKey: 'rec.enable2fa' as const, descriptionKey: 'rec.enable2faDesc' as const },
  { icon: Lock, color: 'var(--kestrel-warning)', bg: 'var(--kestrel-warning-subtle)', titleKey: 'rec.changePasswords' as const, descriptionKey: 'rec.changePasswordsDesc' as const },
  { icon: Key, color: 'var(--kestrel-accent-purple)', bg: 'var(--kestrel-purple-subtle)', titleKey: 'rec.useGenerator' as const, descriptionKey: 'rec.useGeneratorDesc' as const },
]

function getIssueIcon(threatLevel: string) {
  if (threatLevel === 'critical') return { icon: AlertTriangle, color: 'var(--kestrel-danger)', bg: 'var(--kestrel-danger-subtle)' }
  if (threatLevel === 'high') return { icon: AlertTriangle, color: 'var(--kestrel-warning)', bg: 'var(--kestrel-warning-subtle)' }
  if (threatLevel === 'medium') return { icon: Shield, color: 'var(--kestrel-primary)', bg: 'var(--kestrel-primary-subtle)' }
  return { icon: ClockIcon, color: 'var(--kestrel-text-muted)', bg: 'var(--kestrel-hover-bg)' }
}

export default function SecurityCenter() {
  const navigate = useNavigate()
  const appState = useAuthStore((s) => s.appState)
  const { t } = useI18n()
  const [securityScore, setSecurityScore] = useState(0)
  const [scoreLabel, setScoreLabel] = useState('security.loading')
  const [scoreBreakdown, setScoreBreakdown] = useState<SecurityScore['breakdown'] | null>(null)
  const [scanResults, setScanResults] = useState<ScanResultView[]>([])
  const [loading, setLoading] = useState(true)

  const fetchSecurityData = async () => {
    if (appState !== 'unlocked') return
    setLoading(true)
    try {
      const [scoreResult, scanResult] = await Promise.all([
        scannerCommands.getSecurityScore(),
        scannerCommands.runFullScan(),
      ])
      setSecurityScore(scoreResult.score)
      setScoreLabel(scoreResult.label)
      setScoreBreakdown(scoreResult.breakdown)
      setScanResults(scanResult)
    } catch {
      setSecurityScore(0)
      setScoreLabel('security.unableToAssess')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchSecurityData()
  }, [appState])

  // Build metrics from score breakdown
  const metrics = scoreBreakdown
    ? [
        { labelKey: 'security.passwordHealth' as const, value: Math.round(scoreBreakdown.password_health), color: scoreBreakdown.password_health >= 80 ? 'var(--kestrel-success)' : scoreBreakdown.password_health >= 50 ? 'var(--kestrel-warning)' : 'var(--kestrel-danger)' },
        { labelKey: 'security.breachStatus' as const, value: Math.round(scoreBreakdown.breach_status), color: scoreBreakdown.breach_status >= 80 ? 'var(--kestrel-success)' : scoreBreakdown.breach_status >= 50 ? 'var(--kestrel-warning)' : 'var(--kestrel-danger)' },
        { labelKey: 'security.vaultHygiene' as const, value: Math.round(scoreBreakdown.vault_hygiene), color: scoreBreakdown.vault_hygiene >= 80 ? 'var(--kestrel-success)' : scoreBreakdown.vault_hygiene >= 50 ? 'var(--kestrel-warning)' : 'var(--kestrel-danger)' },
        { labelKey: 'security.auditCompliance' as const, value: Math.round(scoreBreakdown.audit_compliance), color: scoreBreakdown.audit_compliance >= 80 ? 'var(--kestrel-success)' : scoreBreakdown.audit_compliance >= 50 ? 'var(--kestrel-warning)' : 'var(--kestrel-danger)' },
      ]
    : [
        { labelKey: 'security.passwordHealth' as const, value: 0, color: 'var(--kestrel-text-muted)' },
        { labelKey: 'security.breachStatus' as const, value: 0, color: 'var(--kestrel-text-muted)' },
        { labelKey: 'security.vaultHygiene' as const, value: 0, color: 'var(--kestrel-text-muted)' },
        { labelKey: 'security.auditCompliance' as const, value: 0, color: 'var(--kestrel-text-muted)' },
      ]

  return (
    <div className="animate-fade-in">
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-3 gap-6">
          <div
            className="col-span-1 rounded-xl p-6 flex flex-col items-center"
            style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
          >
            {loading ? (
              <div className="flex flex-col items-center justify-center h-48">
                <div className="w-8 h-8 border-2 border-t-transparent rounded-full animate-spin mb-3" style={{ borderColor: 'var(--kestrel-primary)', borderTopColor: 'transparent' }} />
                <p className="text-sm" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('security.scanning')}</p>
              </div>
            ) : (
              <>
                <SecurityScoreGauge score={securityScore} />
                <p className="text-base font-semibold mt-2" style={{ color: securityScore >= 70 ? 'var(--kestrel-success)' : securityScore >= 40 ? 'var(--kestrel-warning)' : 'var(--kestrel-danger)' }}>{t(scoreLabel as any)}</p>
                <p className="text-sm mt-1" style={{ color: 'var(--kestrel-text-muted)' }}>
                  {securityScore >= 70 ? t('security.keepUpGreatWork') : securityScore >= 40 ? t('security.roomForImprovement') : t('security.actionNeeded')}
                </p>

                <div className="w-full mt-6 space-y-2">
                  {metrics.map((metric) => (
                    <div
                      key={metric.labelKey}
                      className="flex items-center justify-between px-3 py-2 rounded-lg"
                      style={{ backgroundColor: 'var(--kestrel-hover-bg)' }}
                    >
                      <span className="text-xs" style={{ color: 'var(--kestrel-text-secondary)' }}>{t(metric.labelKey)}</span>
                      <span className="text-sm font-semibold" style={{ color: metric.color }}>
                        <AnimatedNumber value={metric.value} />
                      </span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>

          <div
            className="col-span-2 rounded-xl p-6"
            style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <h3 className="text-base font-semibold" style={{ color: 'var(--kestrel-text)' }}>{t('security.issues')}</h3>
                <span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: scanResults.length > 0 ? 'var(--kestrel-badge-warning-bg)' : 'var(--kestrel-badge-success-bg)', color: scanResults.length > 0 ? 'var(--kestrel-badge-warning-text)' : 'var(--kestrel-badge-success-text)' }}>
                  {scanResults.length}
                </span>
              </div>
              <button onClick={() => navigate('/scanner')} className="text-xs font-medium" style={{ color: 'var(--kestrel-primary)' }}>{t('security.runScan')}</button>
            </div>

            <div className="space-y-2">
              {loading ? (
                <div className="flex items-center justify-center py-12">
                  <div className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: 'var(--kestrel-primary)', borderTopColor: 'transparent' }} />
                </div>
              ) : scanResults.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <CheckCircle size={32} style={{ color: 'var(--kestrel-success)' }} className="mb-3" />
                  <p className="text-sm font-medium" style={{ color: 'var(--kestrel-text)' }}>{t('security.noIssues')}</p>
                  <p className="text-xs mt-1" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('security.vaultSecureGreat')}</p>
                </div>
              ) : (
                scanResults.slice(0, 5).map((result) => {
                  const style = getIssueIcon(result.threat_level)
                  const Icon = style.icon
                  return (
                    <div
                      key={result.id}
                      className="flex items-start gap-3 p-3 rounded-lg transition-colors duration-150 cursor-pointer"
                      style={{ backgroundColor: 'var(--kestrel-hover-bg)' }}
                      onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-border-subtle)' }}
                      onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-hover-bg)' }}
                    >
                      <div
                        className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5"
                        style={{ backgroundColor: style.bg }}
                      >
                        <Icon size={16} style={{ color: style.color }} />
                      </div>
                      <div className="flex-1">
                        <h4 className="text-sm font-medium" style={{ color: 'var(--kestrel-text)' }}>{result.description}</h4>
                        <p className="text-xs mt-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>{result.recommendation}</p>
                      </div>
                      <button
                        onClick={() => navigate('/vault')}
                        className="text-xs font-medium flex items-center gap-0.5 flex-shrink-0"
                        style={{ color: 'var(--kestrel-primary)' }}
                      >
                        {t('security.view')} <ChevronRight size={12} />
                      </button>
                    </div>
                  )
                })
              )}
            </div>
          </div>
        </div>

        <div>
          <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>{t('security.recommendations')}</h3>
          <div className="grid grid-cols-2 gap-4">
            {recommendationKeys.map((rec, i) => {
              const Icon = rec.icon
              return (
                <div
                  key={i}
                  className="flex items-start gap-3 p-4 rounded-xl"
                  style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
                >
                  <div
                    className="w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0"
                    style={{ backgroundColor: rec.bg }}
                  >
                    <Icon size={20} style={{ color: rec.color }} />
                  </div>
                  <div>
                    <h4 className="text-sm font-medium" style={{ color: 'var(--kestrel-text)' }}>{t(rec.titleKey)}</h4>
                    <p className="text-xs mt-1" style={{ color: 'var(--kestrel-text-muted)' }}>{t(rec.descriptionKey)}</p>
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
