import { useState, useEffect } from 'react'
import { Search, Shield, ChevronRight, AlertTriangle } from 'lucide-react'
import { useAuthStore } from '@/stores/auth-store'
import { scannerCommands, type ScanResultView } from '@/lib/tauri'
import { useI18n } from '@/hooks/use-i18n'

interface ScanRecord {
  id: string
  date: string
  status: 'safe' | 'warning' | 'danger'
  filesScanned: number
  duration: string
  results?: ScanResultView[]
}

export default function ThreatScanner() {
  const { t } = useI18n()
  const appState = useAuthStore((s) => s.appState)

  const statusConfig = {
    safe: { label: t('scanner.noThreatsLabel'), color: 'var(--kestrel-success)', bg: 'var(--kestrel-success-subtle)' },
    warning: { label: t('scanner.suspicious'), color: 'var(--kestrel-warning)', bg: 'var(--kestrel-warning-subtle)' },
    danger: { label: t('scanner.threatDetected'), color: 'var(--kestrel-danger)', bg: 'var(--kestrel-danger-subtle)' },
  }
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [history, setHistory] = useState<ScanRecord[]>([])
  const [scanError, setScanError] = useState<string | null>(null)
  const [lastScanResults, setLastScanResults] = useState<ScanResultView[]>([])

  const handleScan = async () => {
    if (appState !== 'unlocked') return
    setIsScanning(true)
    setScanProgress(0)
    setScanError(null)

    // Start progress animation
    const progressInterval = setInterval(() => {
      setScanProgress((prev) => {
        if (prev >= 90) return prev // Stall at 90% until real result comes back
        return prev + 2
      })
    }, 80)

    try {
      const results = await scannerCommands.runFullScan()
      clearInterval(progressInterval)
      setScanProgress(100)

      const hasThreats = results.length > 0
      const threatLevel = hasThreats
        ? results.some((r) => r.threat_level === 'high' || r.threat_level === 'critical')
          ? 'danger'
          : 'warning'
        : 'safe'

      const newScan: ScanRecord = {
        id: Date.now().toString(),
        date: new Date().toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }),
        status: threatLevel,
        filesScanned: results.length,
        duration: t('scanner.completed'),
        results,
      }
      setHistory((h) => [newScan, ...h])
      setLastScanResults(results)

      // Brief delay to show 100% before resetting
      setTimeout(() => {
        setIsScanning(false)
      }, 500)
    } catch (error) {
      clearInterval(progressInterval)
      setScanError(error instanceof Error ? error.message : t('scanner.scanFailed'))
      setIsScanning(false)
      setScanProgress(0)
    }
  }

  useEffect(() => {
    if (!isScanning) return
    return () => {}
  }, [isScanning])

  // Determine overall threat status for display
  const currentStatus: 'safe' | 'warning' | 'danger' = lastScanResults.length > 0
    ? lastScanResults.some((r) => r.threat_level === 'high' || r.threat_level === 'critical')
      ? 'danger'
      : lastScanResults.some((r) => r.threat_level === 'medium')
        ? 'warning'
        : 'safe'
    : 'safe'

  return (
    <div className="animate-fade-in">
      <div className="p-6 space-y-6">
        {/* Status Hero */}
        <div
          className="rounded-xl p-10 text-center"
          style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
        >
          <div
            className="w-20 h-20 rounded-full flex items-center justify-center mx-auto mb-5"
            style={{
              backgroundColor: isScanning ? 'var(--kestrel-primary-subtle)' : currentStatus === 'safe' ? 'var(--kestrel-success-subtle)' : currentStatus === 'danger' ? 'var(--kestrel-danger-subtle)' : 'var(--kestrel-warning-subtle)',
              animation: isScanning ? 'pulse 2s ease-in-out infinite' : 'none',
            }}
          >
            <Shield size={40} style={{ color: isScanning ? 'var(--kestrel-primary)' : currentStatus === 'safe' ? 'var(--kestrel-success)' : currentStatus === 'danger' ? 'var(--kestrel-danger)' : 'var(--kestrel-warning)' }} />
          </div>

          <h1 className="text-2xl font-semibold mb-2" style={{ color: 'var(--kestrel-text)' }}>
            {isScanning ? t('scanner.scanning') : lastScanResults.length > 0 ? currentStatus === 'safe' ? t('scanner.noThreats') : `${lastScanResults.length} ${t('scanner.issuesDetected')}` : t('scanner.noThreats')}
          </h1>
          <p className="text-sm mb-1" style={{ color: 'var(--kestrel-text-muted)' }}>
            {isScanning ? t('scanner.checkingVault') : lastScanResults.length > 0 && currentStatus !== 'safe' ? t('scanner.reviewIssues') : t('scanner.vaultSafe')}
          </p>
          <p className="text-xs mb-6" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
            {isScanning ? `${Math.round(scanProgress)}% ${t('scanner.complete')}` : history.length > 0 ? `${t('scanner.lastScan')}: ${history[0]?.date}` : t('scanner.runScanToCheck')}
          </p>

          {isScanning && (
            <div className="w-full max-w-md mx-auto h-2 rounded-full mb-6" style={{ backgroundColor: 'var(--kestrel-border-subtle)' }}>
              <div
                className="h-2 rounded-full transition-all duration-100"
                style={{ width: `${scanProgress}%`, backgroundColor: 'var(--kestrel-primary)' }}
              />
            </div>
          )}

          {scanError && (
            <div className="mb-4 p-3 rounded-lg text-sm" style={{ backgroundColor: 'var(--kestrel-danger-subtle)', color: 'var(--kestrel-danger)' }}>
              {scanError}
            </div>
          )}

          <button
            onClick={handleScan}
            disabled={isScanning || appState !== 'unlocked'}
            className="inline-flex items-center gap-2 px-6 h-12 rounded-lg text-sm font-semibold transition-colors duration-150"
            style={{
              backgroundColor: isScanning || appState !== 'unlocked' ? 'var(--kestrel-disabled-bg)' : 'var(--kestrel-primary)',
              color: isScanning || appState !== 'unlocked' ? 'var(--kestrel-disabled-text)' : '#FFFFFF',
              cursor: isScanning || appState !== 'unlocked' ? 'not-allowed' : 'pointer',
            }}
          >
            <Search size={18} />
            {isScanning ? t('scanner.scanning') : t('scanner.runFullScan')}
          </button>

          <div className="mt-3">
            <button className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>{t('scanner.scanSettings')}</button>
          </div>
        </div>

        {/* Scan Results - show details from last scan */}
        {lastScanResults.length > 0 && !isScanning && (
          <div
            className="rounded-xl p-6"
            style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
          >
            <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>{t('scanner.scanFindings')}</h3>
            <div className="space-y-3">
              {lastScanResults.map((result) => {
                const isThreat = result.threat_level === 'high' || result.threat_level === 'critical'
                const isWarning = result.threat_level === 'medium'
                return (
                  <div key={result.id} className="flex items-start gap-3 p-3 rounded-lg" style={{ backgroundColor: 'var(--kestrel-hover-bg)' }}>
                    <div
                      className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5"
                      style={{ backgroundColor: isThreat ? 'var(--kestrel-danger-subtle)' : isWarning ? 'var(--kestrel-warning-subtle)' : 'var(--kestrel-success-subtle)' }}
                    >
                      <AlertTriangle size={16} style={{ color: isThreat ? 'var(--kestrel-danger)' : isWarning ? 'var(--kestrel-warning)' : 'var(--kestrel-success)' }} />
                    </div>
                    <div className="flex-1">
                      <h4 className="text-sm font-medium" style={{ color: 'var(--kestrel-text)' }}>{result.description}</h4>
                      <p className="text-xs mt-1" style={{ color: 'var(--kestrel-text-muted)' }}>{result.recommendation}</p>
                      <span className="inline-block text-xs px-2 py-0.5 rounded-full mt-2"
                        style={{
                          backgroundColor: isThreat ? 'var(--kestrel-danger-subtle)' : isWarning ? 'var(--kestrel-warning-subtle)' : 'var(--kestrel-success-subtle)',
                          color: isThreat ? 'var(--kestrel-danger)' : isWarning ? 'var(--kestrel-warning)' : 'var(--kestrel-success)',
                        }}>
                        {result.threat_level}
                      </span>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Scan History */}
        <div
          className="rounded-xl p-6"
          style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold" style={{ color: 'var(--kestrel-text)' }}>{t('scanner.scanHistory')}</h3>
            <button className="text-xs font-medium" style={{ color: 'var(--kestrel-primary)' }}>{t('scanner.viewAll')}</button>
          </div>

          {history.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-sm" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('scanner.noScanHistory')}</p>
            </div>
          ) : (
            <>
              {/* Table Header */}
              <div
                className="grid items-center px-4 py-2 text-xs font-medium"
                style={{ gridTemplateColumns: '1fr 120px 100px 60px 60px', color: 'var(--kestrel-text-muted)', borderBottom: '1px solid var(--kestrel-border-subtle)' }}
              >
                <span>{t('scanner.date')}</span>
                <span>{t('scanner.status')}</span>
                <span className="text-right">{t('scanner.issues')}</span>
                <span className="text-right">{t('scanner.duration')}</span>
                <span></span>
              </div>

              <div className="divide-y" style={{ borderColor: 'var(--kestrel-border-subtle)' }}>
                {history.map((record) => {
                  const status = statusConfig[record.status]
                  return (
                    <div
                      key={record.id}
                      className="grid items-center px-4 py-3 transition-colors duration-150"
                      style={{
                        gridTemplateColumns: '1fr 120px 100px 60px 60px',
                        backgroundColor: record.status === 'danger' ? 'var(--kestrel-danger-subtle)' : 'transparent',
                      }}
                    >
                      <span className="text-sm" style={{ color: 'var(--kestrel-text)' }}>{record.date}</span>
                      <span
                        className="text-xs px-2.5 py-1 rounded-full inline-flex items-center justify-center font-medium"
                        style={{ backgroundColor: status.bg, color: status.color, width: 'fit-content' }}
                      >
                        {status.label}
                      </span>
                      <span className="text-sm text-right" style={{ color: 'var(--kestrel-text-secondary)' }}>{record.filesScanned}</span>
                      <span className="text-sm text-right" style={{ color: 'var(--kestrel-text-muted)' }}>{record.duration}</span>
                      <button className="flex items-center justify-end" style={{ color: 'var(--kestrel-text-muted)' }}>
                        <ChevronRight size={14} />
                      </button>
                    </div>
                  )
                })}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
