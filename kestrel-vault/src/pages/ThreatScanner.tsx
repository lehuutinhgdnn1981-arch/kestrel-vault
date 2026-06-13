import { useState, useEffect } from 'react'
import { Search, Shield, ChevronRight, AlertTriangle } from 'lucide-react'
import { useAuthStore } from '@/stores/auth-store'
import { scannerCommands, type ScanResultView } from '@/lib/tauri'

interface ScanRecord {
  id: string
  date: string
  status: 'safe' | 'warning' | 'danger'
  filesScanned: number
  duration: string
  results?: ScanResultView[]
}

const statusConfig = {
  safe: { label: 'No threats', color: '#22C55E', bg: 'rgba(34, 197, 94, 0.1)' },
  warning: { label: 'Suspicious', color: '#F59E0B', bg: 'rgba(245, 158, 11, 0.1)' },
  danger: { label: '1 threat detected', color: '#EF4444', bg: 'rgba(239, 68, 68, 0.1)' },
}

export default function ThreatScanner() {
  const appState = useAuthStore((s) => s.appState)
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
        duration: 'Completed',
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
      setScanError(error instanceof Error ? error.message : 'Scan failed')
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
      {/* Top Bar */}
      <div
        className="flex items-center justify-between px-8"
        style={{ height: '56px', backgroundColor: '#F8FAFC', borderBottom: '1px solid #E2E8F0' }}
      >
        <h2 className="text-lg font-semibold" style={{ color: '#0F172A' }}>Threat Scanner</h2>
      </div>

      <div className="p-8 max-w-4xl mx-auto space-y-6">
        {/* Status Hero */}
        <div
          className="rounded-xl p-10 text-center"
          style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}
        >
          <div
            className="w-20 h-20 rounded-full flex items-center justify-center mx-auto mb-5"
            style={{
              backgroundColor: isScanning ? 'rgba(37, 99, 235, 0.1)' : currentStatus === 'safe' ? 'rgba(34, 197, 94, 0.1)' : currentStatus === 'danger' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(245, 158, 11, 0.1)',
              animation: isScanning ? 'pulse 2s ease-in-out infinite' : 'none',
            }}
          >
            <Shield size={40} style={{ color: isScanning ? '#2563EB' : currentStatus === 'safe' ? '#22C55E' : currentStatus === 'danger' ? '#EF4444' : '#F59E0B' }} />
          </div>

          <h1 className="text-2xl font-semibold mb-2" style={{ color: '#0F172A' }}>
            {isScanning ? 'Scanning...' : lastScanResults.length > 0 ? currentStatus === 'safe' ? 'No threats found' : `${lastScanResults.length} issue(s) detected` : 'No threats found'}
          </h1>
          <p className="text-sm mb-1" style={{ color: '#64748B' }}>
            {isScanning ? 'Checking your vault for threats' : lastScanResults.length > 0 && currentStatus !== 'safe' ? 'Review the detected issues below' : 'Your vault is safe'}
          </p>
          <p className="text-xs mb-6" style={{ color: '#94A3B8' }}>
            {isScanning ? `${Math.round(scanProgress)}% complete` : history.length > 0 ? `Last scan: ${history[0].date}` : 'Run a scan to check your vault'}
          </p>

          {isScanning && (
            <div className="w-full max-w-md mx-auto h-2 rounded-full mb-6" style={{ backgroundColor: '#F1F5F9' }}>
              <div
                className="h-2 rounded-full transition-all duration-100"
                style={{ width: `${scanProgress}%`, backgroundColor: '#2563EB' }}
              />
            </div>
          )}

          {scanError && (
            <div className="mb-4 p-3 rounded-lg text-sm" style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', color: '#EF4444' }}>
              {scanError}
            </div>
          )}

          <button
            onClick={handleScan}
            disabled={isScanning || appState !== 'unlocked'}
            className="inline-flex items-center gap-2 px-6 h-12 rounded-lg text-sm font-semibold transition-colors duration-150"
            style={{
              backgroundColor: isScanning || appState !== 'unlocked' ? '#E2E8F0' : '#2563EB',
              color: isScanning || appState !== 'unlocked' ? '#94A3B8' : '#FFFFFF',
              cursor: isScanning || appState !== 'unlocked' ? 'not-allowed' : 'pointer',
            }}
          >
            <Search size={18} />
            {isScanning ? 'Scanning...' : 'Run Full Scan'}
          </button>

          <div className="mt-3">
            <button className="text-xs" style={{ color: '#64748B' }}>Scan Settings</button>
          </div>
        </div>

        {/* Scan Results - show details from last scan */}
        {lastScanResults.length > 0 && !isScanning && (
          <div
            className="rounded-xl p-6"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}
          >
            <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Scan Findings</h3>
            <div className="space-y-3">
              {lastScanResults.map((result) => {
                const isThreat = result.threat_level === 'high' || result.threat_level === 'critical'
                const isWarning = result.threat_level === 'medium'
                return (
                  <div key={result.id} className="flex items-start gap-3 p-3 rounded-lg" style={{ backgroundColor: '#F8FAFC' }}>
                    <div
                      className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5"
                      style={{ backgroundColor: isThreat ? 'rgba(239, 68, 68, 0.1)' : isWarning ? 'rgba(245, 158, 11, 0.1)' : 'rgba(34, 197, 94, 0.1)' }}
                    >
                      <AlertTriangle size={16} style={{ color: isThreat ? '#EF4444' : isWarning ? '#F59E0B' : '#22C55E' }} />
                    </div>
                    <div className="flex-1">
                      <h4 className="text-sm font-medium" style={{ color: '#0F172A' }}>{result.description}</h4>
                      <p className="text-xs mt-1" style={{ color: '#64748B' }}>{result.recommendation}</p>
                      <span className="inline-block text-xs px-2 py-0.5 rounded-full mt-2"
                        style={{
                          backgroundColor: isThreat ? 'rgba(239, 68, 68, 0.1)' : isWarning ? 'rgba(245, 158, 11, 0.1)' : 'rgba(34, 197, 94, 0.1)',
                          color: isThreat ? '#EF4444' : isWarning ? '#F59E0B' : '#22C55E',
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
          style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold" style={{ color: '#0F172A' }}>Scan History</h3>
            <button className="text-xs font-medium" style={{ color: '#2563EB' }}>View all</button>
          </div>

          {history.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-sm" style={{ color: '#94A3B8' }}>No scan history yet. Run your first scan above.</p>
            </div>
          ) : (
            <>
              {/* Table Header */}
              <div
                className="grid items-center px-4 py-2 text-xs font-medium"
                style={{ gridTemplateColumns: '1fr 120px 100px 60px 60px', color: '#64748B', borderBottom: '1px solid #F1F5F9' }}
              >
                <span>Date</span>
                <span>Status</span>
                <span className="text-right">Issues</span>
                <span className="text-right">Duration</span>
                <span></span>
              </div>

              <div className="divide-y" style={{ borderColor: '#F1F5F9' }}>
                {history.map((record) => {
                  const status = statusConfig[record.status]
                  return (
                    <div
                      key={record.id}
                      className="grid items-center px-4 py-3 transition-colors duration-150"
                      style={{
                        gridTemplateColumns: '1fr 120px 100px 60px 60px',
                        backgroundColor: record.status === 'danger' ? 'rgba(239, 68, 68, 0.03)' : 'transparent',
                      }}
                    >
                      <span className="text-sm" style={{ color: '#0F172A' }}>{record.date}</span>
                      <span
                        className="text-xs px-2.5 py-1 rounded-full inline-flex items-center justify-center font-medium"
                        style={{ backgroundColor: status.bg, color: status.color, width: 'fit-content' }}
                      >
                        {status.label}
                      </span>
                      <span className="text-sm text-right" style={{ color: '#475569' }}>{record.filesScanned}</span>
                      <span className="text-sm text-right" style={{ color: '#64748B' }}>{record.duration}</span>
                      <button className="flex items-center justify-end" style={{ color: '#64748B' }}>
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
