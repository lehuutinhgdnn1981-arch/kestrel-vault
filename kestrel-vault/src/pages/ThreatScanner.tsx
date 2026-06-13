import { useState, useEffect } from 'react'
import { Search, Shield, ChevronRight } from 'lucide-react'

interface ScanRecord {
  id: string
  date: string
  status: 'safe' | 'warning' | 'danger'
  filesScanned: number
  duration: string
}

const scanHistory: ScanRecord[] = [
  { id: '1', date: 'May 20, 2024 10:30 AM', status: 'safe', filesScanned: 342, duration: '45s' },
  { id: '2', date: 'May 19, 2024 09:15 PM', status: 'safe', filesScanned: 340, duration: '43s' },
]

const statusConfig = {
  safe: { label: 'No threats', color: '#22C55E', bg: 'rgba(34, 197, 94, 0.1)' },
  warning: { label: 'Suspicious', color: '#F59E0B', bg: 'rgba(245, 158, 11, 0.1)' },
  danger: { label: '1 threat detected', color: '#EF4444', bg: 'rgba(239, 68, 68, 0.1)' },
}

export default function ThreatScanner() {
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [history, setHistory] = useState<ScanRecord[]>(scanHistory)

  const handleScan = () => {
    setIsScanning(true)
    setScanProgress(0)
  }

  useEffect(() => {
    if (!isScanning) return
    const interval = setInterval(() => {
      setScanProgress((prev) => {
        if (prev >= 100) {
          setIsScanning(false)
          const newScan: ScanRecord = {
            id: Date.now().toString(),
            date: new Date().toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }),
            status: 'safe',
            filesScanned: 342,
            duration: '44s',
          }
          setHistory((h) => [newScan, ...h])
          return 100
        }
        return prev + 2
      })
    }, 80)
    return () => clearInterval(interval)
  }, [isScanning])

  return (
    <div className="animate-fade-in">
      <div className="flex items-center justify-between px-8" style={{ height: '56px', backgroundColor: '#F8FAFC', borderBottom: '1px solid #E2E8F0' }}>
        <h2 className="text-lg font-semibold" style={{ color: '#0F172A' }}>Threat Scanner</h2>
      </div>

      <div className="p-8 max-w-4xl mx-auto space-y-6">
        <div className="rounded-xl p-10 text-center"
          style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}>
          <div className="w-20 h-20 rounded-full flex items-center justify-center mx-auto mb-5"
            style={{ backgroundColor: isScanning ? 'rgba(37, 99, 235, 0.1)' : 'rgba(34, 197, 94, 0.1)' }}>
            <Shield size={40} style={{ color: isScanning ? '#2563EB' : '#22C55E' }} />
          </div>
          <h1 className="text-2xl font-semibold mb-2" style={{ color: '#0F172A' }}>
            {isScanning ? 'Scanning...' : 'No threats found'}
          </h1>
          <p className="text-sm mb-1" style={{ color: '#64748B' }}>
            {isScanning ? 'Checking your files for threats' : 'Your vault is safe'}
          </p>
          <p className="text-xs mb-6" style={{ color: '#94A3B8' }}>
            {isScanning ? `${Math.round(scanProgress)}% complete` : 'Last scan: just now'}
          </p>

          {isScanning && (
            <div className="w-full max-w-md mx-auto h-2 rounded-full mb-6" style={{ backgroundColor: '#F1F5F9' }}>
              <div className="h-2 rounded-full transition-all duration-100"
                style={{ width: `${scanProgress}%`, backgroundColor: '#2563EB' }} />
            </div>
          )}

          <button onClick={handleScan} disabled={isScanning}
            className="inline-flex items-center gap-2 px-6 h-12 rounded-lg text-sm font-semibold transition-colors duration-150"
            style={{ backgroundColor: isScanning ? '#E2E8F0' : '#2563EB', color: isScanning ? '#94A3B8' : '#FFFFFF', cursor: isScanning ? 'not-allowed' : 'pointer' }}>
            <Search size={18} /> {isScanning ? 'Scanning...' : 'Run Full Scan'}
          </button>
        </div>

        <div className="rounded-xl p-6"
          style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold" style={{ color: '#0F172A' }}>Scan History</h3>
          </div>
          <div className="grid items-center px-4 py-2 text-xs font-medium"
            style={{ gridTemplateColumns: '1fr 120px 100px 60px 60px', color: '#64748B', borderBottom: '1px solid #F1F5F9' }}>
            <span>Date</span><span>Status</span><span className="text-right">Files</span><span className="text-right">Duration</span><span></span>
          </div>
          <div className="divide-y" style={{ borderColor: '#F1F5F9' }}>
            {history.map((record) => {
              const status = statusConfig[record.status]
              return (
                <div key={record.id} className="grid items-center px-4 py-3 transition-colors duration-150"
                  style={{ gridTemplateColumns: '1fr 120px 100px 60px 60px', backgroundColor: record.status === 'danger' ? 'rgba(239, 68, 68, 0.03)' : 'transparent' }}>
                  <span className="text-sm" style={{ color: '#0F172A' }}>{record.date}</span>
                  <span className="text-xs px-2.5 py-1 rounded-full inline-flex items-center justify-center font-medium"
                    style={{ backgroundColor: status.bg, color: status.color, width: 'fit-content' }}>
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
        </div>
      </div>
    </div>
  )
}
