import { useState } from 'react'
import { Sun, Moon, Monitor, ChevronDown, Lock, Shield } from 'lucide-react'
import { useAuthStore } from '@/stores/auth-store'

const categories = [
  { id: 'general', label: 'General' },
  { id: 'security', label: 'Security' },
  { id: 'autolock', label: 'Auto-lock' },
  { id: 'backup', label: 'Backup' },
  { id: 'advanced', label: 'Advanced' },
]

const Toggle = ({ defaultOn = false }: { defaultOn?: boolean }) => {
  const [on, setOn] = useState(defaultOn)
  return (
    <button onClick={() => setOn(!on)}
      className="relative w-10 h-[22px] rounded-full transition-colors duration-150 flex-shrink-0"
      style={{ backgroundColor: on ? '#2563EB' : '#CBD5E1' }}>
      <div className="absolute top-[2px] w-[18px] h-[18px] bg-white rounded-full shadow-sm transition-all duration-150"
        style={{ left: on ? '20px' : '2px' }} />
    </button>
  )
}

const Select = ({ options, defaultValue }: { options: string[]; defaultValue: string }) => {
  const [value, setValue] = useState(defaultValue)
  const [open, setOpen] = useState(false)
  return (
    <div className="relative">
      <button onClick={() => setOpen(!open)}
        className="flex items-center justify-between gap-2 px-3 h-9 rounded-lg text-sm min-w-[140px]"
        style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }}>
        {value}
        <ChevronDown size={14} style={{ color: '#64748B' }} />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute top-full left-0 mt-1 w-full rounded-lg py-1 z-20"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}>
            {options.map((opt) => (
              <button key={opt} onClick={() => { setValue(opt); setOpen(false) }}
                className="w-full text-left px-3 py-2 text-sm transition-colors duration-150"
                style={{ backgroundColor: value === opt ? '#F8FAFC' : 'transparent', color: value === opt ? '#0F172A' : '#475569' }}>
                {opt}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

export default function Settings() {
  const [activeCategory, setActiveCategory] = useState('general')
  const [theme, setTheme] = useState<'light' | 'dark' | 'system'>('dark')

  return (
    <div className="flex h-full animate-fade-in">
      <div className="flex flex-col h-full flex-shrink-0"
        style={{ width: '200px', borderRight: '1px solid #E2E8F0', backgroundColor: '#FFFFFF' }}>
        <div className="p-4">
          <h2 className="text-lg font-semibold mb-4" style={{ color: '#0F172A' }}>Settings</h2>
          <div className="space-y-1">
            {categories.map((cat) => (
              <button key={cat.id} onClick={() => setActiveCategory(cat.id)}
                className="w-full text-left px-3 py-2 rounded-lg text-sm transition-all duration-150"
                style={{ backgroundColor: activeCategory === cat.id ? 'rgba(37, 99, 235, 0.1)' : 'transparent', color: activeCategory === cat.id ? '#2563EB' : '#64748B', fontWeight: activeCategory === cat.id ? 500 : 400 }}>
                {cat.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-8" style={{ backgroundColor: '#F8FAFC' }}>
        {activeCategory === 'general' && (
          <div className="max-w-2xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Vault</h3>
              <div className="rounded-xl p-5" style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}>
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-xs font-medium block mb-1" style={{ color: '#64748B' }}>Vault Name</label>
                    <span className="text-sm" style={{ color: '#0F172A' }}>My KESTREL Vault</span>
                  </div>
                  <button className="px-4 h-9 rounded-lg text-sm font-medium transition-colors"
                    style={{ backgroundColor: '#FFFFFF', color: '#0F172A', border: '1px solid #E2E8F0' }}>
                    Change Password
                  </button>
                </div>
              </div>
            </section>
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Appearance</h3>
              <div className="rounded-xl p-5 space-y-5" style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}>
                <div>
                  <label className="text-xs font-medium block mb-3" style={{ color: '#64748B' }}>Theme</label>
                  <div className="flex gap-3">
                    {([
                      { id: 'light' as const, icon: Sun, label: 'Light' },
                      { id: 'dark' as const, icon: Moon, label: 'Dark' },
                      { id: 'system' as const, icon: Monitor, label: 'System' },
                    ]).map((t) => {
                      const Icon = t.icon
                      const isActive = theme === t.id
                      return (
                        <button key={t.id} onClick={() => setTheme(t.id)}
                          className="flex flex-col items-center gap-2 px-6 py-4 rounded-xl transition-all duration-150"
                          style={{ backgroundColor: isActive ? 'rgba(37, 99, 235, 0.05)' : '#F8FAFC', border: isActive ? '2px solid #2563EB' : '2px solid #E2E8F0' }}>
                          <Icon size={20} style={{ color: isActive ? '#2563EB' : '#64748B' }} />
                          <span className="text-xs font-medium" style={{ color: isActive ? '#2563EB' : '#475569' }}>{t.label}</span>
                        </button>
                      )
                    })}
                  </div>
                </div>
              </div>
            </section>
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Data</h3>
              <div className="rounded-xl p-5 space-y-3" style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}>
                <button className="w-full h-10 rounded-lg text-sm font-medium transition-colors"
                  style={{ backgroundColor: '#F8FAFC', color: '#0F172A', border: '1px solid #E2E8F0' }}>Export Vault</button>
                <button className="w-full h-10 rounded-lg text-sm font-medium transition-colors"
                  style={{ backgroundColor: '#F8FAFC', color: '#0F172A', border: '1px solid #E2E8F0' }}>Import Vault</button>
                <button className="w-full h-10 rounded-lg text-sm font-medium transition-colors"
                  style={{ backgroundColor: 'rgba(239, 68, 68, 0.05)', color: '#EF4444', border: '1px solid rgba(239, 68, 68, 0.2)' }}>Clear Vault Data</button>
              </div>
            </section>
          </div>
        )}

        {activeCategory === 'security' && (
          <div className="max-w-2xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Encryption</h3>
              <div className="rounded-xl p-5 space-y-4" style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}>
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-xs font-medium block mb-0.5" style={{ color: '#64748B' }}>Algorithm</label>
                    <span className="text-sm" style={{ color: '#0F172A' }}>AES-256-GCM</span>
                  </div>
                  <span className="text-xs px-2.5 py-1 rounded-full font-medium"
                    style={{ backgroundColor: 'rgba(34, 197, 94, 0.1)', color: '#22C55E' }}>Active</span>
                </div>
                <div className="flex items-center justify-between pt-3" style={{ borderTop: '1px solid #F1F5F9' }}>
                  <div>
                    <label className="text-xs font-medium block mb-0.5" style={{ color: '#64748B' }}>Key Derivation</label>
                    <span className="text-sm" style={{ color: '#0F172A' }}>Argon2id</span>
                  </div>
                </div>
                {[
                  { label: 'Memory', value: '128 MB' },
                  { label: 'Iterations', value: '3' },
                  { label: 'Parallelism', value: 'Auto' },
                ].map((param) => (
                  <div key={param.label} className="flex items-center justify-between pt-3" style={{ borderTop: '1px solid #F1F5F9' }}>
                    <span className="text-sm" style={{ color: '#475569' }}>{param.label}</span>
                    <span className="text-sm font-medium" style={{ color: '#0F172A' }}>{param.value}</span>
                  </div>
                ))}
              </div>
            </section>
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Master Password</h3>
              <div className="rounded-xl p-5" style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}>
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-xs font-medium block mb-0.5" style={{ color: '#64748B' }}>Security</label>
                    <span className="text-sm" style={{ color: '#0F172A' }}>Protected with Argon2id + AES-256</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Lock size={14} style={{ color: '#22C55E' }} />
                    <Shield size={14} style={{ color: '#22C55E' }} />
                  </div>
                </div>
              </div>
            </section>
          </div>
        )}

        {activeCategory === 'autolock' && (
          <div className="max-w-2xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Auto-lock</h3>
              <div className="rounded-xl p-5 space-y-5" style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}>
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Lock after</label>
                    <p className="text-xs" style={{ color: '#64748B' }}>Automatically lock the vault after a period of inactivity</p>
                  </div>
                  <Select options={['5 minutes', '15 minutes', '30 minutes', '1 hour', 'Never']} defaultValue="5 minutes" />
                </div>
                <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid #F1F5F9' }}>
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Lock on system sleep</label>
                    <p className="text-xs" style={{ color: '#64748B' }}>Lock when your computer goes to sleep</p>
                  </div>
                  <Toggle defaultOn />
                </div>
                <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid #F1F5F9' }}>
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Clear clipboard after</label>
                    <p className="text-xs" style={{ color: '#64748B' }}>Automatically clear copied passwords from clipboard</p>
                  </div>
                  <Select options={['30 seconds', '1 minute', '5 minutes', 'Never']} defaultValue="1 minute" />
                </div>
              </div>
            </section>
          </div>
        )}

        {activeCategory === 'backup' && (
          <div className="max-w-2xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Backup</h3>
              <div className="rounded-xl p-5 space-y-5" style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}>
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Automatic backups</label>
                    <p className="text-xs" style={{ color: '#64748B' }}>Create encrypted backups on a schedule</p>
                  </div>
                  <Toggle defaultOn />
                </div>
                <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid #F1F5F9' }}>
                  <label className="text-sm" style={{ color: '#0F172A' }}>Backup frequency</label>
                  <Select options={['Daily', 'Weekly', 'Monthly']} defaultValue="Weekly" />
                </div>
                <div className="pt-4" style={{ borderTop: '1px solid #F1F5F9' }}>
                  <button className="px-6 h-10 rounded-lg text-sm font-medium transition-colors"
                    style={{ backgroundColor: '#2563EB', color: '#FFFFFF' }}>Backup Now</button>
                </div>
              </div>
            </section>
          </div>
        )}

        {activeCategory === 'advanced' && (
          <div className="max-w-2xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Advanced</h3>
              <div className="rounded-xl p-5 space-y-5" style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}>
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Debug mode</label>
                    <p className="text-xs" style={{ color: '#64748B' }}>Enable verbose logging for troubleshooting</p>
                  </div>
                  <Toggle />
                </div>
                <div className="pt-4" style={{ borderTop: '1px solid #F1F5F9' }}>
                  <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Version</label>
                  <p className="text-xs font-mono-geist" style={{ color: '#64748B' }}>KESTREL Vault v0.1.0</p>
                </div>
              </div>
            </section>
          </div>
        )}
      </div>
    </div>
  )
}
