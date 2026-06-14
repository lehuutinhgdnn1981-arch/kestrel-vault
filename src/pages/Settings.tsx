import { useState, useEffect } from 'react'
import {
  Sun,
  Moon,
  Monitor,
  ChevronDown,
  X,
  Download,
  Upload,
  FolderOpen,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react'
import { useAuthStore } from '@/stores/auth-store'
import { settingsCommands, authCommands, backupCommands, type AppSettings } from '@/lib/tauri'
import { save, open, message } from '@tauri-apps/plugin-dialog'

const categories = [
  { id: 'general', label: 'General' },
  { id: 'security', label: 'Security' },
  { id: 'autolock', label: 'Auto-lock' },
  { id: 'backup', label: 'Backup' },
  { id: 'advanced', label: 'Advanced' },
]

const Toggle = ({ defaultOn = false, onToggle }: { defaultOn?: boolean; onToggle?: (on: boolean) => void }) => {
  const [on, setOn] = useState(defaultOn)
  const handleToggle = () => {
    const newState = !on
    setOn(newState)
    onToggle?.(newState)
  }
  return (
    <button onClick={handleToggle}
      className="relative w-10 h-[22px] rounded-full transition-colors duration-150 flex-shrink-0"
      style={{ backgroundColor: on ? '#2563EB' : '#CBD5E1' }}>
      <div className="absolute top-[2px] w-[18px] h-[18px] bg-white rounded-full shadow-sm transition-all duration-150"
        style={{ left: on ? '20px' : '2px' }} />
    </button>
  )
}

const Select = ({ options, defaultValue, onChange }: { options: string[]; defaultValue: string; onChange?: (value: string) => void }) => {
  const [value, setValue] = useState(defaultValue)
  const [open, setOpen] = useState(false)
  const handleChange = (opt: string) => {
    setValue(opt)
    setOpen(false)
    onChange?.(opt)
  }
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
              <button key={opt} onClick={() => handleChange(opt)}
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
  const appState = useAuthStore((s) => s.appState)
  const [activeCategory, setActiveCategory] = useState('general')
  const [theme, setTheme] = useState<'light' | 'dark' | 'system'>('dark')
  const [appSettings, setAppSettings] = useState<AppSettings | null>(null)

  // Change password dialog state
  const [showChangePasswordDialog, setShowChangePasswordDialog] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [isChangingPassword, setIsChangingPassword] = useState(false)
  const [changePasswordError, setChangePasswordError] = useState<string | null>(null)
  const [changePasswordSuccess, setChangePasswordSuccess] = useState(false)

  // Load settings on mount when unlocked
  useEffect(() => {
    if (appState !== 'unlocked') return
    const loadSettings = async () => {
      try {
        const settings = await settingsCommands.getSettings()
        setAppSettings(settings)
        setTheme(settings.theme as 'light' | 'dark' | 'system')
      } catch {
        // Silently fail — settings remain null
      }
    }
    loadSettings()
  }, [appState])

  const handleUpdateSettings = async (updates: Partial<AppSettings>) => {
    if (appState !== 'unlocked') return
    try {
      const updated = await settingsCommands.updateSettings(updates)
      setAppSettings(updated)
    } catch {
      // Error handled gracefully
    }
  }

  const handleThemeChange = async (newTheme: 'light' | 'dark' | 'system') => {
    setTheme(newTheme)
    await handleUpdateSettings({ theme: newTheme })
  }

  const handleAutoLockChange = async (value: string) => {
    const minutesMap: Record<string, number> = {
      '5 minutes': 5,
      '15 minutes': 15,
      '30 minutes': 30,
      '1 hour': 60,
      'Never': 0,
    }
    const minutes = minutesMap[value] ?? 15
    await handleUpdateSettings({ auto_lock_minutes: minutes })
  }

  const handleClipboardTimeoutChange = async (value: string) => {
    const secondsMap: Record<string, number> = {
      '30 seconds': 30,
      '1 minute': 60,
      '5 minutes': 300,
      'Never': 0,
    }
    const seconds = secondsMap[value] ?? 30
    await handleUpdateSettings({ clear_clipboard_seconds: seconds })
  }

  const handleChangePassword = async () => {
    if (newPassword !== confirmPassword) {
      setChangePasswordError('Passwords do not match')
      return
    }
    if (!currentPassword || !newPassword) {
      setChangePasswordError('All fields are required')
      return
    }
    setIsChangingPassword(true)
    setChangePasswordError(null)
    setChangePasswordSuccess(false)
    try {
      await authCommands.changePassword(currentPassword, newPassword)
      setChangePasswordSuccess(true)
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setTimeout(() => {
        setShowChangePasswordDialog(false)
        setChangePasswordSuccess(false)
      }, 1500)
    } catch (error) {
      setChangePasswordError(error instanceof Error ? error.message : 'Failed to change password')
    } finally {
      setIsChangingPassword(false)
    }
  }

  // Get the auto-lock display value from settings
  const autoLockDisplayValue = (() => {
    const minutes = appSettings?.auto_lock_minutes ?? 15
    if (minutes === 0) return 'Never'
    if (minutes === 60) return '1 hour'
    return `${minutes} minutes`
  })()

  // Get the clipboard timeout display value from settings
  const clipboardDisplayValue = (() => {
    const seconds = appSettings?.clear_clipboard_seconds ?? 30
    if (seconds === 0) return 'Never'
    if (seconds >= 300) return '5 minutes'
    if (seconds >= 60) return '1 minute'
    return `${seconds} seconds`
  })()

  return (
    <div className="flex h-full animate-fade-in">
      {/* Category Sidebar */}
      <div
        className="flex flex-col h-full flex-shrink-0"
        style={{ width: '200px', borderRight: '1px solid #E2E8F0', backgroundColor: '#FFFFFF' }}
      >
        <div className="p-4">
          <h2 className="text-lg font-semibold mb-4" style={{ color: '#0F172A' }}>Settings</h2>
          <div className="space-y-1">
            {categories.map((cat) => (
              <button key={cat.id} onClick={() => setActiveCategory(cat.id)}
                className="w-full text-left px-3 py-2 rounded-lg text-sm transition-all duration-150"
                style={{
                  backgroundColor: activeCategory === cat.id ? 'rgba(37, 99, 235, 0.1)' : 'transparent',
                  color: activeCategory === cat.id ? '#2563EB' : '#64748B',
                  fontWeight: activeCategory === cat.id ? 500 : 400,
                }}>
                {cat.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Settings Content */}
      <div className="flex-1 overflow-y-auto p-8" style={{ backgroundColor: '#F8FAFC' }}>
        {/* General */}
        {activeCategory === 'general' && (
          <div className="max-w-2xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Vault</h3>
              <div
                className="rounded-xl p-5"
                style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-xs font-medium block mb-1" style={{ color: '#64748B' }}>Vault Name</label>
                    <span className="text-sm" style={{ color: '#0F172A' }}>My KESTREL Vault</span>
                  </div>
                  <button
                    onClick={() => setShowChangePasswordDialog(true)}
                    className="px-4 h-9 rounded-lg text-sm font-medium transition-colors"
                    style={{ backgroundColor: '#FFFFFF', color: '#0F172A', border: '1px solid #E2E8F0' }}
                  >
                    Change Password
                  </button>
                </div>
              </div>
            </section>

            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Appearance</h3>
              <div
                className="rounded-xl p-5 space-y-5"
                style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}
              >
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
                        <button key={t.id} onClick={() => handleThemeChange(t.id)}
                          className="flex flex-col items-center gap-2 px-6 py-4 rounded-xl transition-all duration-150"
                          style={{
                            backgroundColor: isActive ? 'rgba(37, 99, 235, 0.05)' : '#F8FAFC',
                            border: isActive ? '2px solid #2563EB' : '2px solid #E2E8F0',
                          }}>
                          <Icon size={20} style={{ color: isActive ? '#2563EB' : '#64748B' }} />
                          <span className="text-xs font-medium" style={{ color: isActive ? '#2563EB' : '#475569' }}>{t.label}</span>
                        </button>
                      )
                    })}
                  </div>
                </div>

                <div className="flex items-center justify-between pt-3" style={{ borderTop: '1px solid #E2E8F0' }}>
                  <label className="text-sm" style={{ color: '#0F172A' }}>Language</label>
                  <Select options={['English', 'Spanish', 'French', 'German', 'Vietnamese']} defaultValue="English" />
                </div>
              </div>
            </section>

            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Data</h3>
              <div
                className="rounded-xl p-5 space-y-3"
                style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}
              >
                <button
                  className="w-full h-10 rounded-lg text-sm font-medium transition-colors"
                  style={{ backgroundColor: '#F8FAFC', color: '#0F172A', border: '1px solid #E2E8F0' }}
                >
                  Export Vault
                </button>
                <button
                  className="w-full h-10 rounded-lg text-sm font-medium transition-colors"
                  style={{ backgroundColor: '#F8FAFC', color: '#0F172A', border: '1px solid #E2E8F0' }}
                >
                  Import Vault
                </button>
                <button
                  className="w-full h-10 rounded-lg text-sm font-medium transition-colors"
                  style={{ backgroundColor: 'rgba(239, 68, 68, 0.05)', color: '#EF4444', border: '1px solid rgba(239, 68, 68, 0.2)' }}
                >
                  Clear Vault Data
                </button>
              </div>
            </section>
          </div>
        )}

        {/* Security */}
        {activeCategory === 'security' && (
          <div className="max-w-2xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Encryption</h3>
              <div
                className="rounded-xl p-5 space-y-4"
                style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-xs font-medium block mb-0.5" style={{ color: '#64748B' }}>Algorithm</label>
                    <span className="text-sm" style={{ color: '#0F172A' }}>AES-256-GCM</span>
                  </div>
                  <span
                    className="text-xs px-2.5 py-1 rounded-full font-medium"
                    style={{ backgroundColor: 'rgba(34, 197, 94, 0.1)', color: '#22C55E' }}
                  >
                    Active
                  </span>
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
                    <div className="flex items-center gap-3">
                      <span className="text-sm font-medium" style={{ color: '#0F172A' }}>{param.value}</span>
                      <button className="text-xs" style={{ color: '#2563EB' }}>Edit</button>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Master Password</h3>
              <div
                className="rounded-xl p-5"
                style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-xs font-medium block mb-0.5" style={{ color: '#64748B' }}>Last changed</label>
                    <span className="text-sm" style={{ color: '#0F172A' }}>3 months ago</span>
                  </div>
                  <button
                    onClick={() => setShowChangePasswordDialog(true)}
                    className="px-4 h-9 rounded-lg text-sm font-medium transition-colors"
                    style={{ backgroundColor: '#F8FAFC', color: '#0F172A', border: '1px solid #E2E8F0' }}
                  >
                    Change Password
                  </button>
                </div>
              </div>
            </section>
          </div>
        )}

        {/* Auto-lock */}
        {activeCategory === 'autolock' && (
          <div className="max-w-2xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Auto-lock</h3>
              <div
                className="rounded-xl p-5 space-y-5"
                style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Lock after</label>
                    <p className="text-xs" style={{ color: '#64748B' }}>Automatically lock the vault after a period of inactivity</p>
                  </div>
                  <Select options={['5 minutes', '15 minutes', '30 minutes', '1 hour', 'Never']} defaultValue={autoLockDisplayValue} onChange={handleAutoLockChange} />
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
                    <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Lock on window blur</label>
                    <p className="text-xs" style={{ color: '#64748B' }}>Lock when switching to another application</p>
                  </div>
                  <Toggle />
                </div>

                <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid #F1F5F9' }}>
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Clear clipboard after</label>
                    <p className="text-xs" style={{ color: '#64748B' }}>Automatically clear copied passwords from clipboard</p>
                  </div>
                  <Select options={['30 seconds', '1 minute', '5 minutes', 'Never']} defaultValue={clipboardDisplayValue} onChange={handleClipboardTimeoutChange} />
                </div>
              </div>
            </section>
          </div>
        )}

        {/* Backup */}
        {activeCategory === 'backup' && (
          <div className="max-w-2xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Backup & Restore</h3>
              <div
                className="rounded-xl p-5 space-y-5"
                style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}
              >
                {/* Export Backup */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'rgba(37, 99, 235, 0.1)' }}>
                      <Download size={18} style={{ color: '#2563EB' }} />
                    </div>
                    <div>
                      <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Export Backup</label>
                      <p className="text-xs" style={{ color: '#64748B' }}>Create an encrypted backup of your vault</p>
                    </div>
                  </div>
                  <button
                    onClick={async () => {
                      try {
                        const filePath = await save({
                          defaultPath: `kestrel_vault_backup_${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.db`,
                          filters: [{ name: 'Database', extensions: ['db'] }],
                        })
                        if (filePath) {
                          const info = await backupCommands.createBackup(filePath)
                          await message(`Backup created successfully!\n${info.entry_count} entries backed up.\nSize: ${(info.file_size_bytes / 1024).toFixed(1)} KB`, { title: 'Backup Complete', kind: 'info' })
                        }
                      } catch (e: any) {
                        await message(`Backup failed: ${e?.message || e}`, { title: 'Backup Error', kind: 'error' })
                      }
                    }}
                    className="px-4 h-9 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
                    style={{ backgroundColor: '#2563EB', color: '#FFFFFF' }}
                  >
                    <Download size={14} />
                    Export
                  </button>
                </div>

                {/* Import/Restore Backup */}
                <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid #F1F5F9' }}>
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'rgba(34, 197, 94, 0.1)' }}>
                      <Upload size={18} style={{ color: '#22C55E' }} />
                    </div>
                    <div>
                      <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Restore from Backup</label>
                      <p className="text-xs" style={{ color: '#64748B' }}>Replace vault data with a backup file</p>
                    </div>
                  </div>
                  <button
                    onClick={async () => {
                      try {
                        const filePath = await open({
                          filters: [{ name: 'Database', extensions: ['db'] }],
                          multiple: false,
                        })
                        if (filePath) {
                          const confirmed = await message(
                            'Restoring from backup will replace all current vault data. You will need to re-enter your master password. Continue?',
                            { title: 'Confirm Restore', kind: 'warning', okLabel: 'Restore', cancelLabel: 'Cancel' }
                          )
                          if (confirmed) {
                            await backupCommands.restoreBackup(filePath as string)
                            await message('Vault restored successfully. Please unlock with your master password.', { title: 'Restore Complete', kind: 'info' })
                          }
                        }
                      } catch (e: any) {
                        await message(`Restore failed: ${e?.message || e}`, { title: 'Restore Error', kind: 'error' })
                      }
                    }}
                    className="px-4 h-9 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
                    style={{ backgroundColor: '#F8FAFC', color: '#0F172A', border: '1px solid #E2E8F0' }}
                  >
                    <Upload size={14} />
                    Restore
                  </button>
                </div>

                {/* Export Encrypted JSON */}
                <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid #F1F5F9' }}>
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'rgba(139, 92, 246, 0.1)' }}>
                      <FolderOpen size={18} style={{ color: '#8B5CF6' }} />
                    </div>
                    <div>
                      <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Export Encrypted JSON</label>
                      <p className="text-xs" style={{ color: '#64748B' }}>Export vault data as encrypted JSON for migration</p>
                    </div>
                  </div>
                  <button
                    onClick={async () => {
                      try {
                        const filePath = await save({
                          defaultPath: `kestrel_vault_export_${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.json`,
                          filters: [{ name: 'JSON', extensions: ['json'] }],
                        })
                        if (filePath) {
                          const exportData = await backupCommands.exportEncrypted()
                          // Write JSON to file using Tauri FS
                          const { writeFile } = await import('@tauri-apps/plugin-fs')
                          await writeFile(filePath, new TextEncoder().encode(JSON.stringify(exportData, null, 2)))
                          await message('Encrypted export saved successfully.', { title: 'Export Complete', kind: 'info' })
                        }
                      } catch (e: any) {
                        await message(`Export failed: ${e?.message || e}`, { title: 'Export Error', kind: 'error' })
                      }
                    }}
                    className="px-4 h-9 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
                    style={{ backgroundColor: '#F8FAFC', color: '#0F172A', border: '1px solid #E2E8F0' }}
                  >
                    <FolderOpen size={14} />
                    Export JSON
                  </button>
                </div>
              </div>
            </section>

            {/* Backup Info */}
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Backup Information</h3>
              <div
                className="rounded-xl p-5 space-y-4"
                style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}
              >
                <div className="flex items-center gap-3 p-3 rounded-lg" style={{ backgroundColor: 'rgba(37, 99, 235, 0.05)', border: '1px solid rgba(37, 99, 235, 0.1)' }}>
                  <AlertCircle size={16} style={{ color: '#2563EB' }} />
                  <p className="text-xs" style={{ color: '#475569' }}>
                    All backups are encrypted with your master password. You will need your master password to restore from any backup.
                  </p>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg" style={{ backgroundColor: 'rgba(34, 197, 94, 0.05)', border: '1px solid rgba(34, 197, 94, 0.1)' }}>
                  <CheckCircle2 size={16} style={{ color: '#22C55E' }} />
                  <p className="text-xs" style={{ color: '#475569' }}>
                    Backups use the same AES-256-GCM encryption as your vault. Data remains encrypted at all times.
                  </p>
                </div>
              </div>
            </section>
          </div>
        )}

        {/* Advanced */}
        {activeCategory === 'advanced' && (
          <div className="max-w-2xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Advanced</h3>
              <div
                className="rounded-xl p-5 space-y-5"
                style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Debug mode</label>
                    <p className="text-xs" style={{ color: '#64748B' }}>Enable verbose logging for troubleshooting</p>
                  </div>
                  <Toggle />
                </div>

                <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid #F1F5F9' }}>
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Reset all settings</label>
                    <p className="text-xs" style={{ color: '#64748B' }}>Restore default settings (does not delete data)</p>
                  </div>
                  <button
                    className="px-4 h-9 rounded-lg text-sm font-medium transition-colors"
                    style={{ backgroundColor: '#F8FAFC', color: '#0F172A', border: '1px solid #E2E8F0' }}
                  >
                    Reset
                  </button>
                </div>

                <div className="pt-4" style={{ borderTop: '1px solid #F1F5F9' }}>
                  <label className="text-sm block mb-0.5" style={{ color: '#0F172A' }}>Version</label>
                  <p className="text-xs font-mono-geist" style={{ color: '#64748B' }}>KESTREL Vault v1.0.0 (Build 2024.05.20)</p>
                </div>
              </div>
            </section>
          </div>
        )}
      </div>

      {/* Change Password Dialog */}
      {showChangePasswordDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ backgroundColor: 'rgba(0,0,0,0.4)' }}>
          <div className="rounded-xl p-6 w-full max-w-md" style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 8px 30px rgb(0 0 0 / 0.12)' }}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold" style={{ color: '#0F172A' }}>Change Master Password</h3>
              <button onClick={() => { setShowChangePasswordDialog(false); setChangePasswordError(null); setChangePasswordSuccess(false) }}
                className="w-8 h-8 flex items-center justify-center rounded-lg" style={{ color: '#64748B' }}>
                <X size={16} />
              </button>
            </div>

            {changePasswordSuccess ? (
              <div className="p-4 rounded-lg text-center" style={{ backgroundColor: 'rgba(34, 197, 94, 0.1)' }}>
                <p className="text-sm font-medium" style={{ color: '#22C55E' }}>Password changed successfully!</p>
              </div>
            ) : (
              <div className="space-y-4">
                <div>
                  <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Current Password</label>
                  <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)}
                    className="w-full h-9 rounded-lg text-sm outline-none px-3"
                    style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
                </div>
                <div>
                  <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>New Password</label>
                  <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full h-9 rounded-lg text-sm outline-none px-3"
                    style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
                </div>
                <div>
                  <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Confirm New Password</label>
                  <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full h-9 rounded-lg text-sm outline-none px-3"
                    style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
                </div>

                {changePasswordError && (
                  <div className="p-3 rounded-lg text-sm" style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', color: '#EF4444' }}>
                    {changePasswordError}
                  </div>
                )}

                <div className="flex items-center justify-end gap-3 mt-2">
                  <button onClick={() => { setShowChangePasswordDialog(false); setChangePasswordError(null) }}
                    className="px-4 h-9 rounded-lg text-sm font-medium"
                    style={{ backgroundColor: '#F8FAFC', color: '#0F172A', border: '1px solid #E2E8F0' }}>
                    Cancel
                  </button>
                  <button onClick={handleChangePassword} disabled={isChangingPassword || !currentPassword || !newPassword || !confirmPassword}
                    className="px-4 h-9 rounded-lg text-sm font-medium transition-colors"
                    style={{
                      backgroundColor: isChangingPassword || !currentPassword || !newPassword || !confirmPassword ? '#E2E8F0' : '#2563EB',
                      color: isChangingPassword || !currentPassword || !newPassword || !confirmPassword ? '#94A3B8' : '#FFFFFF',
                    }}>
                    {isChangingPassword ? 'Changing...' : 'Change Password'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
