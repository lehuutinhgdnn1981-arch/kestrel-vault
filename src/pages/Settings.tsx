import { useState, useEffect } from 'react'
import {
  Sun,
  Moon,
  Monitor,
  ChevronDown,
  X,
  FolderOpen,
  Shield,
  Clock,
  Info,
} from 'lucide-react'
import { useAuthStore } from '@/stores/auth-store'
import { useAppStore } from '@/stores/app-store'
import { settingsCommands, authCommands, vaultDataCommands, type AppSettings } from '@/lib/tauri'
import { open, save } from '@tauri-apps/plugin-dialog'
import { readTextFile, writeTextFile } from '@tauri-apps/plugin-fs'
import { useI18n } from '@/hooks/use-i18n'

const categoryKeys = [
  { id: 'general', labelKey: 'settings.general' as const },
  { id: 'security', labelKey: 'settings.security' as const },
  { id: 'autolock', labelKey: 'settings.autolock' as const },
  { id: 'backup', labelKey: 'settings.backup' as const },
  { id: 'advanced', labelKey: 'settings.advanced' as const },
]

const Toggle = ({ on: controlledOn, onToggle }: { on?: boolean; defaultOn?: boolean; onToggle?: (on: boolean) => void }) => {
  const [internalOn, setInternalOn] = useState(controlledOn ?? false)
  const on = controlledOn !== undefined ? controlledOn : internalOn
  const handleToggle = () => {
    const newState = !on
    if (controlledOn === undefined) {
      setInternalOn(newState)
    }
    onToggle?.(newState)
  }
  return (
    <button onClick={handleToggle}
      className="relative w-10 h-[22px] rounded-full transition-colors duration-150 flex-shrink-0"
      style={{ backgroundColor: on ? 'var(--kestrel-primary)' : 'var(--kestrel-text-light)' }}>
      <div className="absolute top-[2px] w-[18px] h-[18px] bg-white rounded-full shadow-sm transition-all duration-150"
        style={{ left: on ? '20px' : '2px' }} />
    </button>
  )
}

const Select = ({ options, value: controlledValue, defaultValue, onChange }: { options: string[]; value?: string; defaultValue?: string; onChange?: (value: string) => void }) => {
  const [internalValue, setInternalValue] = useState(defaultValue ?? options[0])
  const value = controlledValue !== undefined ? controlledValue : internalValue
  const [isOpen, setIsOpen] = useState(false)
  const handleChange = (opt: string) => {
    if (controlledValue === undefined) {
      setInternalValue(opt)
    }
    setIsOpen(false)
    onChange?.(opt)
  }
  return (
    <div className="relative">
      <button onClick={() => setIsOpen(!isOpen)}
        className="flex items-center justify-between gap-2 px-3 h-9 rounded-lg text-sm min-w-[140px]"
        style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }}>
        {value}
        <ChevronDown size={14} style={{ color: 'var(--kestrel-text-muted)' }} />
      </button>
      {isOpen && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setIsOpen(false)} />
          <div className="absolute top-full left-0 mt-1 w-full rounded-lg py-1 z-20"
            style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}>
            {options.map((opt) => (
              <button key={opt} onClick={() => handleChange(opt)}
                className="w-full text-left px-3 py-2 text-sm transition-colors duration-150"
                style={{ backgroundColor: value === opt ? 'var(--kestrel-bg)' : 'transparent', color: value === opt ? 'var(--kestrel-text)' : 'var(--kestrel-text-secondary)' }}>
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
  const { t } = useI18n()
  const categories = categoryKeys.map(c => ({ id: c.id, label: t(c.labelKey) }))
  const appState = useAuthStore((s) => s.appState)
  const setAutoLockMinutes = useAuthStore((s) => s.setAutoLockMinutes)
  const setAppTheme = useAppStore((s) => s.setTheme)
  const [activeCategory, setActiveCategory] = useState('general')
  const [theme, setTheme] = useState<'light' | 'dark' | 'system'>('dark')
  const [appSettings, setAppSettings] = useState<AppSettings | null>(null)
  const [settingsLoading, setSettingsLoading] = useState(true)
  const [settingsError, setSettingsError] = useState<string | null>(null)

  // Change password dialog state
  const [showChangePasswordDialog, setShowChangePasswordDialog] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [isChangingPassword, setIsChangingPassword] = useState(false)
  const [changePasswordError, setChangePasswordError] = useState<string | null>(null)
  const [changePasswordSuccess, setChangePasswordSuccess] = useState(false)

  // Feedback messages for vault operations
  const [feedbackMessage, setFeedbackMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [isVaultBusy, setIsVaultBusy] = useState(false)

  // Backup state
  const [isBackingUp, setIsBackingUp] = useState(false)
  const [lastBackupPath, setLastBackupPath] = useState<string | null>(null)

  const showFeedback = (type: 'success' | 'error', text: string) => {
    setFeedbackMessage({ type, text })
    setTimeout(() => setFeedbackMessage(null), 3000)
  }

  // Load settings on mount when unlocked
  useEffect(() => {
    if (appState !== 'unlocked') return
    const loadSettings = async () => {
      setSettingsLoading(true)
      setSettingsError(null)
      try {
        const settings = await settingsCommands.getSettings()
        setAppSettings(settings)
        setTheme(settings.theme as 'light' | 'dark' | 'system')
        // Sync auto-lock minutes with auth store on load
        setAutoLockMinutes(settings.auto_lock_minutes)
        // Apply theme to DOM on load
        setAppTheme(settings.theme as 'light' | 'dark' | 'system')
      } catch (err) {
        const msg = err instanceof Error ? err.message : t('settings.failedToLoad')
        setSettingsError(msg)
      } finally {
        setSettingsLoading(false)
      }
    }
    loadSettings()
  }, [appState, setAutoLockMinutes, setAppTheme])

  const handleUpdateSettings = async (updates: Partial<AppSettings>) => {
    if (appState !== 'unlocked') return
    try {
      const updated = await settingsCommands.updateSettings(updates)
      setAppSettings(updated)
      setSettingsError(null)
      return updated
    } catch (err) {
      const msg = err instanceof Error ? err.message : t('feedback.failedToUpdate')
      showFeedback('error', msg)
      return null
    }
  }

  const handleThemeChange = async (newTheme: 'light' | 'dark' | 'system') => {
    setTheme(newTheme)
    // Apply theme to DOM immediately for visual feedback
    setAppTheme(newTheme)
    const result = await handleUpdateSettings({ theme: newTheme })
    if (!result) {
      // Revert on failure
      const currentTheme = appSettings?.theme as 'light' | 'dark' | 'system' ?? 'dark'
      setTheme(currentTheme)
      setAppTheme(currentTheme)
    } else {
      showFeedback('success', t('feedback.themeChanged', { theme: newTheme }))
    }
  }

  const handleAutoLockChange = async (value: string) => {
    const minutesMap: Record<string, number> = {
      [t('settings.5minutes')]: 5,
      [t('settings.15minutes')]: 15,
      [t('settings.30minutes')]: 30,
      [t('settings.1hour')]: 60,
      [t('settings.never')]: 0,
    }
    const minutes = minutesMap[value] ?? 15
    const result = await handleUpdateSettings({ auto_lock_minutes: minutes })
    if (result) {
      // Sync with auth store for auto-lock hook
      setAutoLockMinutes(minutes)
      showFeedback('success', t('feedback.autoLockSet', { value }))
    }
  }

  const handleClipboardTimeoutChange = async (value: string) => {
    const secondsMap: Record<string, number> = {
      [t('settings.30seconds')]: 30,
      [t('settings.1minute')]: 60,
      [t('settings.5minutes')]: 300,
      [t('settings.never')]: 0,
    }
    const seconds = secondsMap[value] ?? 30
    const result = await handleUpdateSettings({ clear_clipboard_seconds: seconds })
    if (result) {
      showFeedback('success', t('feedback.clipboardSet', { value }))
    }
  }

  const handleLanguageChange = async (value: string) => {
    const langMap: Record<string, string> = {
      'English': 'en',
      'Vietnamese': 'vi',
      'Spanish': 'es',
      'French': 'fr',
      'German': 'de',
    }
    const lang = langMap[value] ?? 'en'
    const result = await handleUpdateSettings({ language: lang })
    if (result) {
      // Actually switch the UI language immediately
      useAppStore.getState().setLanguage(lang as 'en' | 'vi')
      showFeedback('success', t('feedback.languageSaved'))
    }
  }

  const handleBackupFrequencyChange = async (value: string) => {
    const freqMap: Record<string, string> = {
      'Daily': 'daily',
      'Weekly': 'weekly',
      'Monthly': 'monthly',
    }
    const freq = freqMap[value] ?? 'weekly'
    const result = await handleUpdateSettings({ backup_frequency: freq })
    if (result) {
      showFeedback('success', `Backup frequency set to ${value.toLowerCase()}`)
    }
  }

  const handleBackupNow = async () => {
    setIsBackingUp(true)
    try {
      const backupPath = await vaultDataCommands.createBackup()
      setLastBackupPath(backupPath)
      showFeedback('success', `Backup created: ${backupPath}`)
    } catch (error) {
      showFeedback('error', error instanceof Error ? error.message : 'Backup failed')
    } finally {
      setIsBackingUp(false)
    }
  }

  const handleBrowseBackupLocation = async () => {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
      })
      if (selected) {
        const result = await handleUpdateSettings({ backup_location: selected as string })
        if (result) {
          showFeedback('success', 'Backup location updated')
        }
      }
    } catch {
      // User cancelled or error
    }
  }

  const handleResetSettings = async () => {
    if (!window.confirm('Reset all settings to defaults? This does not delete vault data.')) return
    try {
      const reset = await settingsCommands.resetSettings()
      setAppSettings(reset)
      setTheme(reset.theme as 'light' | 'dark' | 'system')
      // Apply reset theme to DOM
      setAppTheme(reset.theme as 'light' | 'dark' | 'system')
      // Sync auto-lock minutes with auth store on reset
      setAutoLockMinutes(reset.auto_lock_minutes)
      showFeedback('success', 'Settings reset to defaults')
    } catch (error) {
      showFeedback('error', error instanceof Error ? error.message : 'Failed to reset settings')
    }
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
    if (newPassword.length < 8) {
      setChangePasswordError('New password must be at least 8 characters')
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

  // Get the language display value from settings
  const languageDisplayValue = (() => {
    const lang = appSettings?.language ?? 'en'
    const langDisplayMap: Record<string, string> = {
      'en': 'English',
      'es': 'Spanish',
      'fr': 'French',
      'de': 'German',
      'vi': 'Vietnamese',
    }
    return langDisplayMap[lang] ?? 'English'
  })()

  // Get the backup frequency display value from settings
  const backupFrequencyDisplayValue = (() => {
    const freq = appSettings?.backup_frequency ?? 'weekly'
    const freqDisplayMap: Record<string, string> = {
      'daily': 'Daily',
      'weekly': 'Weekly',
      'monthly': 'Monthly',
    }
    return freqDisplayMap[freq] ?? 'Weekly'
  })()

  return (
    <div className="flex h-full">
      {/* Category Sidebar */}
      <div
        className="flex flex-col h-full flex-shrink-0"
        style={{ width: '200px', borderRight: '1px solid var(--kestrel-border)', backgroundColor: 'var(--kestrel-surface)' }}
      >
        <div className="p-4">
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>{t('settings.title')}</h2>
          <div className="space-y-1">
            {categories.map((cat) => (
              <button key={cat.id} onClick={() => setActiveCategory(cat.id)}
                className="w-full text-left px-3 py-2 rounded-lg text-sm transition-all duration-150"
                style={{
                  backgroundColor: activeCategory === cat.id ? 'var(--kestrel-primary-subtle)' : 'transparent',
                  color: activeCategory === cat.id ? 'var(--kestrel-primary)' : 'var(--kestrel-text-muted)',
                  fontWeight: activeCategory === cat.id ? 500 : 400,
                }}>
                {cat.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Settings Content */}
      <div className="flex-1 overflow-y-auto p-8" style={{ backgroundColor: 'var(--kestrel-bg)' }}>
        {/* Loading state */}
        {settingsLoading && (
          <div className="flex items-center justify-center h-64">
            <div className="text-center">
              <div className="mx-auto h-6 w-6 animate-spin rounded-full border-2 border-t-transparent" style={{ borderColor: 'var(--kestrel-text-light)', borderTopColor: 'transparent' }} />
              <p className="mt-3 text-sm" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>Loading settings...</p>
            </div>
          </div>
        )}

        {/* Error state */}
        {settingsError && !settingsLoading && (
          <div className="max-w-3xl">
            <div className="rounded-xl p-5" style={{ backgroundColor: 'var(--kestrel-danger-subtle)', border: '1px solid var(--kestrel-danger-subtle-border)' }}>
              <p className="text-sm font-medium" style={{ color: 'var(--kestrel-danger)' }}>Failed to load settings</p>
              <p className="text-xs mt-1" style={{ color: 'var(--kestrel-text-muted)' }}>{settingsError}</p>
              <button
                onClick={() => {
                  setSettingsLoading(true)
                  setSettingsError(null)
                  settingsCommands.getSettings()
                    .then((settings) => {
                      setAppSettings(settings)
                      setTheme(settings.theme as 'light' | 'dark' | 'system')
                      setAutoLockMinutes(settings.auto_lock_minutes)
                      setAppTheme(settings.theme as 'light' | 'dark' | 'system')
                    })
                    .catch((err) => setSettingsError(err instanceof Error ? err.message : 'Failed to load settings'))
                    .finally(() => setSettingsLoading(false))
                }}
                className="mt-3 px-4 h-8 rounded-lg text-sm font-medium"
                style={{ backgroundColor: 'var(--kestrel-surface)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}
              >
                Retry
              </button>
            </div>
          </div>
        )}

        {/* Settings content — only show when loaded */}
        {!settingsLoading && !settingsError && (
        <>
        {/* Feedback banner */}
        {feedbackMessage && (
          <div className="mb-4 p-3 rounded-lg text-sm"
            style={{
              backgroundColor: feedbackMessage.type === 'success' ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
              color: feedbackMessage.type === 'success' ? 'var(--kestrel-success)' : 'var(--kestrel-danger)',
            }}>
            {feedbackMessage.text}
          </div>
        )}

        {/* General */}
        {activeCategory === 'general' && (
          <div className="max-w-3xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>{t('settings.vault')}</h3>
              <div
                className="rounded-xl p-5"
                style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)' }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-xs font-medium block mb-1" style={{ color: 'var(--kestrel-text-muted)' }}>Vault Name</label>
                    <span className="text-sm" style={{ color: 'var(--kestrel-text)' }}>My KESTREL Vault</span>
                  </div>
                  <button
                    onClick={() => setShowChangePasswordDialog(true)}
                    className="px-4 h-9 rounded-lg text-sm font-medium transition-colors"
                    style={{ backgroundColor: 'var(--kestrel-surface)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}
                  >
                    Change Password
                  </button>
                </div>
              </div>
            </section>

            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>{t('settings.appearance')}</h3>
              <div
                className="rounded-xl p-5 space-y-5"
                style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)' }}
              >
                <div>
                  <label className="text-xs font-medium block mb-3" style={{ color: 'var(--kestrel-text-muted)' }}>{t('settings.theme')}</label>
                  <div className="flex gap-3">
                    {([
                      { id: 'light' as const, icon: Sun, label: t('settings.light') },
                      { id: 'dark' as const, icon: Moon, label: t('settings.dark') },
                      { id: 'system' as const, icon: Monitor, label: t('settings.system') },
                    ]).map((themeOpt) => {
                      const Icon = themeOpt.icon
                      const isActive = theme === themeOpt.id
                      return (
                        <button key={themeOpt.id} onClick={() => handleThemeChange(themeOpt.id)}
                          className="flex flex-col items-center gap-2 px-6 py-4 rounded-xl transition-all duration-150"
                          style={{
                            backgroundColor: isActive ? 'var(--kestrel-selected-bg)' : 'var(--kestrel-hover-bg)',
                            border: isActive ? '2px solid var(--kestrel-primary)' : '2px solid var(--kestrel-border)',
                          }}>
                          <Icon size={20} style={{ color: isActive ? 'var(--kestrel-primary)' : 'var(--kestrel-text-muted)' }} />
                          <span className="text-xs font-medium" style={{ color: isActive ? 'var(--kestrel-primary)' : 'var(--kestrel-text-secondary)' }}>{themeOpt.label}</span>
                        </button>
                      )
                    })}
                  </div>
                </div>

                <div className="flex items-center justify-between pt-3" style={{ borderTop: '1px solid var(--kestrel-border)' }}>
                  <div>
                    <label className="text-sm" style={{ color: 'var(--kestrel-text)' }}>{t('settings.language')}</label>
                    <p className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>UI language preference (saved for future updates)</p>
                  </div>
                  <Select options={['English', 'Vietnamese', 'Spanish', 'French', 'German']} value={languageDisplayValue} onChange={handleLanguageChange} />
                </div>
              </div>
            </section>

            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>{t('settings.data')}</h3>
              <div
                className="rounded-xl p-5 space-y-3"
                style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)' }}
              >
                <button
                  onClick={async () => {
                    try {
                      setIsVaultBusy(true)
                      const data = await vaultDataCommands.exportVault()
                      const filePath = await save({
                        defaultPath: 'kestrel-vault-export.json',
                        filters: [{ name: 'JSON', extensions: ['json'] }],
                      })
                      if (filePath) {
                        await writeTextFile(filePath, data)
                        showFeedback('success', 'Vault exported successfully')
                      }
                    } catch (error) {
                      showFeedback('error', error instanceof Error ? error.message : 'Export failed')
                    } finally {
                      setIsVaultBusy(false)
                    }
                  }}
                  disabled={isVaultBusy}
                  className="w-full h-10 rounded-lg text-sm font-medium transition-colors"
                  style={{ backgroundColor: 'var(--kestrel-bg)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}
                >
                  {isVaultBusy ? 'Exporting...' : 'Export Vault'}
                </button>
                <button
                  onClick={async () => {
                    try {
                      setIsVaultBusy(true)
                      const filePath = await open({
                        filters: [{ name: 'JSON', extensions: ['json'] }],
                        multiple: false,
                      })
                      if (filePath) {
                        const data = await readTextFile(filePath as string)
                        await vaultDataCommands.importVault(data)
                        showFeedback('success', 'Vault imported successfully')
                      }
                    } catch (error) {
                      showFeedback('error', error instanceof Error ? error.message : 'Import failed')
                    } finally {
                      setIsVaultBusy(false)
                    }
                  }}
                  disabled={isVaultBusy}
                  className="w-full h-10 rounded-lg text-sm font-medium transition-colors"
                  style={{ backgroundColor: 'var(--kestrel-bg)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}
                >
                  {isVaultBusy ? 'Importing...' : 'Import Vault'}
                </button>
                <button
                  onClick={async () => {
                    if (!window.confirm('This will permanently delete ALL vault data. This action cannot be undone. Are you sure?')) return
                    try {
                      setIsVaultBusy(true)
                      await vaultDataCommands.clearVault(true)
                      showFeedback('success', 'Vault data cleared')
                    } catch (error) {
                      showFeedback('error', error instanceof Error ? error.message : 'Failed to clear vault')
                    } finally {
                      setIsVaultBusy(false)
                    }
                  }}
                  disabled={isVaultBusy}
                  className="w-full h-10 rounded-lg text-sm font-medium transition-colors"
                  style={{ backgroundColor: 'var(--kestrel-danger-subtle)', color: 'var(--kestrel-danger)', border: '1px solid var(--kestrel-danger-subtle-border)' }}
                >
                  {isVaultBusy ? 'Clearing...' : 'Clear Vault Data'}
                </button>
              </div>
            </section>
          </div>
        )}

        {/* Security */}
        {activeCategory === 'security' && (
          <div className="max-w-3xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>{t('settings.encryption')}</h3>
              <div
                className="rounded-xl p-5 space-y-4"
                style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)' }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-xs font-medium block mb-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>{t('settings.algorithm')}</label>
                    <span className="text-sm font-medium" style={{ color: 'var(--kestrel-text)' }}>AES-256-GCM</span>
                  </div>
                  <span
                    className="text-xs px-2.5 py-1 rounded-full font-medium"
                    style={{ backgroundColor: 'var(--kestrel-success-subtle)', color: 'var(--kestrel-success)' }}
                  >
                    Active
                  </span>
                </div>

                <div className="flex items-center justify-between pt-3" style={{ borderTop: '1px solid var(--kestrel-border-subtle)' }}>
                  <div>
                    <label className="text-xs font-medium block mb-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>Key Derivation</label>
                    <span className="text-sm font-medium" style={{ color: 'var(--kestrel-text)' }}>Argon2id</span>
                  </div>
                  <span
                    className="text-xs px-2.5 py-1 rounded-full font-medium"
                    style={{ backgroundColor: 'var(--kestrel-success-subtle)', color: 'var(--kestrel-success)' }}
                  >
                    Active
                  </span>
                </div>

                <div className="pt-3" style={{ borderTop: '1px solid var(--kestrel-border-subtle)' }}>
                  <p className="text-xs font-medium mb-2" style={{ color: 'var(--kestrel-text-muted)' }}>KDF Parameters</p>
                  <div className="grid grid-cols-3 gap-3">
                    <div className="rounded-lg p-3 text-center" style={{ backgroundColor: 'var(--kestrel-bg)' }}>
                      <p className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>{t('settings.memory')}</p>
                      <p className="text-sm font-semibold mt-0.5" style={{ color: 'var(--kestrel-text)' }}>256 MB</p>
                    </div>
                    <div className="rounded-lg p-3 text-center" style={{ backgroundColor: 'var(--kestrel-bg)' }}>
                      <p className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>{t('settings.iterations')}</p>
                      <p className="text-sm font-semibold mt-0.5" style={{ color: 'var(--kestrel-text)' }}>3</p>
                    </div>
                    <div className="rounded-lg p-3 text-center" style={{ backgroundColor: 'var(--kestrel-bg)' }}>
                      <p className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>{t('settings.parallelism')}</p>
                      <p className="text-sm font-semibold mt-0.5" style={{ color: 'var(--kestrel-text)' }}>4</p>
                    </div>
                  </div>
                  <p className="text-xs mt-2" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
                    KDF parameters are set during vault initialization and cannot be changed without re-creating the vault.
                  </p>
                </div>
              </div>
            </section>

            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>Brute-Force Protection</h3>
              <div
                className="rounded-xl p-5 space-y-4"
                style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)' }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-xs font-medium block mb-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>Max Login Attempts</label>
                    <span className="text-sm font-medium" style={{ color: 'var(--kestrel-text)' }}>
                      {appSettings?.max_login_attempts ?? 5} attempts
                    </span>
                  </div>
                  <Shield size={16} style={{ color: 'var(--kestrel-success)' }} />
                </div>

                <div className="flex items-center justify-between pt-3" style={{ borderTop: '1px solid var(--kestrel-border-subtle)' }}>
                  <div>
                    <label className="text-xs font-medium block mb-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>Lockout Duration</label>
                    <span className="text-sm font-medium" style={{ color: 'var(--kestrel-text)' }}>
                      {appSettings?.lockout_duration_seconds ?? 300} seconds ({Math.floor((appSettings?.lockout_duration_seconds ?? 300) / 60)} min)
                    </span>
                  </div>
                  <Clock size={16} style={{ color: 'var(--kestrel-warning)' }} />
                </div>

                <div className="pt-3" style={{ borderTop: '1px solid var(--kestrel-border-subtle)' }}>
                  <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--kestrel-primary-subtle)', border: '1px solid var(--kestrel-primary-subtle)' }}>
                    <div className="flex items-start gap-2">
                      <Info size={14} style={{ color: 'var(--kestrel-primary)', marginTop: '2px' }} />
                      <div>
                        <p className="text-xs font-medium" style={{ color: 'var(--kestrel-primary)' }}>Lockout Progression</p>
                        <p className="text-xs mt-1" style={{ color: 'var(--kestrel-text-secondary)' }}>
                          1-3 failed attempts: Immediate retry allowed.
                        </p>
                        <p className="text-xs" style={{ color: 'var(--kestrel-text-secondary)' }}>
                          4-5 failed attempts: Exponential backoff (2s, 4s delay).
                        </p>
                        <p className="text-xs" style={{ color: 'var(--kestrel-text-secondary)' }}>
                          6+ failed attempts: Full lockout requiring vault reset.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>Rate Limiting</h3>
              <div
                className="rounded-xl p-5 space-y-4"
                style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)' }}
              >
                {[
                  { label: 'Login Attempts', value: '5 per 5 minutes', color: 'var(--kestrel-danger)' },
                  { label: 'Vault Commands', value: '60 per minute', color: 'var(--kestrel-primary)' },
                  { label: 'File Operations', value: '20 per minute', color: 'var(--kestrel-warning)' },
                ].map((item, i) => (
                  <div key={item.label} className={i > 0 ? 'pt-3' : ''} style={i > 0 ? { borderTop: '1px solid var(--kestrel-border-subtle)' } : {}}>
                    <div className="flex items-center justify-between">
                      <div>
                        <label className="text-xs font-medium block mb-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>{item.label}</label>
                        <span className="text-sm" style={{ color: 'var(--kestrel-text)' }}>{item.value}</span>
                      </div>
                      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                    </div>
                  </div>
                ))}
                <p className="text-xs pt-2" style={{ color: 'var(--kestrel-text-on-dark-muted)', borderTop: '1px solid var(--kestrel-border-subtle)' }}>
                  Rate limits protect against automated attacks. Sliding window algorithm resets after the time window passes.
                </p>
              </div>
            </section>

            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>Master Password</h3>
              <div
                className="rounded-xl p-5"
                style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)' }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-xs font-medium block mb-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>Last changed</label>
                    <span className="text-sm" style={{ color: 'var(--kestrel-text)' }}>Set during vault initialization</span>
                  </div>
                  <button
                    onClick={() => setShowChangePasswordDialog(true)}
                    className="px-4 h-9 rounded-lg text-sm font-medium transition-colors"
                    style={{ backgroundColor: 'var(--kestrel-bg)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}
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
          <div className="max-w-3xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>Auto-lock</h3>
              <div
                className="rounded-xl p-5 space-y-5"
                style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)' }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: 'var(--kestrel-text)' }}>Lock after</label>
                    <p className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>Automatically lock the vault after a period of inactivity</p>
                  </div>
                  <Select options={['5 minutes', '15 minutes', '30 minutes', '1 hour', 'Never']} value={autoLockDisplayValue} onChange={handleAutoLockChange} />
                </div>

                <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid var(--kestrel-border-subtle)' }}>
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: 'var(--kestrel-text)' }}>Lock on system sleep</label>
                    <p className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>Lock when your computer goes to sleep</p>
                  </div>
                  <Toggle on={appSettings?.lock_on_sleep ?? true} onToggle={(val) => { handleUpdateSettings({ lock_on_sleep: val }); showFeedback('success', val ? 'Lock on sleep enabled' : 'Lock on sleep disabled') }} />
                </div>

                <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid var(--kestrel-border-subtle)' }}>
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: 'var(--kestrel-text)' }}>Lock on window blur</label>
                    <p className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>Lock when switching to another application</p>
                  </div>
                  <Toggle on={appSettings?.lock_on_blur ?? false} onToggle={(val) => { handleUpdateSettings({ lock_on_blur: val }); showFeedback('success', val ? 'Lock on blur enabled' : 'Lock on blur disabled') }} />
                </div>

                <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid var(--kestrel-border-subtle)' }}>
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: 'var(--kestrel-text)' }}>Clear clipboard after</label>
                    <p className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>Automatically clear copied passwords from clipboard</p>
                  </div>
                  <Select options={['30 seconds', '1 minute', '5 minutes', 'Never']} value={clipboardDisplayValue} onChange={handleClipboardTimeoutChange} />
                </div>
              </div>
            </section>
          </div>
        )}

        {/* Backup */}
        {activeCategory === 'backup' && (
          <div className="max-w-3xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>{t('settings.backup')}</h3>
              <div
                className="rounded-xl p-5 space-y-5"
                style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)' }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: 'var(--kestrel-text)' }}>Automatic backups</label>
                    <p className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>Create encrypted backups on a schedule</p>
                  </div>
                  <Toggle on={appSettings?.auto_backup ?? true} onToggle={(val) => { handleUpdateSettings({ auto_backup: val }); showFeedback('success', val ? 'Auto-backup enabled' : 'Auto-backup disabled') }} />
                </div>

                <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid var(--kestrel-border-subtle)' }}>
                  <label className="text-sm" style={{ color: 'var(--kestrel-text)' }}>Backup location</label>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono-geist px-3 py-1.5 rounded max-w-[200px] truncate" style={{ backgroundColor: 'var(--kestrel-bg)', color: 'var(--kestrel-text-secondary)' }}>
                      {appSettings?.backup_location ?? '~/Backups/KESTREL'}
                    </span>
                    <button onClick={handleBrowseBackupLocation} className="text-xs flex items-center gap-1" style={{ color: 'var(--kestrel-primary)' }}>
                      <FolderOpen size={12} /> Browse
                    </button>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid var(--kestrel-border-subtle)' }}>
                  <label className="text-sm" style={{ color: 'var(--kestrel-text)' }}>Backup frequency</label>
                  <Select options={['Daily', 'Weekly', 'Monthly']} value={backupFrequencyDisplayValue} onChange={handleBackupFrequencyChange} />
                </div>

                <div className="pt-4" style={{ borderTop: '1px solid var(--kestrel-border-subtle)' }}>
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <label className="text-xs font-medium block mb-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>Last backup</label>
                      <span className="text-sm" style={{ color: lastBackupPath ? 'var(--kestrel-text)' : 'var(--kestrel-text-muted)' }}>
                        {lastBackupPath ?? 'No backup yet'}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={handleBackupNow}
                    disabled={isBackingUp || appState !== 'unlocked'}
                    className="px-6 h-10 rounded-lg text-sm font-medium transition-colors"
                    style={{
                      backgroundColor: isBackingUp || appState !== 'unlocked' ? 'var(--kestrel-disabled-bg)' : 'var(--kestrel-primary)',
                      color: isBackingUp || appState !== 'unlocked' ? 'var(--kestrel-disabled-text)' : '#FFFFFF',
                    }}
                  >
                    {isBackingUp ? 'Creating backup...' : 'Backup Now'}
                  </button>
                </div>
              </div>
            </section>
          </div>
        )}

        {/* Advanced */}
        {activeCategory === 'advanced' && (
          <div className="max-w-3xl space-y-8">
            <section>
              <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>{t('settings.advanced')}</h3>
              <div
                className="rounded-xl p-5 space-y-5"
                style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)' }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: 'var(--kestrel-text)' }}>Debug mode</label>
                    <p className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>Enable verbose logging for troubleshooting</p>
                  </div>
                  <Toggle on={appSettings?.debug_mode ?? false} onToggle={(val) => { handleUpdateSettings({ debug_mode: val }); showFeedback('success', val ? 'Debug mode enabled' : 'Debug mode disabled') }} />
                </div>

                <div className="flex items-center justify-between pt-4" style={{ borderTop: '1px solid var(--kestrel-border-subtle)' }}>
                  <div>
                    <label className="text-sm block mb-0.5" style={{ color: 'var(--kestrel-text)' }}>Reset all settings</label>
                    <p className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>Restore default settings (does not delete data)</p>
                  </div>
                  <button
                    onClick={handleResetSettings}
                    className="px-4 h-9 rounded-lg text-sm font-medium transition-colors"
                    style={{ backgroundColor: 'var(--kestrel-bg)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}
                  >
                    Reset
                  </button>
                </div>

                <div className="pt-4" style={{ borderTop: '1px solid var(--kestrel-border-subtle)' }}>
                  <label className="text-sm mb-0.5 block" style={{ color: 'var(--kestrel-text)' }}>{t('settings.version')}</label>
                  <p className="text-xs font-mono-geist" style={{ color: 'var(--kestrel-text-muted)' }}>KESTREL Vault v0.1.0</p>
                </div>
              </div>
            </section>
          </div>
        )}
        </>
        )}
      </div>

      {/* Change Password Dialog */}
      {showChangePasswordDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ backgroundColor: 'var(--kestrel-overlay)' }}>
          <div className="rounded-xl p-6 w-full max-w-md" style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: '0 8px 30px rgb(0 0 0 / 0.12)' }}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold" style={{ color: 'var(--kestrel-text)' }}>Change Master Password</h3>
              <button onClick={() => { setShowChangePasswordDialog(false); setChangePasswordError(null); setChangePasswordSuccess(false) }}
                className="w-8 h-8 flex items-center justify-center rounded-lg" style={{ color: 'var(--kestrel-text-muted)' }}>
                <X size={16} />
              </button>
            </div>

            {changePasswordSuccess ? (
              <div className="p-4 rounded-lg text-center" style={{ backgroundColor: 'var(--kestrel-success-subtle)' }}>
                <p className="text-sm font-medium" style={{ color: 'var(--kestrel-success)' }}>Password changed successfully!</p>
              </div>
            ) : (
              <div className="space-y-4">
                <div>
                  <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>Current Password</label>
                  <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)}
                    className="w-full h-9 rounded-lg text-sm outline-none px-3"
                    style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }} />
                </div>
                <div>
                  <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>New Password</label>
                  <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full h-9 rounded-lg text-sm outline-none px-3"
                    style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }} />
                </div>
                <div>
                  <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>Confirm New Password</label>
                  <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full h-9 rounded-lg text-sm outline-none px-3"
                    style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }} />
                </div>

                {changePasswordError && (
                  <div className="p-3 rounded-lg text-sm" style={{ backgroundColor: 'var(--kestrel-danger-subtle)', color: 'var(--kestrel-danger)' }}>
                    {changePasswordError}
                  </div>
                )}

                <div className="flex items-center justify-end gap-3 mt-2">
                  <button onClick={() => { setShowChangePasswordDialog(false); setChangePasswordError(null) }}
                    className="px-4 h-9 rounded-lg text-sm font-medium"
                    style={{ backgroundColor: 'var(--kestrel-bg)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}>
                    Cancel
                  </button>
                  <button onClick={handleChangePassword} disabled={isChangingPassword || !currentPassword || !newPassword || !confirmPassword}
                    className="px-4 h-9 rounded-lg text-sm font-medium transition-colors"
                    style={{
                      backgroundColor: isChangingPassword || !currentPassword || !newPassword || !confirmPassword ? 'var(--kestrel-disabled-bg)' : 'var(--kestrel-primary)',
                      color: isChangingPassword || !currentPassword || !newPassword || !confirmPassword ? 'var(--kestrel-disabled-text)' : '#FFFFFF',
                    }}>
                    {isChangingPassword ? t('settings.changing') : t('settings.changePassword')}
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
