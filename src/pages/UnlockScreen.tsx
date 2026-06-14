import { useState, useRef, useEffect } from 'react'
import { Eye, EyeOff, ArrowRight, Shield } from 'lucide-react'
import { useAuthStore } from '@/stores/auth-store'
import { useI18n } from '@/hooks/use-i18n'

export default function UnlockScreen() {
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [isShaking] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const unlock = useAuthStore((s) => s.unlock)
  const createVault = useAuthStore((s) => s.createVault)
  const isInitialized = useAuthStore((s) => s.isInitialized)
  const unlockState = useAuthStore((s) => s.unlockState)
  const error = useAuthStore((s) => s.error)
  const clearError = useAuthStore((s) => s.clearError)
  const { t } = useI18n()

  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!password.trim()) return
    if (isInitialized) {
      unlock(password)
    } else {
      createVault(password)
    }
  }

  const isUnlocking = unlockState === 'unlocking'

  return (
    <div
      className="flex items-center justify-center min-h-screen"
      style={{ backgroundColor: 'var(--kestrel-bg)' }}
    >
      <div className={`w-full max-w-sm px-6 ${isShaking ? 'animate-shake' : ''}`}>
        <div className="flex flex-col items-center mb-10 animate-blur-in">
          <div className="relative mb-4">
            <div className="absolute inset-0 rounded-full animate-pulse-soft" style={{ backgroundColor: 'rgba(37, 99, 235, 0.15)', filter: 'blur(20px)', transform: 'scale(1.5)' }} />
            <img src="/kestrel-logo.png" alt="KESTREL" className="w-16 h-16 object-contain relative" />
          </div>
          <h1
            className="text-3xl font-bold tracking-widest"
            style={{ color: 'var(--kestrel-bg)', letterSpacing: '0.08em' }}
          >
            KESTREL
          </h1>
          <p
            className="text-xs font-medium tracking-widest mt-1"
            style={{ color: 'var(--kestrel-text-on-dark-muted)', letterSpacing: '0.15em' }}
          >
            VAULT
          </p>
          <p className="text-sm mt-2" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
            {t('unlock.tagline')}
          </p>
        </div>

        {isUnlocking ? (
          <div className="text-center py-8 animate-scale-in">
            <div
              className="w-8 h-8 border-2 border-t-transparent rounded-full animate-spin mx-auto mb-4"
              style={{ borderColor: 'var(--kestrel-primary)', borderTopColor: 'transparent' }}
            />
            <p className="text-sm" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
              {isInitialized ? t('unlock.unlocking') : t('unlock.creating')}
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4 animate-slide-in-from-bottom" style={{ animationFillMode: 'both' }}>
            <p className="text-sm text-center mb-4" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
              {isInitialized
                ? t('unlock.unlockPrompt')
                : t('unlock.createPrompt')}
            </p>

            <div className="relative">
              <Shield
                size={16}
                className="absolute left-3 top-1/2 -translate-y-1/2"
                style={{ color: 'var(--kestrel-text-muted)' }}
              />
              <input
                ref={inputRef}
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => { setPassword(e.target.value); if (error) clearError() }}
                placeholder={t('unlock.masterPassword')}
                className="w-full h-11 rounded-lg text-sm outline-none transition-all duration-200 pr-10"
                style={{
                  backgroundColor: 'var(--kestrel-surface)',
                  paddingLeft: '40px',
                  border: error ? '1px solid var(--kestrel-danger)' : '1px solid var(--kestrel-border)',
                  color: 'var(--kestrel-text)',
                }}
                autoFocus
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2"
                style={{ color: 'var(--kestrel-text-muted)' }}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>

            {error && (
              <p className="text-xs" style={{ color: 'var(--kestrel-danger)' }}>
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={!password.trim()}
              className="w-full h-11 rounded-lg text-sm font-semibold flex items-center justify-center gap-2 transition-all duration-200"
              style={{
                backgroundColor: password.trim() ? 'var(--kestrel-primary)' : 'var(--kestrel-disabled-bg)',
                color: '#FFFFFF',
                cursor: password.trim() ? 'pointer' : 'not-allowed',
                transform: 'scale(1)',
              }}
              onMouseEnter={(e) => { if (password.trim()) { e.currentTarget.style.backgroundColor = 'var(--kestrel-primary-hover)'; e.currentTarget.style.transform = 'translateY(-1px)'; e.currentTarget.style.boxShadow = '0 4px 12px rgba(37, 99, 235, 0.4)' } }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = password.trim() ? 'var(--kestrel-primary)' : 'var(--kestrel-disabled-bg)'; e.currentTarget.style.transform = 'scale(1)'; e.currentTarget.style.boxShadow = 'none' }}
            >
              {isInitialized ? t('unlock.unlockVault') : t('unlock.createVault')}
              <ArrowRight size={16} />
            </button>

            {isInitialized && (
              <div className="flex items-center justify-between pt-2">
                <span className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>
                  {t('unlock.autoLockInfo')} <span className="underline cursor-pointer">5 {t('unlock.minutes')}</span>
                </span>
              </div>
            )}
          </form>
        )}
      </div>
    </div>
  )
}
