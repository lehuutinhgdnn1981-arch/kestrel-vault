import { useState, useRef, useEffect } from 'react'
import { Lock, Eye, EyeOff, ArrowRight } from 'lucide-react'
import { useVaultStore } from '../store/useVaultStore'

export default function UnlockScreen() {
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState(false)
  const [isShaking, setIsShaking] = useState(false)
  const [isUnlocking, setIsUnlocking] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const setUnlocked = useVaultStore((s: { setUnlocked: (v: boolean) => void }) => s.setUnlocked)

  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!password.trim()) return

    setIsUnlocking(true)
    setError(false)

    setTimeout(() => {
      if (password.length > 0) {
        setUnlocked(true)
      } else {
        setError(true)
        setIsShaking(true)
        setIsUnlocking(false)
        setTimeout(() => setIsShaking(false), 300)
      }
    }, 600)
  }

  return (
    <div
      className="flex items-center justify-center min-h-screen"
      style={{ backgroundColor: '#0F172A' }}
    >
      <div className={`w-full max-w-sm px-6 ${isShaking ? 'animate-shake' : ''}`}>
        <div className="flex flex-col items-center mb-10">
          <img src="/kestrel-logo.png" alt="KESTREL" className="w-16 h-16 object-contain mb-4" />
          <h1
            className="text-3xl font-bold tracking-widest"
            style={{ color: '#F8FAFC', letterSpacing: '0.08em' }}
          >
            KESTREL
          </h1>
          <p
            className="text-xs font-medium tracking-widest mt-1"
            style={{ color: '#94A3B8', letterSpacing: '0.15em' }}
          >
            VAULT
          </p>
          <p className="text-sm mt-2" style={{ color: '#94A3B8' }}>
            Secure. Private. Always Yours.
          </p>
        </div>

        {isUnlocking ? (
          <div className="text-center py-8 animate-fade-in">
            <div
              className="w-8 h-8 border-2 border-t-transparent rounded-full animate-spin mx-auto mb-4"
              style={{ borderColor: '#2563EB', borderTopColor: 'transparent' }}
            />
            <p className="text-sm" style={{ color: '#94A3B8' }}>Unlocking...</p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <p className="text-sm text-center mb-4" style={{ color: '#94A3B8' }}>
              Unlock your vault to continue
            </p>

            <div className="relative">
              <Lock
                size={16}
                className="absolute left-3 top-1/2 -translate-y-1/2"
                style={{ color: '#64748B' }}
              />
              <input
                ref={inputRef}
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => { setPassword(e.target.value); setError(false) }}
                placeholder="Master Password"
                className="w-full h-11 rounded-lg text-sm outline-none transition-all duration-150 pr-10"
                style={{
                  backgroundColor: '#FFFFFF',
                  paddingLeft: '40px',
                  border: error ? '1px solid #EF4444' : '1px solid #E2E8F0',
                }}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2"
                style={{ color: '#64748B' }}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>

            {error && (
              <p className="text-xs" style={{ color: '#EF4444' }}>
                Incorrect master password. Please try again.
              </p>
            )}

            <button
              type="submit"
              disabled={!password.trim()}
              className="w-full h-11 rounded-lg text-sm font-semibold flex items-center justify-center gap-2 transition-all duration-150"
              style={{
                backgroundColor: password.trim() ? '#2563EB' : '#334155',
                color: '#FFFFFF',
                cursor: password.trim() ? 'pointer' : 'not-allowed',
              }}
            >
              Unlock Vault
              <ArrowRight size={16} />
            </button>

            <div className="flex items-center justify-between pt-2">
              <span className="text-xs" style={{ color: '#64748B' }}>
                Auto-lock after <span className="underline cursor-pointer">5 minutes</span>
              </span>
            </div>

            <div className="flex items-center justify-between pt-2">
              <a href="#" className="text-xs hover:underline" style={{ color: '#64748B' }}>
                Need help?
              </a>
              <a href="#" className="text-xs hover:underline" style={{ color: '#64748B' }}>
                Create New Vault
              </a>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
