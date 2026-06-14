/**
 * React hook for i18n — re-renders when locale changes.
 *
 * Usage:
 *   const { t, locale, setLocale } = useI18n()
 *   <h1>{t('nav.dashboard')}</h1>
 */

import { useCallback, useSyncExternalStore } from 'react'
import { t as _t, setLocale as _setLocale, getLocale, type Locale, type TranslationKey } from '@/lib/i18n'

// Simple subscription system for locale changes
type Listener = () => void
const listeners = new Set<Listener>()

function subscribe(listener: Listener) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function emitChange() {
  listeners.forEach((l) => l())
}

/** Set locale and trigger re-renders in all useI18n hooks */
export function setAppLocale(locale: Locale) {
  _setLocale(locale)
  emitChange()
}

export function useI18n() {
  const locale = useSyncExternalStore(subscribe, getLocale)

  const translate = useCallback(
    (key: TranslationKey, params?: Record<string, string | number>) => _t(key, params),
    // locale in deps so useCallback updates when locale changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [locale],
  )

  const changeLocale = useCallback((newLocale: Locale) => {
    setAppLocale(newLocale)
  }, [])

  return { t: translate, locale, setLocale: changeLocale }
}
