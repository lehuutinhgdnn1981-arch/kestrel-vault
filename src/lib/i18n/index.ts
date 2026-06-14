/**
 * Lightweight i18n system for KESTREL Vault.
 *
 * Usage:
 *   import { t } from '@/lib/i18n'
 *   t('nav.dashboard')  // → "Dashboard" or "Bảng điều khiển"
 *
 * In React components, use the `useI18n` hook for reactive updates:
 *   const { t } = useI18n()
 *   <h1>{t('nav.dashboard')}</h1>
 */

import en, { type TranslationKey } from './en'
import vi from './vi'

export type { TranslationKey }

export type Locale = 'en' | 'vi'

const translations: Record<Locale, Record<TranslationKey, string>> = {
  en,
  vi,
}

/** Current locale — defaults to 'en', updated by the i18n store */
let currentLocale: Locale = 'en'

/** Set the current locale */
export function setLocale(locale: Locale) {
  currentLocale = locale
}

/** Get the current locale */
export function getLocale(): Locale {
  return currentLocale
}

/**
 * Translate a key to the current locale.
 * Falls back to English if the key is not found.
 */
export function t(key: TranslationKey, params?: Record<string, string | number>): string {
  let value = translations[currentLocale]?.[key] ?? translations.en[key] ?? key

  if (params) {
    for (const [paramKey, paramValue] of Object.entries(params)) {
      value = value.replace(`{${paramKey}}`, String(paramValue))
    }
  }

  return value
}

/**
 * Get all available locales.
 */
export function getAvailableLocales(): { code: Locale; label: string }[] {
  return [
    { code: 'en', label: 'English' },
    { code: 'vi', label: 'Tiếng Việt' },
  ]
}

export { en, vi }
