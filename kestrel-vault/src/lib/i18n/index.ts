/**
 * i18n module for KESTREL Vault.
 *
 * Provides translation functions and locale management.
 * Supported locales: en (English), vi (Vietnamese)
 */

import en, { type TranslationKey } from './en'
import vi from './vi'

export type Locale = 'en' | 'vi'

type TranslationMap = Record<TranslationKey, string>

const translations: Record<Locale, TranslationMap> = { en, vi }

let currentLocale: Locale = 'en'

const listeners = new Set<() => void>()

/** Get the current locale */
export function getLocale(): Locale {
  return currentLocale
}

/** Set the locale and notify all subscribers */
export function setLocale(locale: Locale): void {
  currentLocale = locale
  listeners.forEach((l) => l())
}

/** Subscribe to locale changes */
export function subscribeLocale(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/**
 * Translate a key with optional interpolation params.
 *
 * @example
 * t('vault.breachedFound', { count: 5 }) // "BREACHED — found 5 times!"
 */
export function t(key: TranslationKey, params?: Record<string, string | number>): string {
  const raw = translations[currentLocale]?.[key] ?? translations.en[key] ?? key
  if (!params) return raw
  return raw.replace(/\{(\w+)\}/g, (_, k) => String(params[k] ?? `{${k}}`))
}

export type { TranslationKey }
