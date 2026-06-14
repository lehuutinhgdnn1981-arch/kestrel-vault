import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Bell,
  X,
  Shield,
  Key,
  Plus,
  Trash2,
  Upload,
  FilePlus,
  Eye,
  Lock,
  Settings,
  CheckCircle2,
} from 'lucide-react'
import { auditCommands, type AuditEventView } from '@/lib/tauri'
import { useAppStore } from '@/stores/app-store'
import { useI18n } from '@/hooks/use-i18n'
import type { TranslationKey } from '@/lib/i18n/en'

function formatTimeAgo(
  timestamp: string,
  t: (key: TranslationKey, params?: Record<string, string | number>) => string,
): string {
  const now = Date.now()
  const then = new Date(timestamp).getTime()
  const diffMs = now - then
  const diffSeconds = Math.floor(diffMs / 1000)
  const diffMinutes = Math.floor(diffSeconds / 60)
  const diffHours = Math.floor(diffMinutes / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffSeconds < 60) return t('time.justNow')
  if (diffMinutes < 60) return `${diffMinutes}${t('time.minAgo')}`
  if (diffHours < 24) return `${diffHours} ${diffHours === 1 ? t('time.hourAgo') : t('time.hoursAgo')}`
  return `${diffDays} ${diffDays === 1 ? t('time.dayAgo') : t('time.daysAgo')}`
}

function getEventIcon(category: string, action: string): { icon: typeof Plus; color: string } {
  if (category === 'vault') {
    if (action === 'create') return { icon: Plus, color: 'var(--kestrel-success)' }
    if (action === 'delete') return { icon: Trash2, color: 'var(--kestrel-danger)' }
    if (action === 'password_reveal') return { icon: Eye, color: 'var(--kestrel-warning)' }
    if (action === 'update') return { icon: Key, color: 'var(--kestrel-primary)' }
    return { icon: Key, color: 'var(--kestrel-primary)' }
  }
  if (category === 'notes') return { icon: FilePlus, color: 'var(--kestrel-accent-purple)' }
  if (category === 'files') return { icon: Upload, color: 'var(--kestrel-success)' }
  if (category === 'scanner') return { icon: Shield, color: 'var(--kestrel-success)' }
  if (category === 'auth') {
    if (action === 'unlock') return { icon: Lock, color: 'var(--kestrel-success)' }
    if (action === 'lock') return { icon: Lock, color: 'var(--kestrel-text-muted)' }
    return { icon: Shield, color: 'var(--kestrel-primary)' }
  }
  if (category === 'settings') return { icon: Settings, color: 'var(--kestrel-text-muted)' }
  return { icon: Shield, color: 'var(--kestrel-text-muted)' }
}

interface NotificationItem {
  id: string
  icon: typeof Plus
  iconColor: string
  title: string
  description: string
  time: string
  isRead: boolean
  category: string
  action: string
}

export default function NotificationDropdown() {
  const [isOpen, setIsOpen] = useState(false)
  const [notifications, setNotifications] = useState<NotificationItem[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()
  const addToast = useAppStore((s) => s.addToast)
  const { t } = useI18n()

  // Fetch notifications when dropdown opens
  useEffect(() => {
    if (isOpen) {
      fetchNotifications()
    }
  }, [isOpen])

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsOpen(false)
      }
    }
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
      return () => document.removeEventListener('mousedown', handleClickOutside)
    }
    return undefined
  }, [isOpen])

  const fetchNotifications = async () => {
    setIsLoading(true)
    try {
      const page = await auditCommands.queryEvents({ limit: 15 })
      const items: NotificationItem[] = page.events.map((event: AuditEventView, index: number) => {
        const style = getEventIcon(event.category, event.action)
        return {
          id: `notif-${index}-${event.timestamp}`,
          icon: style.icon,
          iconColor: style.color,
          title: `${event.action.charAt(0).toUpperCase() + event.action.slice(1).replace(/_/g, ' ')} - ${event.category}`,
          description: event.subject || 'No details',
          time: formatTimeAgo(event.timestamp, t),
          isRead: index > 2, // Mark older items as read
          category: event.category,
          action: event.action,
        }
      })
      setNotifications(items)
    } catch {
      // Use toast for error feedback
      addToast({ variant: 'error', title: t('notif.failedToLoad') })
    } finally {
      setIsLoading(false)
    }
  }

  const unreadCount = notifications.filter((n) => !n.isRead).length

  const handleNotificationClick = (notif: NotificationItem) => {
    // Navigate based on category
    const routeMap: Record<string, string> = {
      vault: '/vault',
      notes: '/notes',
      files: '/files',
      scanner: '/scanner',
      auth: '/settings',
      settings: '/settings',
    }
    const route = routeMap[notif.category] || '/dashboard'
    navigate(route)
    setIsOpen(false)
  }

  const handleMarkAllRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })))
  }

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Bell Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="relative w-9 h-9 flex items-center justify-center rounded-lg transition-colors duration-150"
        style={{
          backgroundColor: isOpen ? 'var(--kestrel-hover-bg)' : 'var(--kestrel-surface)',
          border: `1px solid ${isOpen ? 'var(--kestrel-border)' : 'var(--kestrel-border)'}`,
        }}
        title={t('notif.title')}
      >
        <Bell size={16} style={{ color: 'var(--kestrel-text-muted)' }} />
        {unreadCount > 0 && (
          <span
            className="absolute -top-1 -right-1 min-w-[18px] h-[18px] flex items-center justify-center rounded-full text-white text-xs font-bold"
            style={{ backgroundColor: 'var(--kestrel-danger)', fontSize: '10px', padding: '0 4px' }}
          >
            {unreadCount}
          </span>
        )}
      </button>

      {/* Dropdown Panel */}
      {isOpen && (
        <div
          className="absolute right-0 top-full mt-2 w-80 rounded-xl shadow-xl overflow-hidden"
          style={{
            backgroundColor: 'var(--kestrel-surface)',
            border: '1px solid var(--kestrel-border)',
            boxShadow: 'var(--kestrel-shadow-dropdown)',
            zIndex: 9999,
            animation: 'fadeIn 150ms ease-out',
          }}
        >
          {/* Header */}
          <div
            className="flex items-center justify-between px-4"
            style={{ height: '44px', borderBottom: '1px solid var(--kestrel-border-subtle)' }}
          >
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold" style={{ color: 'var(--kestrel-text)' }}>
                {t('notif.title')}
              </h3>
              {unreadCount > 0 && (
                <span
                  className="text-xs font-medium px-1.5 py-0.5 rounded-full"
                  style={{ backgroundColor: 'var(--kestrel-danger-subtle)', color: 'var(--kestrel-danger)' }}
                >
                  {unreadCount} {t('notif.new')}
                </span>
              )}
            </div>
            <div className="flex items-center gap-1">
              {unreadCount > 0 && (
                <button
                  onClick={handleMarkAllRead}
                  className="text-xs font-medium px-2 py-1 rounded transition-colors"
                  style={{ color: 'var(--kestrel-primary)' }}
                  onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-hover-bg)' }}
                  onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent' }}
                >
                  {t('notif.markAllRead')}
                </button>
              )}
              <button
                onClick={() => setIsOpen(false)}
                className="p-1 rounded transition-colors"
                style={{ color: 'var(--kestrel-text-on-dark-muted)' }}
              >
                <X size={14} />
              </button>
            </div>
          </div>

          {/* Notification List */}
          <div className="overflow-y-auto" style={{ maxHeight: '360px' }}>
            {isLoading && (
              <div className="flex items-center justify-center py-8">
                <div className="w-5 h-5 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: 'var(--kestrel-primary)', borderTopColor: 'transparent' }} />
              </div>
            )}

            {!isLoading && notifications.length === 0 && (
              <div className="text-center py-8">
                <CheckCircle2 size={24} style={{ color: 'var(--kestrel-text-light)', margin: '0 auto 8px' }} />
                <p className="text-sm" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
                  {t('notif.noNotifications')}
                </p>
              </div>
            )}

            {!isLoading &&
              notifications.map((notif) => {
                const Icon = notif.icon
                return (
                  <button
                    key={notif.id}
                    onClick={() => handleNotificationClick(notif)}
                    className="w-full flex items-start gap-3 px-4 py-3 text-left transition-colors duration-100"
                    style={{
                      backgroundColor: notif.isRead ? 'transparent' : 'var(--kestrel-hover-bg)',
                      borderLeft: notif.isRead ? '3px solid transparent' : `3px solid ${notif.iconColor}`,
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-selected-bg)' }}
                    onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = notif.isRead ? 'transparent' : 'var(--kestrel-hover-bg)' }}
                  >
                    <div
                      className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5"
                      style={{ backgroundColor: `${notif.iconColor}15` }}
                    >
                      <Icon size={13} style={{ color: notif.iconColor }} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p
                        className="text-sm truncate"
                        style={{
                          color: 'var(--kestrel-text)',
                          fontWeight: notif.isRead ? 400 : 500,
                        }}
                      >
                        {notif.title}
                      </p>
                      <p className="text-xs truncate mt-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>
                        {notif.description}
                      </p>
                    </div>
                    <span className="text-xs flex-shrink-0 mt-0.5" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
                      {notif.time}
                    </span>
                  </button>
                )
              })}
          </div>

          {/* Footer */}
          <div
            className="px-4 py-2 text-center"
            style={{ borderTop: '1px solid var(--kestrel-border-subtle)', backgroundColor: 'var(--kestrel-footer-bg)' }}
          >
            <button
              onClick={() => {
                navigate('/audit')
                setIsOpen(false)
              }}
              className="text-xs font-medium transition-colors hover:underline"
              style={{ color: 'var(--kestrel-primary)' }}
            >
              {t('notif.viewAllActivity')}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
