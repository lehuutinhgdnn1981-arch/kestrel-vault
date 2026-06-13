import { Routes, Route, Navigate } from 'react-router'
import Layout from './components/Layout'
import UnlockScreen from './pages/UnlockScreen'
import Dashboard from './pages/Dashboard'
import PasswordVault from './pages/PasswordVault'
import FileVault from './pages/FileVault'
import SecureNotes from './pages/SecureNotes'
import SecurityCenter from './pages/SecurityCenter'
import ThreatScanner from './pages/ThreatScanner'
import AuditLogs from './pages/AuditLogs'
import Settings from './pages/Settings'
import { useVaultStore } from './store/useVaultStore'

function AppRoutes() {
  const isUnlocked = useVaultStore((s: { isUnlocked: boolean }) => s.isUnlocked)

  if (!isUnlocked) {
    return <UnlockScreen />
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/vault" element={<PasswordVault />} />
        <Route path="/files" element={<FileVault />} />
        <Route path="/notes" element={<SecureNotes />} />
        <Route path="/security" element={<SecurityCenter />} />
        <Route path="/scanner" element={<ThreatScanner />} />
        <Route path="/audit" element={<AuditLogs />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}

export default function App() {
  return <AppRoutes />
}
