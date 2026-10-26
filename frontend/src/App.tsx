import { lazy, Suspense } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from './api/auth'
import { Layout } from './components/Layout'
import { Skeleton, ToastProvider } from './components/ui'
import { Login } from './pages/Login'
import { Account, ChangePassword } from './pages/Account'
import { Overview } from './pages/Overview'

const Alerts = lazy(() => import('./pages/Alerts'))
const AlertDetail = lazy(() => import('./pages/AlertDetail'))
const Cases = lazy(() => import('./pages/Cases'))
const CaseDetail = lazy(() => import('./pages/CaseDetail'))
const Traffic = lazy(() => import('./pages/Traffic'))
const Entity = lazy(() => import('./pages/Entity'))
const Hunt = lazy(() => import('./pages/Hunt'))
const Intel = lazy(() => import('./pages/Intel'))
const Logs = lazy(() => import('./pages/Logs'))
const Assets = lazy(() => import('./pages/Assets'))
const Handover = lazy(() => import('./pages/Handover'))
const Reports = lazy(() => import('./pages/Reports'))
const Rules = lazy(() => import('./pages/Rules'))
const Users = lazy(() => import('./pages/admin/Users'))
const Settings = lazy(() => import('./pages/admin/Settings'))
const Audit = lazy(() => import('./pages/admin/Audit'))

function Gate() {
  const { state } = useAuth()
  if (state.phase === 'loading') return <Skeleton rows={3} />
  if (state.phase !== 'signed-in') return <Login />
  if (state.user.mustChangePassword) {
    return (
      <div className="auth-main" style={{ minHeight: '100%' }}>
        <div className="auth-card" style={{ maxWidth: 420 }}>
          <h2 style={{ marginBottom: 14 }}>Set your password</h2>
          <ChangePassword forced />
        </div>
      </div>
    )
  }
  return (
    <Suspense fallback={<Skeleton rows={8} />}>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="alerts/:id" element={<AlertDetail />} />
          <Route path="cases" element={<Cases />} />
          <Route path="cases/:id" element={<CaseDetail />} />
          <Route path="traffic" element={<Traffic />} />
          <Route path="entities/ip/:ip" element={<Entity />} />
          <Route path="hunt" element={<Hunt />} />
          <Route path="intel" element={<Intel />} />
          <Route path="logs" element={<Logs />} />
          <Route path="assets" element={<Assets />} />
          <Route path="handover" element={<Handover />} />
          <Route path="reports" element={<Reports />} />
          <Route path="rules" element={<Rules />} />
          <Route path="account" element={<Account />} />
          <Route path="admin/users" element={<Users />} />
          <Route path="admin/settings" element={<Settings />} />
          <Route path="admin/audit" element={<Audit />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Suspense>
  )
}

export function App() {
  return (
    <BrowserRouter>
      <ToastProvider>
        <AuthProvider>
          <Gate />
        </AuthProvider>
      </ToastProvider>
    </BrowserRouter>
  )
}
