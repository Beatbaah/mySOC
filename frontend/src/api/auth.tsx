import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ApiError, get, onUnauthorized, post, setCsrf } from './client'
import type { Me, Role, SessionState } from './types'

type AuthState =
  | { phase: 'loading' }
  | { phase: 'signed-out'; reason?: string }
  | { phase: 'mfa'; step: 'verify' | 'enroll'; user: Me }
  | { phase: 'signed-in'; user: Me }

interface AuthApi {
  state: AuthState
  login: (username: string, password: string) => Promise<void>
  accept: (s: SessionState) => void
  logout: () => Promise<void>
  refresh: () => Promise<void>
}

const Ctx = createContext<AuthApi | null>(null)
const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 }

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ phase: 'loading' })
  const qc = useQueryClient()

  const accept = useCallback((s: SessionState) => {
    setCsrf(s.csrfToken)
    setState(s.mfa === 'none' ? { phase: 'signed-in', user: s.user } : { phase: 'mfa', step: s.mfa, user: s.user })
  }, [])

  const refresh = useCallback(async () => {
    try {
      accept(await get<SessionState>('/api/auth/me'))
    } catch (e) {
      setState({ phase: 'signed-out', reason: e instanceof ApiError && e.status === 401 ? undefined : (e as Error).message })
    }
  }, [accept])

  useEffect(() => {
    refresh()
  }, [refresh])

  useEffect(
    () =>
      onUnauthorized(() => {
        qc.clear()
        setState({ phase: 'signed-out', reason: 'Your session ended. Sign in again.' })
      }),
    [qc],
  )

  const login = useCallback(
    async (username: string, password: string) => {
      accept(await post<SessionState>('/api/auth/login', { username, password }))
    },
    [accept],
  )

  const logout = useCallback(async () => {
    try {
      await post('/api/auth/logout')
    } finally {
      qc.clear()
      setState({ phase: 'signed-out' })
    }
  }, [qc])

  const value = useMemo(() => ({ state, login, accept, logout, refresh }), [state, login, accept, logout, refresh])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuth(): AuthApi {
  const c = useContext(Ctx)
  if (!c) throw new Error('useAuth outside AuthProvider')
  return c
}

export function useMe(): Me {
  const { state } = useAuth()
  if (state.phase !== 'signed-in') throw new Error('not signed in')
  return state.user
}

export function useCan(role: Role): boolean {
  const me = useMe()
  return RANK[me.role] >= RANK[role] && (role === 'viewer' || !me.mustChangePassword)
}
