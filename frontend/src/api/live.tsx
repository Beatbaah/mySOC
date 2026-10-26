import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import type { Severity } from './types'

export interface Pulse {
  latestAlertId: number
  openBySeverity: Record<Severity, number>
  newest: { id: number; title: string; severity: Severity }[]
  sensors: { name: string; online: boolean; flowsPerSecond?: number }[]
}

const Ctx = createContext<{ pulse: Pulse | null; connected: boolean }>({ pulse: null, connected: false })

// One EventSource for the whole console. When the server says something
// changed, the relevant cached queries are refetched.
export function LiveProvider({ children, onExpired }: { children: ReactNode; onExpired: () => void }) {
  const [pulse, setPulse] = useState<Pulse | null>(null)
  const [connected, setConnected] = useState(false)
  const qc = useQueryClient()
  const lastId = useRef<number | null>(null)

  useEffect(() => {
    const es = new EventSource('/api/stream', { withCredentials: true })
    es.onopen = () => setConnected(true)
    es.onerror = () => setConnected(false)
    es.addEventListener('pulse', (ev) => {
      const p = JSON.parse((ev as MessageEvent).data) as Pulse
      setPulse(p)
      setConnected(true)
      if (lastId.current !== null && p.latestAlertId !== lastId.current) {
        qc.invalidateQueries({ queryKey: ['alerts'] })
        qc.invalidateQueries({ queryKey: ['overview'] })
      }
      lastId.current = p.latestAlertId
    })
    es.addEventListener('expired', () => {
      es.close()
      onExpired()
    })
    return () => es.close()
  }, [qc, onExpired])

  return <Ctx.Provider value={{ pulse, connected }}>{children}</Ctx.Provider>
}

export function useLive() {
  return useContext(Ctx)
}
