import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { CornerDownLeft, Search } from 'lucide-react'
import { get } from '../api/client'
import type { Alert, Asset, Indicator, Page } from '../api/types'
import { Sev } from './ui'

const IP_RE = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]*)$/i

const PAGES: { label: string; to: string; words?: string }[] = [
  { label: 'Overview', to: '/', words: 'dashboard home' },
  { label: 'Alerts', to: '/alerts', words: 'queue triage' },
  { label: 'Cases', to: '/cases', words: 'investigations incidents' },
  { label: 'Traffic', to: '/traffic', words: 'flows network bandwidth' },
  { label: 'Hunt', to: '/hunt', words: 'beaconing threat hunting' },
  { label: 'Threat intel', to: '/intel', words: 'indicators ioc reputation' },
  { label: 'Logs', to: '/logs', words: 'syslog events' },
  { label: 'Assets', to: '/assets', words: 'hosts inventory devices' },
  { label: 'Shift handover', to: '/handover', words: 'notes shift' },
  { label: 'Reports', to: '/reports', words: 'metrics mttc export csv' },
  { label: 'Detection rules', to: '/rules', words: 'thresholds tuning' },
  { label: 'Your account', to: '/account', words: 'password authenticator mfa' },
]

interface Hit { key: string; group: string; to: string; label: ReactNode; meta?: ReactNode }

function useDebounced<T>(v: T, ms: number) {
  const [d, setD] = useState(v)
  useEffect(() => {
    const t = setTimeout(() => setD(v), ms)
    return () => clearTimeout(t)
  }, [v, ms])
  return d
}

// Search box in the top bar. Results come in as you type, grouped by kind;
// arrow keys move, Enter opens, Esc closes. "/" or Cmd/Ctrl+K focuses it.
export function GlobalSearch() {
  const nav = useNavigate()
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const [at, setAt] = useState(0)
  const input = useRef<HTMLInputElement>(null)
  const box = useRef<HTMLDivElement>(null)
  const term = useDebounced(q.trim(), 180)
  const enabled = open && term.length >= 2

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement
      if ((e.key === '/' && !typing) || (e.key.toLowerCase() === 'k' && (e.metaKey || e.ctrlKey))) {
        e.preventDefault()
        input.current?.focus()
        input.current?.select()
      }
    }
    const away = (e: MouseEvent) => !box.current?.contains(e.target as Node) && setOpen(false)
    window.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', away)
    return () => {
      window.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', away)
    }
  }, [])

  const alerts = useQuery({
    queryKey: ['search', 'alerts', term],
    queryFn: () => get<Page<Alert>>('/api/alerts', { q: term, limit: 25, sort: 'risk' }),
    enabled,
    staleTime: 10_000,
  })
  const assets = useQuery({
    queryKey: ['search', 'assets', term],
    queryFn: () => get<{ items: Asset[] }>('/api/assets', { q: term, limit: 4 }),
    enabled,
    staleTime: 30_000,
  })
  const intel = useQuery({
    queryKey: ['search', 'intel', term],
    queryFn: () => get<{ items: Indicator[] }>('/api/indicators', { q: term, limit: 4 }),
    enabled,
    staleTime: 30_000,
  })

  const hits = useMemo<Hit[]>(() => {
    const v = q.trim()
    if (!v) return []
    const out: Hit[] = []
    if (/^#?\d+$/.test(v)) out.push({ key: 'id', group: 'Go to', to: `/alerts/${v.replace('#', '')}`, label: <>Alert #{v.replace('#', '')}</> })
    if (IP_RE.test(v)) out.push({ key: 'ip', group: 'Go to', to: `/entities/ip/${encodeURIComponent(v)}`, label: <>Everything about <span className="mono">{v}</span></> })
    const lower = v.toLowerCase()
    for (const p of PAGES) {
      if (`${p.label} ${p.words ?? ''}`.toLowerCase().includes(lower)) out.push({ key: `p${p.to}`, group: 'Pages', to: p.to, label: p.label })
    }
    if (v.length >= 2 && v === term) {
      // Repeats of one detection share a title; show each title once (highest risk first).
      const seen = new Set<string>()
      for (const a of alerts.data?.items ?? []) {
        if (seen.has(a.title) || seen.size >= 5) continue
        seen.add(a.title)
        out.push({ key: `a${a.id}`, group: 'Alerts', to: `/alerts/${a.id}`, label: a.title, meta: <Sev s={a.severity} /> })
      }
      if (alerts.data?.items.length) {
        out.push({ key: 'all', group: 'Alerts', to: `/alerts?view=all&q=${encodeURIComponent(v)}`, label: <span className="muted">All alerts matching “{v}”</span> })
      }
      for (const a of assets.data?.items ?? []) {
        out.push({
          key: `h${a.id}`, group: 'Assets', to: `/entities/ip/${encodeURIComponent(a.ip)}`,
          label: <><span className="mono">{a.ip}</span> {a.hostname && <span className="muted">{a.hostname}</span>}</>,
          meta: <span className="faint">{a.criticality}</span>,
        })
      }
      for (const i of intel.data?.items ?? []) {
        out.push({
          key: `i${i.id}`, group: 'Threat intel', to: i.kind === 'ip' ? `/entities/ip/${encodeURIComponent(i.value)}` : `/intel`,
          label: <><span className="mono">{i.value}</span> <span className="muted">{i.threat}</span></>,
          meta: <span className="faint">{i.kind}</span>,
        })
      }
    }
    return out
  }, [q, term, alerts.data, assets.data, intel.data])

  useEffect(() => setAt(0), [q])

  const go = (h: Hit | undefined) => {
    if (!h) return
    nav(h.to)
    setQ('')
    setOpen(false)
    input.current?.blur()
  }
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setAt((i) => Math.min(i + 1, hits.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setAt((i) => Math.max(i - 1, 0)) }
    else if (e.key === 'Enter') { e.preventDefault(); go(hits[at]) }
    else if (e.key === 'Escape') { setOpen(false); input.current?.blur() }
  }

  const loading = enabled && (alerts.isFetching || assets.isFetching || intel.isFetching)
  const showPanel = open && q.trim().length > 0
  let lastGroup = ''

  return (
    <div className="search" ref={box} role="search">
      <div className="input-wrap">
        <Search size={14} />
        <input
          ref={input} className="input" value={q} placeholder="Search alerts, IPs, hosts, indicators"
          onChange={(e) => { setQ(e.target.value); setOpen(true) }} onFocus={() => setOpen(true)} onKeyDown={onKeyDown}
          role="combobox" aria-expanded={showPanel} aria-controls="search-results" aria-autocomplete="list"
          aria-activedescendant={showPanel && hits[at] ? `sr-${hits[at].key}` : undefined} aria-label="Search"
        />
        <kbd className="search-key" aria-hidden>/</kbd>
      </div>
      {showPanel && (
        <div className="search-panel pop" id="search-results" role="listbox">
          {hits.map((h, i) => {
            const head = h.group !== lastGroup ? h.group : null
            lastGroup = h.group
            return (
              <div key={h.key}>
                {head && <div className="search-group">{head}</div>}
                <div id={`sr-${h.key}`} role="option" aria-selected={i === at} className={`search-hit ${i === at ? 'on' : ''}`}
                  onMouseEnter={() => setAt(i)} onMouseDown={(e) => { e.preventDefault(); go(h) }}>
                  <span className="search-label">{h.label}</span>
                  {h.meta}
                  {i === at && <CornerDownLeft size={13} className="faint" />}
                </div>
              </div>
            )
          })}
          {loading && <div className="search-note">Searching…</div>}
          {!loading && hits.length === 0 && (
            <div className="search-note">{q.trim().length < 2 ? 'Keep typing to search alerts, assets and indicators.' : `Nothing matches “${q.trim()}”.`}</div>
          )}
        </div>
      )}
    </div>
  )
}
