import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { X } from 'lucide-react'
import type { Severity } from '../api/types'
import { countryName, dateTime, DISPOSITION_LABEL, flag, STATUS_LABEL, timeAgo } from '../lib/format'
import { techniqueUrl } from '../lib/mitre'
import { useTween } from '../lib/motion'

export function PageHead({ title, sub, crumbs, actions }: { title: ReactNode; sub?: ReactNode; crumbs?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        {crumbs && <div className="crumbs">{crumbs}</div>}
        <h1>{title}</h1>
        {sub && <p>{sub}</p>}
      </div>
      {actions && <div className="btn-row">{actions}</div>}
    </div>
  )
}

export function Card({ title, sub, actions, children, flush, className = '' }: {
  title?: ReactNode; sub?: ReactNode; actions?: ReactNode; children: ReactNode; flush?: boolean; className?: string
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <div className="card-head">
          <div>
            {title && <h2>{title}</h2>}
            {sub && <div className="sub">{sub}</div>}
          </div>
          {actions}
        </div>
      )}
      <div className={`card-body ${flush ? 'flush' : ''}`}>{children}</div>
    </section>
  )
}

export function Sev({ s }: { s: Severity | string }) {
  return (
    <span className={`badge sev sev-${s}`}>
      <span className="sev-dot" aria-hidden />
      {s}
    </span>
  )
}

export function Status({ s }: { s: string }) {
  const cls = s === 'resolved' ? 'status-ok' : s === 'open' || s === 'investigating' ? 'status-new' : s === 'contained' ? 'status-in_progress' : `status-${s}`
  return <span className={`badge ${cls}`}>{STATUS_LABEL[s] ?? s}</span>
}

export function Disposition({ d }: { d: string | null }) {
  if (!d) return null
  return <span className={`badge ${d === 'true_positive' ? 'status-in_progress' : 'tag'}`}>{DISPOSITION_LABEL[d]}</span>
}

export function riskColor(score: number): string {
  return score >= 80 ? 'var(--sev-critical)' : score >= 60 ? 'var(--sev-high)' : score >= 40 ? 'var(--sev-medium)' : 'var(--sev-low)'
}

export function Risk({ score }: { score: number }) {
  return (
    <span className="risk" title={`Risk score ${score} of 100`}>
      <span className="risk-bar"><i style={{ width: `${score}%`, background: riskColor(score) }} /></span>
      {score}
    </span>
  )
}

export function Ip({ ip }: { ip: string }) {
  if (!ip) return <span className="faint">—</span>
  return (
    <Link className="ip" to={`/entities/ip/${encodeURIComponent(ip)}`} onClick={(e) => e.stopPropagation()}>
      {ip}
    </Link>
  )
}

export function Country({ code, name }: { code: string; name?: boolean }) {
  if (!code) return null
  return (
    <span className="nowrap" title={countryName(code)}>
      <span aria-hidden>{flag(code)}</span> {name ? countryName(code) : code}
    </span>
  )
}

export function Mitre({ id, tactic }: { id: string; tactic?: string }) {
  if (!id && !tactic) return null
  const url = techniqueUrl(id)
  const label = id || tactic
  return url ? (
    <a className="badge mitre" href={url} target="_blank" rel="noreferrer noopener" title={tactic} onClick={(e) => e.stopPropagation()}>
      {label}
    </a>
  ) : (
    <span className="badge mitre">{label}</span>
  )
}

export function Ago({ iso }: { iso: string | null | undefined }) {
  const [, tick] = useState(0)
  useEffect(() => {
    const t = setInterval(() => tick((n) => n + 1), 30_000)
    return () => clearInterval(t)
  }, [])
  return (
    <time dateTime={iso ?? undefined} title={dateTime(iso)} className="nowrap">
      {timeAgo(iso)}
    </time>
  )
}

export function Empty({ title, children, icon, action }: { title: string; children?: ReactNode; icon?: ReactNode; action?: ReactNode }) {
  return (
    <div className={`empty${icon ? ' big' : ''}`}>
      {icon && <span className="empty-icon">{icon}</span>}
      <strong>{title}</strong>
      {children}
      {action && <div className="empty-action">{action}</div>}
    </div>
  )
}

export function Skeleton({ rows = 5, height = 14 }: { rows?: number; height?: number }) {
  return (
    <div style={{ display: 'grid', gap: 10, padding: 16 }} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="skeleton" style={{ height, width: `${92 - ((i * 13) % 30)}%` }} />
      ))}
    </div>
  )
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null
  return <div className="error-box" role="alert">{error instanceof Error ? error.message : String(error)}</div>
}

/** A live number: counts to its new value and flashes once when it changes. */
export function Ticker({ value, format = (n) => n.toLocaleString() }: { value: number; format?: (n: number) => string }) {
  const [shown, changes] = useTween(value)
  return <span key={changes} className={changes ? 'ticked' : undefined}>{format(shown)}</span>
}

/** The footer of a capped list: says how many are left and reveals the next batch. */
export function ShowMore({ remaining, next, onClick, noun }: { remaining: number; next: number; onClick: () => void; noun: string }) {
  if (!remaining) return null
  return (
    <button type="button" className="show-more" onClick={onClick}>
      Show {next === remaining ? `all ${remaining}` : `${next} more`} {noun}
      {next !== remaining && <span className="faint"> of {remaining} left</span>}
    </button>
  )
}

export function BarList({ items }: { items: { label: ReactNode; value: number; display?: ReactNode; key: string }[] }) {
  const max = Math.max(1, ...items.map((i) => i.value))
  if (!items.length) return <Empty title="Nothing in this period" />
  return (
    <div className="bar-list">
      {items.map((i) => (
        <div className="bar-row" key={i.key}>
          <div style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{i.label}</div>
          <div className="mono muted" style={{ fontSize: 12 }}>{i.display ?? i.value.toLocaleString()}</div>
          <div className="track"><i style={{ width: `${(i.value / max) * 100}%` }} /></div>
        </div>
      ))}
    </div>
  )
}

export function Seg<T extends string | number>({ value, options, onChange, label }: {
  value: T; options: { value: T; label: string }[]; onChange: (v: T) => void; label: string
}) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={String(o.value)} type="button" className={o.value === value ? 'on' : ''} aria-pressed={o.value === value} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  )
}

export function Modal({ title, onClose, children, footer, wide }: { title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null
    ref.current?.querySelector<HTMLElement>('input, textarea, select, button.primary')?.focus()
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
      prev?.focus()
    }
  }, [onClose])
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} ref={ref} style={wide ? { maxWidth: 640 } : undefined}>
        <div className="modal-head">
          <h2>{title}</h2>
          <button className="btn ghost icon" onClick={onClose} aria-label="Close"><X size={16} /></button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  )
}

// ── toasts ──────────────────────────────────────────────────────────────

interface Toast { id: number; text: string; error?: boolean }
const ToastCtx = createContext<(text: string, error?: boolean) => void>(() => {})

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const push = useCallback((text: string, error = false) => {
    const id = Date.now() + Math.random()
    setToasts((t) => [...t, { id, text, error }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), error ? 7000 : 3500)
  }, [])
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.error ? 'error' : ''}`}>{t.text}</div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

export function useToast() {
  return useContext(ToastCtx)
}

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : 'Something went wrong.'
}
