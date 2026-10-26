import { useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { useCan } from '../api/auth'
import { get, post } from '../api/client'
import type { Alert, Page } from '../api/types'
import { CloseDialog } from '../components/AlertActions'
import { Ago, Card, Country, Disposition, Empty, ErrorBox, errorText, Ip, Mitre, PageHead, Risk, Sev, Skeleton, Status, useToast } from '../components/ui'
import { portLabel, SEVERITIES } from '../lib/format'
import { useChanged } from '../lib/useChanged'

const PAGE = 50
const VIEWS = [
  { key: 'open', label: 'Open', status: ['new', 'in_progress'] },
  { key: 'new', label: 'New', status: ['new'] },
  { key: 'mine', label: 'Mine', status: ['new', 'in_progress'], assignee: 'me' },
  { key: 'closed', label: 'Closed', status: ['closed'] },
  { key: 'all', label: 'All', status: [] },
]

export default function Alerts() {
  const [params, setParams] = useSearchParams()
  const nav = useNavigate()
  const qc = useQueryClient()
  const toast = useToast()
  const canTriage = useCan('analyst')
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [closing, setClosing] = useState(false)
  const [q, setQ] = useState(params.get('q') ?? '')

  const view = params.get('view') ?? (params.getAll('status').length ? 'custom' : 'open')
  const v = VIEWS.find((x) => x.key === view)
  const status = v ? v.status : params.getAll('status')
  const assignee = v?.assignee ?? params.get('assignee') ?? undefined
  const severity = params.getAll('severity')
  const sort = params.get('sort') ?? 'last_seen'
  const page = Number(params.get('page') ?? 0)
  const filters = { status, severity, assignee, sort, rule: params.get('rule') ?? undefined, q: params.get('q') ?? undefined, ip: params.get('ip') ?? undefined }

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ['alerts', filters, page],
    queryFn: () => get<Page<Alert>>('/api/alerts', { ...filters, limit: PAGE, offset: page * PAGE }),
    placeholderData: keepPreviousData,
    refetchInterval: 20_000,
  })
  const changed = useChanged(data?.items, (a) => a.id, (a) => `${a.lastSeen}|${a.count}|${a.status}`)

  const set = (patch: Record<string, string | string[] | null>) => {
    const next = new URLSearchParams(params)
    for (const [k, val] of Object.entries(patch)) {
      next.delete(k)
      if (Array.isArray(val)) val.forEach((x) => next.append(k, x))
      else if (val !== null) next.set(k, val)
    }
    if (!('page' in patch)) next.delete('page')
    setParams(next, { replace: true })
    setSelected(new Set())
  }

  const toggleSev = (s: string) => set({ severity: severity.includes(s) ? severity.filter((x) => x !== s) : [...severity, s] })

  const bulk = useMutation({
    mutationFn: (body: Record<string, unknown>) => post<{ updated: number }>('/api/alerts/bulk', { ids: [...selected], ...body }),
    onSuccess: (r) => {
      toast(`Updated ${r.updated} alert${r.updated === 1 ? '' : 's'}`)
      setSelected(new Set())
      setClosing(false)
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['overview'] })
    },
    onError: (e) => toast(errorText(e), true),
  })

  const items = useMemo(() => data?.items ?? [], [data])
  const allOnPage = items.length > 0 && items.every((a) => selected.has(a.id))
  const total = data?.total ?? 0

  return (
    <>
      <PageHead title="Alerts" sub="Repeats of the same activity are folded into one alert with a count." />

      <div className="toolbar">
        <div className="seg" role="tablist" aria-label="Queue view">
          {VIEWS.map((x) => (
            <button key={x.key} role="tab" aria-selected={view === x.key} className={view === x.key ? 'on' : ''}
              onClick={() => set({ view: x.key, status: null, assignee: null })}>
              {x.label}
            </button>
          ))}
        </div>
        {SEVERITIES.map((s) => (
          <button key={s} className={`chip ${severity.includes(s) ? 'on' : ''}`} onClick={() => toggleSev(s)} aria-pressed={severity.includes(s)}>
            <span className={`badge sev sev-${s}`} style={{ height: 'auto' }}><span className="sev-dot" /></span>
            {s}
          </button>
        ))}
        <form className="input-wrap grow" style={{ minWidth: 220 }} onSubmit={(e) => { e.preventDefault(); set({ q: q.trim() || null }) }}>
          <Search size={14} />
          <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by title, IP or rule" aria-label="Filter alerts" />
        </form>
        <select className="select" style={{ width: 'auto' }} value={sort} onChange={(e) => set({ sort: e.target.value })} aria-label="Sort">
          <option value="last_seen">Most recent</option>
          <option value="risk">Highest risk</option>
          <option value="count">Most repeated</option>
          <option value="first_seen">Newest first seen</option>
        </select>
      </div>

      {(params.get('rule') || params.get('ip')) && (
        <div className="toolbar">
          {params.get('rule') && <button className="chip on" onClick={() => set({ rule: null })}>Rule {params.get('rule')} ✕</button>}
          {params.get('ip') && <button className="chip on" onClick={() => set({ ip: null })}>IP {params.get('ip')} ✕</button>}
        </div>
      )}

      {selected.size > 0 && canTriage && (
        <div className="card" style={{ padding: '8px 12px', marginBottom: 10, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <strong>{selected.size} selected</strong>
          <button className="btn sm" onClick={() => bulk.mutate({ status: 'in_progress' })}>Take</button>
          <button className="btn sm" onClick={() => setClosing(true)}>Close…</button>
          <button className="btn sm" onClick={() => nav(`/cases?new=${[...selected].join(',')}`)}>Open a case</button>
          <button className="btn sm ghost" onClick={() => setSelected(new Set())}>Clear</button>
        </div>
      )}

      <ErrorBox error={error} />
      <Card flush>
        {isLoading ? <Skeleton rows={10} /> : items.length === 0 ? (
          <Empty title="No alerts match">Try another view or clear the filters.</Empty>
        ) : (
          <div className="table-wrap" style={{ opacity: isFetching ? 0.7 : 1 }}>
            <table className="data">
              <thead>
                <tr>
                  {canTriage && (
                    <th style={{ width: 30 }}>
                      <input type="checkbox" checked={allOnPage} aria-label="Select all on this page"
                        onChange={() => setSelected(allOnPage ? new Set() : new Set(items.map((a) => a.id)))} />
                    </th>
                  )}
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>Alert</th>
                  <th>Source → target</th>
                  <th>Technique</th>
                  <th className="num">Count</th>
                  <th>Last seen</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.id} className={`clickable ${selected.has(a.id) ? 'selected' : ''} ${changed.has(a.id) ? 'arrived' : ''}`} onClick={() => nav(`/alerts/${a.id}`)}>
                    {canTriage && (
                      <td onClick={(e) => e.stopPropagation()}>
                        <input type="checkbox" checked={selected.has(a.id)} aria-label={`Select alert ${a.id}`}
                          onChange={() => {
                            const n = new Set(selected)
                            if (n.has(a.id)) n.delete(a.id)
                            else n.add(a.id)
                            setSelected(n)
                          }} />
                      </td>
                    )}
                    <td><Sev s={a.severity} /></td>
                    <td><Risk score={a.riskScore} /></td>
                    <td className="title-cell">
                      <div className="title-text">{a.title}</div>
                      <div className="sub"><span className="mono">#{a.id}</span> · {a.ruleId}{a.caseId ? ` · case #${a.caseId}` : ''}</div>
                    </td>
                    <td className="nowrap">
                      <Ip ip={a.srcIp} />
                      {a.srcCountry && <span className="faint" style={{ fontSize: 12 }}> <Country code={a.srcCountry} /></span>}
                      {a.dstIp && <><span className="flow-arrow">→</span><Ip ip={a.dstIp} /></>}
                      {a.dstPort ? <span className="faint mono" style={{ fontSize: 11 }}> :{portLabel(a.dstPort)}</span> : null}
                    </td>
                    <td><Mitre id={a.mitreTechnique} tactic={a.mitreTactic} /></td>
                    <td className="num">{a.count > 1 ? `×${a.count.toLocaleString()}` : ''}</td>
                    <td className="muted"><Ago iso={a.lastSeen} /></td>
                    <td className="nowrap">
                      <Status s={a.status} /> {a.status === 'closed' ? <Disposition d={a.disposition} /> : a.assignee ? <span className="faint" style={{ fontSize: 12 }}>{a.assignee.username}</span> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {total > PAGE && (
        <div className="btn-row" style={{ justifyContent: 'flex-end', marginTop: 10 }}>
          <span className="muted">{page * PAGE + 1}–{Math.min(total, (page + 1) * PAGE)} of {total.toLocaleString()}</span>
          <button className="btn sm" disabled={page === 0} onClick={() => set({ page: String(page - 1) })}>Previous</button>
          <button className="btn sm" disabled={(page + 1) * PAGE >= total} onClick={() => set({ page: String(page + 1) })}>Next</button>
        </div>
      )}

      {closing && (
        <CloseDialog count={selected.size} busy={bulk.isPending} onCancel={() => setClosing(false)}
          onConfirm={(disposition) => bulk.mutate({ status: 'closed', disposition })} />
      )}
    </>
  )
}
