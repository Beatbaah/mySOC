import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ExternalLink, Plus, Search, Trash2, Upload } from 'lucide-react'
import { useCan } from '../api/auth'
import { del, get, post } from '../api/client'
import type { Indicator } from '../api/types'
import { Ago, Card, Empty, ErrorBox, errorText, Modal, PageHead, Skeleton, useToast } from '../components/ui'
import { dateTime, num } from '../lib/format'

interface ProviderResult { verdict: string; summary: string; score?: number; link?: string; provider?: string; cached?: boolean; details?: Record<string, unknown> }
interface Lookup {
  kind: string; value: string; providers: Record<string, ProviderResult>; indicator: Indicator | null
  seenLocally: { flows: number; firstSeen: string | null; lastSeen: string | null } | null
}

const VERDICT_COLOR: Record<string, string> = {
  malicious: 'var(--sev-critical)', suspicious: 'var(--sev-medium)', clean: 'var(--ok)', unknown: 'var(--text-3)',
  unconfigured: 'var(--text-3)', error: 'var(--danger)',
}

function LookupPanel({ initial }: { initial: string }) {
  const [value, setValue] = useState(initial)
  const lookup = useMutation({ mutationFn: (v: string) => get<Lookup>('/api/intel/lookup', { value: v }) })
  useEffect(() => {
    if (initial) lookup.mutate(initial)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initial])
  const r = lookup.data
  return (
    <Card title="Reputation lookup" sub="AbuseIPDB, AlienVault OTX and VirusTotal. Results are cached for an hour.">
      <form className="btn-row" onSubmit={(e) => { e.preventDefault(); if (value.trim()) lookup.mutate(value.trim()) }}>
        <div className="input-wrap" style={{ flex: 1, minWidth: 240 }}>
          <Search size={14} />
          <input className="input" value={value} onChange={(e) => setValue(e.target.value)} placeholder="IP address, domain, URL or file hash" aria-label="Indicator to look up" />
        </div>
        <button className="btn primary" disabled={lookup.isPending}>{lookup.isPending ? 'Looking up…' : 'Look up'}</button>
      </form>
      <div style={{ marginTop: 12 }}><ErrorBox error={lookup.error} /></div>
      {r && (
        <div className="grid" style={{ marginTop: 4 }}>
          <div className="btn-row">
            <span className="mono" style={{ fontSize: 14 }}>{r.value}</span>
            <span className="badge tag">{r.kind}</span>
            {r.indicator && <span className="badge" style={{ background: 'var(--danger-bg)', color: 'var(--danger)' }}>On the indicator list</span>}
            {r.kind === 'ip' && <Link className="ip" to={`/entities/ip/${encodeURIComponent(r.value)}`}>Entity page</Link>}
          </div>
          {r.seenLocally && (
            <p className="muted">
              {r.seenLocally.flows ? <>Seen on this network in {num(r.seenLocally.flows)} flows, last <Ago iso={r.seenLocally.lastSeen} />.</> : 'Not seen on this network.'}
            </p>
          )}
          <div className="grid cols-3">
            {Object.entries(r.providers).map(([id, p]) => (
              <div key={id} className="card" style={{ padding: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ fontWeight: 500 }}>{p.provider ?? id}</strong>
                  <span className="badge" style={{ color: VERDICT_COLOR[p.verdict], background: 'var(--surface-2)', textTransform: 'capitalize' }}>{p.verdict}</span>
                </div>
                <p className="muted" style={{ marginTop: 6, fontSize: 12.5 }}>{p.summary}</p>
                {p.link && <a className="ip" href={p.link} target="_blank" rel="noreferrer noopener" style={{ fontSize: 12, display: 'inline-block', marginTop: 6 }}>Open report <ExternalLink size={11} /></a>}
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  )
}

function AddDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [mode, setMode] = useState<'one' | 'bulk'>('one')
  const [value, setValue] = useState('')
  const [threat, setThreat] = useState('')
  const [confidence, setConfidence] = useState(80)
  const [text, setText] = useState('')
  const [source, setSource] = useState('')
  const save = useMutation({
    mutationFn: async () => mode === 'one'
      ? (await post('/api/indicators', { value, threat, confidence }), 'Indicator added')
      : ((r: { added: number; skipped: number; invalid: number }) => `Added ${r.added}, skipped ${r.skipped} duplicates, ${r.invalid} invalid`)(
        await post('/api/indicators/import', { text, source: source || 'import', threat })),
    onSuccess: (msg) => { qc.invalidateQueries({ queryKey: ['indicators'] }); toast(msg); onClose() },
    onError: (e) => toast(errorText(e), true),
  })
  return (
    <Modal title="Add indicators" onClose={onClose} wide footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={save.isPending || (mode === 'one' ? !value.trim() : !text.trim())} onClick={() => save.mutate()}>Add</button></>}>
      <div className="form">
        <div className="seg"><button className={mode === 'one' ? 'on' : ''} onClick={() => setMode('one')}>One</button><button className={mode === 'bulk' ? 'on' : ''} onClick={() => setMode('bulk')}>Import a list</button></div>
        {mode === 'one' ? (
          <>
            <label className="field"><span>IP, domain, URL or hash</span><input className="input mono" value={value} onChange={(e) => setValue(e.target.value)} /></label>
            <label className="field"><span>Confidence ({confidence}%)</span><input type="range" min={0} max={100} step={5} value={confidence} onChange={(e) => setConfidence(Number(e.target.value))} /></label>
          </>
        ) : (
          <>
            <label className="field"><span>One per line, or CSV: value, threat, confidence</span>
              <textarea className="textarea mono" style={{ minHeight: 160 }} value={text} onChange={(e) => setText(e.target.value)} placeholder={'203.0.113.9\nbad.example.com,phishing,90'} />
            </label>
            <label className="field"><span>Source</span><input className="input" value={source} onChange={(e) => setSource(e.target.value)} placeholder="e.g. abuse.ch feed" /></label>
          </>
        )}
        <label className="field"><span>Threat {mode === 'bulk' && '(default for lines without one)'}</span><input className="input" value={threat} onChange={(e) => setThreat(e.target.value)} placeholder="e.g. Cobalt Strike C2" /></label>
        <p className="faint" style={{ fontSize: 12 }}>Traffic to or from listed IP addresses raises an alert (rule NET-010) within 30 seconds.</p>
      </div>
    </Modal>
  )
}

export default function Intel() {
  const [params] = useSearchParams()
  const canEdit = useCan('analyst')
  const qc = useQueryClient()
  const toast = useToast()
  const [q, setQ] = useState('')
  const [adding, setAdding] = useState(false)
  const list = useQuery({ queryKey: ['indicators', q], queryFn: () => get<{ items: Indicator[]; total: number }>('/api/indicators', { q: q || undefined }) })
  const remove = useMutation({
    mutationFn: (id: number) => del(`/api/indicators/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['indicators'] }),
    onError: (e) => toast(errorText(e), true),
  })
  return (
    <>
      <PageHead title="Threat intel" sub="Check reputation and manage the indicators the sensor watches for."
        actions={canEdit && <button className="btn primary" onClick={() => setAdding(true)}><Plus size={14} /> Add indicators</button>} />
      <div className="grid">
        {canEdit ? <LookupPanel initial={params.get('lookup') ?? ''} /> : <div className="note-box">Reputation lookups need the analyst role.</div>}
        <Card title="Indicators" sub={list.data ? `${list.data.total} on the list` : undefined}
          actions={<div className="input-wrap" style={{ width: 240 }}><Search size={14} /><input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter" aria-label="Filter indicators" /></div>} flush>
          {list.isLoading ? <Skeleton rows={5} /> : !list.data?.items.length ? <Empty title="No indicators">{canEdit && <button className="btn sm" style={{ marginTop: 8 }} onClick={() => setAdding(true)}><Upload size={13} /> Import a feed</button>}</Empty> : (
            <table className="data">
              <thead><tr><th>Indicator</th><th>Type</th><th>Threat</th><th className="num">Confidence</th><th className="num">Hits</th><th>Source</th><th>Added</th>{canEdit && <th />}</tr></thead>
              <tbody>
                {list.data.items.map((i) => (
                  <tr key={i.id}>
                    <td className="mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>{i.kind === 'ip' ? <Link className="ip" to={`/entities/ip/${i.value}`}>{i.value}</Link> : i.value}</td>
                    <td><span className="badge tag">{i.kind}</span></td>
                    <td>{i.threat || <span className="faint">—</span>}</td>
                    <td className="num">{i.confidence}%</td>
                    <td className="num" style={{ color: i.hits ? 'var(--sev-high)' : undefined }}>{i.kind === 'ip' ? num(i.hits ?? 0) : '—'}</td>
                    <td className="muted">{i.source}</td>
                    <td className="muted" title={dateTime(i.createdAt)}><Ago iso={i.createdAt} /></td>
                    {canEdit && <td style={{ width: 40 }}><button className="btn ghost icon sm" aria-label={`Remove ${i.value}`} onClick={() => remove.mutate(i.id)}><Trash2 size={13} /></button></td>}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
      {adding && <AddDialog onClose={() => setAdding(false)} />}
    </>
  )
}
