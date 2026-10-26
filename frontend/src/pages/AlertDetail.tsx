import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Briefcase, Check, ExternalLink, RotateCcw, UserPlus } from 'lucide-react'
import { useCan, useMe } from '../api/auth'
import { get, patch, post } from '../api/client'
import type { Alert, Asset, Case, Flow, Indicator, UserRef } from '../api/types'
import { CloseDialog } from '../components/AlertActions'
import { FlowTable } from '../components/FlowTable'
import {
  Ago, Card, Country, Disposition, Empty, ErrorBox, errorText, Ip, Mitre, Modal, PageHead, Risk, Sev, Skeleton, ShowMore, Status, useToast,
} from '../components/ui'
import { useShown } from '../lib/useShown'
import { dateTime, num, portLabel } from '../lib/format'
import { techniqueUrl } from '../lib/mitre'

interface Detail { alert: Alert; related: Alert[]; flows: Flow[]; assets: Asset[]; indicators: Indicator[]; case: Case | null }

function EvidenceValue({ v }: { v: unknown }) {
  if (Array.isArray(v)) return <span className="mono">{v.slice(0, 30).join(', ')}{v.length > 30 ? ` … (+${v.length - 30})` : ''}</span>
  if (v && typeof v === 'object') return <span className="mono">{JSON.stringify(v)}</span>
  if (typeof v === 'number') return <span className="mono">{v.toLocaleString()}</span>
  return <span className="mono">{String(v)}</span>
}

function EntityCard({ label, ip, country, assets, indicators }: { label: string; ip: string; country?: string; assets: Asset[]; indicators: Indicator[] }) {
  if (!ip) return null
  const asset = assets.find((a) => a.ip === ip)
  const ioc = indicators.find((i) => i.value === ip)
  return (
    <div className="card" style={{ padding: 12 }}>
      <div className="faint" style={{ fontSize: 12 }}>{label}</div>
      <div style={{ marginTop: 2, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <Ip ip={ip} />
        {country && <span className="muted" style={{ fontSize: 12 }}><Country code={country} name /></span>}
        {asset && <span className="badge tag">internal</span>}
      </div>
      {asset && (
        <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
          {asset.hostname || 'unnamed host'} · {asset.os || 'unknown OS'} · <span style={{ textTransform: 'capitalize' }}>{asset.criticality}</span> criticality{asset.owner ? ` · ${asset.owner}` : ''}
        </div>
      )}
      {ioc && <div className="error-box" style={{ marginTop: 8, padding: '6px 9px' }}>On the indicator list: {ioc.threat || 'known bad'} ({ioc.confidence}% confidence)</div>}
    </div>
  )
}

function CaseDialog({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const nav = useNavigate()
  const toast = useToast()
  const qc = useQueryClient()
  const [mode, setMode] = useState<'new' | 'existing'>('new')
  const [title, setTitle] = useState(alert.title)
  const [caseId, setCaseId] = useState<number | ''>('')
  const cases = useQuery({ queryKey: ['cases', 'active'], queryFn: () => get<{ items: Case[] }>('/api/cases', { status: ['open', 'investigating', 'contained'] }) })
  const go = useMutation({
    mutationFn: async () => {
      if (mode === 'new') return (await post<Case>('/api/cases', { title, severity: alert.severity, alertIds: [alert.id] })).id
      await post(`/api/cases/${caseId}/alerts`, { alertIds: [alert.id] })
      return Number(caseId)
    },
    onSuccess: (id) => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['cases'] })
      toast(mode === 'new' ? 'Case opened' : 'Added to case')
      nav(`/cases/${id}`)
    },
    onError: (e) => toast(errorText(e), true),
  })
  return (
    <Modal title="Add to a case" onClose={onClose} footer={
      <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={go.isPending || (mode === 'new' ? title.trim().length < 3 : !caseId)} onClick={() => go.mutate()}>
          {mode === 'new' ? 'Open case' : 'Add to case'}
        </button>
      </>
    }>
      <div className="form">
        <div className="seg">
          <button className={mode === 'new' ? 'on' : ''} onClick={() => setMode('new')}>New case</button>
          <button className={mode === 'existing' ? 'on' : ''} onClick={() => setMode('existing')}>Existing case</button>
        </div>
        {mode === 'new' ? (
          <label className="field"><span>Title</span><input className="input" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={255} /></label>
        ) : (
          <label className="field">
            <span>Case</span>
            <select className="select" value={caseId} onChange={(e) => setCaseId(Number(e.target.value) || '')}>
              <option value="">Choose…</option>
              {cases.data?.items.map((c) => <option key={c.id} value={c.id}>#{c.id} {c.title}</option>)}
            </select>
          </label>
        )}
      </div>
    </Modal>
  )
}

export default function AlertDetail() {
  const { id } = useParams()
  const me = useMe()
  const canTriage = useCan('analyst')
  const toast = useToast()
  const qc = useQueryClient()
  const [closing, setClosing] = useState(false)
  const [casing, setCasing] = useState(false)
  const [assigning, setAssigning] = useState(false)

  const { data, error, isLoading } = useQuery({ queryKey: ['alerts', 'detail', id], queryFn: () => get<Detail>(`/api/alerts/${id}`) })
  const related = useShown(data?.related ?? [], 10, 20, id)
  const people = useQuery({ queryKey: ['assignable'], queryFn: () => get<{ items: UserRef[] }>('/api/users/assignable'), enabled: assigning })

  const update = useMutation({
    mutationFn: (body: Record<string, unknown>) => patch<Alert>(`/api/alerts/${id}`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['overview'] })
      setClosing(false)
      setAssigning(false)
    },
    onError: (e) => toast(errorText(e), true),
  })

  if (isLoading) return <Skeleton rows={10} />
  if (error || !data) return <ErrorBox error={error ?? 'Alert not found'} />
  const a = data.alert
  const evidence = Object.entries(a.evidence).filter(([k]) => k !== 'occurrences')

  return (
    <>
      <PageHead
        crumbs={<><Link to="/alerts">Alerts</Link> / <span className="mono">#{a.id}</span></>}
        title={a.title}
        sub={<span style={{ display: 'inline-flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <Sev s={a.severity} /> <Risk score={a.riskScore} /> <Status s={a.status} /> <Disposition d={a.disposition} />
          <span className="faint">{a.ruleId}</span>
        </span>}
        actions={canTriage && (
          <>
            {a.status !== 'closed' && a.assignee?.id !== me.id && (
              <button className="btn" onClick={() => update.mutate({ status: 'in_progress', assigneeId: me.id })}><Check size={14} /> Take it</button>
            )}
            {a.status !== 'closed' && <button className="btn" onClick={() => setAssigning(true)}><UserPlus size={14} /> Assign</button>}
            {!a.caseId && <button className="btn" onClick={() => setCasing(true)}><Briefcase size={14} /> Add to case</button>}
            {a.status === 'closed'
              ? <button className="btn" onClick={() => update.mutate({ status: 'in_progress' })}><RotateCcw size={14} /> Reopen</button>
              : <button className="btn primary" onClick={() => setClosing(true)}>Close…</button>}
          </>
        )}
      />

      <div className="split">
        <div className="grid">
          <Card title="What happened">
            <p style={{ fontSize: 14, lineHeight: 1.55 }}>{a.description}</p>
            {evidence.length > 0 && (
              <dl className="kv" style={{ marginTop: 14 }}>
                {evidence.map(([k, v]) => (
                  <div key={k} style={{ display: 'contents' }}>
                    <dt>{k.replace(/_/g, ' ')}</dt>
                    <dd><EvidenceValue v={v} /></dd>
                  </div>
                ))}
              </dl>
            )}
          </Card>

          <div className="grid cols-2">
            <EntityCard label="Source" ip={a.srcIp} country={a.srcCountry} assets={data.assets} indicators={data.indicators} />
            <EntityCard label={a.dstPort ? `Target · port ${portLabel(a.dstPort)}` : 'Target'} ip={a.dstIp} assets={data.assets} indicators={data.indicators} />
          </div>

          <Card title="Traffic around this alert" sub="Flows between these addresses, 5 minutes either side" flush>
            {data.flows.length ? <FlowTable flows={data.flows} /> : <Empty title="No stored flows for this window" />}
          </Card>

          <Card title="Other alerts involving these addresses" sub="Last 24 hours" flush>
            {data.related.length === 0 ? <Empty title="None" /> : (
              <>
              <table className="data">
                <tbody>
                  {related.shown.map((r, i) => (
                    <tr key={r.id} className={related.fresh(i) ? 'row-in' : undefined}>
                      <td style={{ width: 90 }}><Sev s={r.severity} /></td>
                      <td><Link to={`/alerts/${r.id}`} className="title-text">{r.title}</Link></td>
                      <td><Mitre id={r.mitreTechnique} tactic={r.mitreTactic} /></td>
                      <td className="muted" style={{ width: 90 }}><Ago iso={r.lastSeen} /></td>
                      <td style={{ width: 100 }}><Status s={r.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <ShowMore remaining={related.remaining} next={related.next} onClick={related.showMore} noun="alerts" />
              </>
            )}
          </Card>
        </div>

        <div className="grid sticky-col">
          <Card title="Details">
            <dl className="kv">
              <dt>First seen</dt><dd>{dateTime(a.firstSeen)}</dd>
              <dt>Last seen</dt><dd>{dateTime(a.lastSeen)} (<Ago iso={a.lastSeen} />)</dd>
              <dt>Occurrences</dt><dd className="mono">{num(a.count)}</dd>
              <dt>Protocol</dt><dd>{a.protocol || '—'}</dd>
              <dt>Assigned to</dt><dd>{a.assignee?.displayName ?? <span className="faint">nobody</span>}</dd>
              {a.closedAt && <><dt>Closed</dt><dd>{dateTime(a.closedAt)} by {a.closedBy}</dd></>}
              <dt>Case</dt><dd>{data.case ? <Link to={`/cases/${data.case.id}`}>#{data.case.id} {data.case.title}</Link> : <span className="faint">none</span>}</dd>
            </dl>
          </Card>
          {(a.mitreTactic || a.mitreTechnique) && (
            <Card title="MITRE ATT&CK">
              <dl className="kv">
                <dt>Tactic</dt><dd>{a.mitreTactic || '—'}</dd>
                <dt>Technique</dt>
                <dd>
                  {techniqueUrl(a.mitreTechnique) ? (
                    <a href={techniqueUrl(a.mitreTechnique)} target="_blank" rel="noreferrer noopener" className="ip">{a.mitreTechnique} <ExternalLink size={11} /></a>
                  ) : a.mitreTechnique || '—'}
                </dd>
              </dl>
            </Card>
          )}
          <Card title="Next steps">
            <ul style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 6 }} className="muted">
              {a.srcIp && <li>Check <Link className="ip" to={`/entities/ip/${a.srcIp}`}>{a.srcIp}</Link>’s other activity and reputation.</li>}
              {a.srcIp && <li><Link className="ip" to={`/intel?lookup=${a.srcIp}`}>Look up {a.srcIp}</Link> in threat intel.</li>}
              <li>Group related alerts into a case so the timeline stays in one place.</li>
            </ul>
          </Card>
        </div>
      </div>

      {closing && <CloseDialog busy={update.isPending} onCancel={() => setClosing(false)} onConfirm={(d) => update.mutate({ status: 'closed', disposition: d })} />}
      {casing && <CaseDialog alert={a} onClose={() => setCasing(false)} />}
      {assigning && (
        <Modal title="Assign alert" onClose={() => setAssigning(false)}>
          {people.isLoading ? <Skeleton rows={3} /> : (
            <div style={{ display: 'grid', gap: 6 }}>
              {people.data?.items.map((u) => (
                <button key={u.id} className="btn" style={{ justifyContent: 'flex-start' }} onClick={() => update.mutate({ assigneeId: u.id })}>
                  {u.displayName} <span className="faint">@{u.username}</span>
                </button>
              ))}
              {a.assignee && <button className="btn ghost" onClick={() => update.mutate({ assigneeId: 0 })}>Unassign</button>}
            </div>
          )}
        </Modal>
      )}
    </>
  )
}
