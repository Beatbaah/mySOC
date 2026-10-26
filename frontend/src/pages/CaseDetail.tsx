import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { X } from 'lucide-react'
import { useCan } from '../api/auth'
import { del, get, patch, post } from '../api/client'
import type { Alert, Case, CaseEvent, CaseStatus, Severity, UserRef } from '../api/types'
import { Ago, Card, Empty, ErrorBox, errorText, Ip, Mitre, PageHead, Sev, Skeleton, Status, useToast } from '../components/ui'
import { dateTime, SEVERITIES, STATUS_LABEL } from '../lib/format'

interface Detail { case: Case; events: CaseEvent[]; alerts: Alert[] }
const STEPS: CaseStatus[] = ['open', 'investigating', 'contained', 'resolved', 'closed']

function Stepper({ status, onChange, disabled }: { status: CaseStatus; onChange: (s: CaseStatus) => void; disabled: boolean }) {
  const at = STEPS.indexOf(status)
  return (
    <div style={{ display: 'grid', gridTemplateColumns: `repeat(${STEPS.length}, 1fr)`, gap: 4 }} role="group" aria-label="Case status">
      {STEPS.map((s, i) => (
        <button key={s} disabled={disabled} onClick={() => onChange(s)} aria-pressed={s === status}
          style={{
            border: '1px solid var(--border)', borderRadius: 6, padding: '7px 6px', cursor: disabled ? 'default' : 'pointer', fontSize: 12, fontWeight: 500,
            background: i < at ? 'var(--accent-bg)' : i === at ? 'var(--accent)' : 'var(--surface-2)',
            color: i === at ? 'var(--accent-ink)' : i < at ? 'var(--text)' : 'var(--text-3)',
          }}>
          {STATUS_LABEL[s]}
        </button>
      ))}
    </div>
  )
}

function eventMark(kind: string) {
  return kind === 'note' ? 'note' : ''
}

export default function CaseDetail() {
  const { id } = useParams()
  const qc = useQueryClient()
  const toast = useToast()
  const canEdit = useCan('analyst')
  const [note, setNote] = useState('')
  const [editingSummary, setEditingSummary] = useState<string | null>(null)

  const { data, error, isLoading } = useQuery({ queryKey: ['cases', 'detail', id], queryFn: () => get<Detail>(`/api/cases/${id}`) })
  const people = useQuery({ queryKey: ['assignable'], queryFn: () => get<{ items: UserRef[] }>('/api/users/assignable'), enabled: canEdit })
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['cases'] })
    qc.invalidateQueries({ queryKey: ['alerts'] })
  }
  const update = useMutation({
    mutationFn: (body: Record<string, unknown>) => patch(`/api/cases/${id}`, body),
    onSuccess: () => { refresh(); setEditingSummary(null) },
    onError: (e) => toast(errorText(e), true),
  })
  const addNote = useMutation({
    mutationFn: () => post(`/api/cases/${id}/notes`, { body: note }),
    onSuccess: () => { setNote(''); refresh() },
    onError: (e) => toast(errorText(e), true),
  })
  const unlink = useMutation({
    mutationFn: (alertId: number) => del(`/api/cases/${id}/alerts/${alertId}`),
    onSuccess: refresh,
    onError: (e) => toast(errorText(e), true),
  })

  if (isLoading) return <Skeleton rows={10} />
  if (error || !data) return <ErrorBox error={error ?? 'Case not found'} />
  const c = data.case
  const entities = [...new Set(data.alerts.flatMap((a) => [a.srcIp, a.dstIp]).filter(Boolean))]
  const tactics = [...new Set(data.alerts.map((a) => a.mitreTactic).filter(Boolean))]

  return (
    <>
      <PageHead
        crumbs={<><Link to="/cases">Cases</Link> / <span className="mono">#{c.id}</span></>}
        title={c.title}
        sub={<span style={{ display: 'inline-flex', gap: 10, alignItems: 'center' }}><Sev s={c.severity} /><Status s={c.status} /><span className="faint">opened <Ago iso={c.createdAt} /> by {c.createdBy}</span></span>}
      />
      <div className="split">
        <div className="grid">
          <Card><Stepper status={c.status} disabled={!canEdit || update.isPending} onChange={(s) => update.mutate({ status: s })} /></Card>

          <Card title="Summary" actions={canEdit && editingSummary === null && <button className="btn sm ghost" onClick={() => setEditingSummary(c.summary)}>Edit</button>}>
            {editingSummary !== null ? (
              <div className="form">
                <textarea className="textarea" value={editingSummary} onChange={(e) => setEditingSummary(e.target.value)} style={{ minHeight: 140 }} />
                <div className="btn-row">
                  <button className="btn primary sm" onClick={() => update.mutate({ summary: editingSummary })}>Save</button>
                  <button className="btn sm" onClick={() => setEditingSummary(null)}>Cancel</button>
                </div>
              </div>
            ) : c.summary ? <p style={{ whiteSpace: 'pre-wrap' }}>{c.summary}</p> : <p className="faint">No summary yet.</p>}
          </Card>

          <Card title={`Alerts (${data.alerts.length})`} flush>
            {data.alerts.length === 0 ? <Empty title="No alerts linked">Link alerts from the alert page or the queue.</Empty> : (
              <table className="data">
                <tbody>
                  {data.alerts.map((a) => (
                    <tr key={a.id}>
                      <td style={{ width: 90 }}><Sev s={a.severity} /></td>
                      <td>
                        <Link to={`/alerts/${a.id}`} className="title-text">{a.title}</Link>
                        <div className="sub">{dateTime(a.firstSeen)}</div>
                      </td>
                      <td><Mitre id={a.mitreTechnique} tactic={a.mitreTactic} /></td>
                      <td style={{ width: 100 }}><Status s={a.status} /></td>
                      {canEdit && <td style={{ width: 40 }}><button className="btn ghost icon sm" aria-label={`Remove alert ${a.id} from case`} onClick={() => unlink.mutate(a.id)}><X size={13} /></button></td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>

          <Card title="Timeline">
            {canEdit && (
              <form className="form" style={{ marginBottom: 18 }} onSubmit={(e) => { e.preventDefault(); if (note.trim()) addNote.mutate() }}>
                <textarea className="textarea" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note: what you checked, what you found, what you did." />
                <div><button className="btn primary sm" disabled={!note.trim() || addNote.isPending}>Add note</button></div>
              </form>
            )}
            <ul className="timeline">
              {[...data.events].reverse().map((e) => (
                <li key={e.id}>
                  <span className={`mark ${eventMark(e.kind)}`} />
                  <div className="meta"><strong style={{ color: 'var(--text-2)', fontWeight: 500 }}>{e.actor}</strong> · {dateTime(e.at)}</div>
                  {e.kind === 'note' ? <div className="note-body">{e.body}</div> : <div className="body">{e.body}</div>}
                  {e.kind === 'alert_linked' && Array.isArray(e.data.alerts) && (
                    <div style={{ display: 'grid', gap: 2, marginTop: 4 }}>
                      {(e.data.alerts as { id: number; title: string; severity: Severity }[]).map((a) => (
                        <Link key={a.id} to={`/alerts/${a.id}`} className="muted" style={{ fontSize: 12 }}>#{a.id} {a.title}</Link>
                      ))}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          </Card>
        </div>

        <div className="grid">
          <Card title="Case">
            <div className="form">
              <label className="field"><span>Owner</span>
                <select className="select" disabled={!canEdit} value={c.owner?.id ?? ''} onChange={(e) => update.mutate({ ownerId: Number(e.target.value) || 0 })}>
                  <option value="">Nobody</option>
                  {(people.data?.items ?? (c.owner ? [c.owner] : [])).map((u) => <option key={u.id} value={u.id}>{u.displayName}</option>)}
                </select>
              </label>
              <label className="field"><span>Severity</span>
                <select className="select" disabled={!canEdit} value={c.severity} onChange={(e) => update.mutate({ severity: e.target.value })}>
                  {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </label>
              <dl className="kv">
                <dt>Updated</dt><dd><Ago iso={c.updatedAt} /></dd>
                {c.resolvedAt && <><dt>Resolved</dt><dd>{dateTime(c.resolvedAt)}</dd></>}
              </dl>
            </div>
          </Card>
          <Card title="Entities involved">
            {entities.length === 0 ? <span className="faint">None yet.</span> : (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>{entities.map((ip) => <Ip key={ip} ip={ip} />)}</div>
            )}
          </Card>
          <Card title="ATT&CK tactics">
            {tactics.length === 0 ? <span className="faint">None yet.</span> : (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>{tactics.map((t) => <span key={t} className="badge tag">{t}</span>)}</div>
            )}
          </Card>
        </div>
      </div>
    </>
  )
}
