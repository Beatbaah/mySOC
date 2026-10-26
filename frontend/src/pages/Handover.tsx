import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useCan } from '../api/auth'
import { get, post } from '../api/client'
import type { Severity } from '../api/types'
import { Ago, Card, Empty, ErrorBox, errorText, PageHead, Sev, Skeleton, Status, useToast } from '../components/ui'
import { dateTime, SEVERITIES } from '../lib/format'

interface Snapshot {
  hours: number
  openBySeverity: Record<string, number>
  newAlerts: number
  closedAlerts: number
  urgent: { id: number; title: string; severity: Severity; status: string; riskScore: number }[]
  openCases: { id: number; title: string; severity: Severity; status: string; owner: string | null }[]
  sensors: { name: string; online: boolean }[]
}
interface HandoverRow { id: number; author: string; incoming: string; shift: string; notes: string; snapshot: Snapshot; createdAt: string }

function SnapshotView({ s }: { s: Snapshot }) {
  return (
    <div className="grid">
      <div className="btn-row">
        {SEVERITIES.slice(0, 4).map((sv) => <span key={sv} className="badge tag"><Sev s={sv} /> {s.openBySeverity[sv] ?? 0} open</span>)}
        <span className="badge tag">{s.newAlerts} new in {s.hours}h</span>
        <span className="badge tag">{s.closedAlerts} closed in {s.hours}h</span>
        {s.sensors.map((x) => <span key={x.name} className="badge tag"><span className={`dot ${x.online ? 'on' : 'off'}`} /> {x.name}</span>)}
      </div>
      <div className="grid cols-2">
        <div>
          <div className="faint" style={{ fontSize: 12, marginBottom: 6 }}>Top open high/critical alerts</div>
          {s.urgent.length === 0 ? <span className="faint">None</span> : s.urgent.map((a) => (
            <div key={a.id} style={{ display: 'flex', gap: 8, padding: '3px 0' }}><Sev s={a.severity} /><Link to={`/alerts/${a.id}`}>{a.title}</Link></div>
          ))}
        </div>
        <div>
          <div className="faint" style={{ fontSize: 12, marginBottom: 6 }}>Active cases</div>
          {s.openCases.length === 0 ? <span className="faint">None</span> : s.openCases.map((c) => (
            <div key={c.id} style={{ display: 'flex', gap: 8, padding: '3px 0', alignItems: 'center' }}>
              <Status s={c.status} /><Link to={`/cases/${c.id}`}>{c.title}</Link><span className="faint">{c.owner ?? 'unowned'}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default function Handover() {
  const canWrite = useCan('analyst')
  const qc = useQueryClient()
  const toast = useToast()
  const [notes, setNotes] = useState('')
  const [incoming, setIncoming] = useState('')
  const [shift, setShift] = useState('')
  const [missing, setMissing] = useState(false)
  const { data, error, isLoading } = useQuery({ queryKey: ['handovers'], queryFn: () => get<{ items: HandoverRow[]; current: Snapshot }>('/api/handovers') })
  const save = useMutation({
    mutationFn: () => post('/api/handovers', { notes, incoming, shift }),
    onSuccess: () => { setNotes(''); setIncoming(''); qc.invalidateQueries({ queryKey: ['handovers'] }); toast('Handover saved') },
    onError: (e) => toast(errorText(e), true),
  })
  return (
    <>
      <PageHead title="Shift handover" sub="What the next shift needs to know. The queue snapshot is captured automatically." />
      <ErrorBox error={error} />
      {isLoading || !data ? <Skeleton rows={8} /> : (
        <div className="grid">
          <Card title="Right now" sub="This is saved with your handover">
            <SnapshotView s={data.current} />
          </Card>
          {canWrite && (
            <Card title="Write a handover">
              <form className="form" onSubmit={(e) => {
                e.preventDefault()
                setMissing(!notes.trim())
                if (notes.trim()) save.mutate()
              }}>
                {missing && <ErrorBox error="Write a note for the next shift before saving." />}
                <div className="grid cols-2">
                  <label className="field"><span>Handing over to</span><input className="input" value={incoming} onChange={(e) => setIncoming(e.target.value)} placeholder="Name or team" /></label>
                  <label className="field"><span>Shift</span>
                    <select className="select" value={shift} onChange={(e) => setShift(e.target.value)}>
                      <option value="">—</option><option value="day">Day</option><option value="evening">Evening</option><option value="night">Night</option>
                    </select>
                  </label>
                </div>
                <label className="field"><span>Notes</span>
                  <textarea className="textarea" style={{ minHeight: 140 }} value={notes} onChange={(e) => { setNotes(e.target.value); setMissing(false) }}
                    placeholder={'In progress: …\nWatch for: …\nBlocked on: …'} />
                </label>
                <div><button className="btn primary" disabled={save.isPending}>Save handover</button></div>
              </form>
            </Card>
          )}
          <Card title="Previous handovers" flush>
            {data.items.length === 0 ? <Empty title="No handovers yet" /> : data.items.map((h) => (
              <details key={h.id} style={{ borderBottom: '1px solid var(--border)', padding: '12px 16px' }}>
                <summary style={{ cursor: 'pointer', display: 'flex', gap: 10, alignItems: 'center' }}>
                  <strong style={{ fontWeight: 500 }}>{h.author}{h.incoming ? ` → ${h.incoming}` : ''}</strong>
                  {h.shift && <span className="badge tag" style={{ textTransform: 'capitalize' }}>{h.shift}</span>}
                  <span className="faint" title={dateTime(h.createdAt)}><Ago iso={h.createdAt} /></span>
                </summary>
                <p style={{ whiteSpace: 'pre-wrap', margin: '10px 0 14px' }}>{h.notes}</p>
                <SnapshotView s={h.snapshot} />
              </details>
            ))}
          </Card>
        </div>
      )}
    </>
  )
}
