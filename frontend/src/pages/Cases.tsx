import { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Briefcase, Plus } from 'lucide-react'
import { useCan } from '../api/auth'
import { get, post } from '../api/client'
import type { Case, Severity } from '../api/types'
import { Ago, Card, Empty, ErrorBox, errorText, Modal, PageHead, Seg, Sev, Skeleton, Status, useToast } from '../components/ui'
import { SEVERITIES } from '../lib/format'

const FILTERS = {
  active: ['open', 'investigating', 'contained'],
  resolved: ['resolved', 'closed'],
  all: [] as string[],
}

export function NewCaseDialog({ alertIds, onClose }: { alertIds: number[]; onClose: () => void }) {
  const nav = useNavigate()
  const qc = useQueryClient()
  const toast = useToast()
  const [title, setTitle] = useState('')
  const [summary, setSummary] = useState('')
  const [severity, setSeverity] = useState<Severity>('medium')
  const create = useMutation({
    mutationFn: () => post<Case>('/api/cases', { title, summary, severity, alertIds }),
    onSuccess: (c) => {
      qc.invalidateQueries({ queryKey: ['cases'] })
      qc.invalidateQueries({ queryKey: ['alerts'] })
      toast('Case opened')
      nav(`/cases/${c.id}`)
    },
    onError: (e) => toast(errorText(e), true),
  })
  return (
    <Modal title="Open a case" onClose={onClose} wide footer={
      <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={title.trim().length < 3 || create.isPending} onClick={() => create.mutate()}>Open case</button>
      </>
    }>
      <div className="form">
        {alertIds.length > 0 && <div className="note-box">{alertIds.length} selected alert{alertIds.length === 1 ? '' : 's'} will be linked. The case takes the severity of its worst alert.</div>}
        <label className="field"><span>Title</span>
          <input className="input" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Workstation ws-45 beaconing to known C2" maxLength={255} />
        </label>
        <label className="field"><span>Severity</span>
          <select className="select" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label className="field"><span>Summary</span>
          <textarea className="textarea" value={summary} onChange={(e) => setSummary(e.target.value)} placeholder="What do we know so far?" />
        </label>
      </div>
    </Modal>
  )
}

export default function Cases() {
  const nav = useNavigate()
  const [params, setParams] = useSearchParams()
  const canEdit = useCan('analyst')
  const [filter, setFilter] = useState<keyof typeof FILTERS>('active')
  const [mine, setMine] = useState(false)
  const [creating, setCreating] = useState<number[] | null>(null)

  useEffect(() => {
    const ids = params.get('new')
    if (ids !== null) {
      setCreating(ids.split(',').map(Number).filter(Boolean))
      setParams({}, { replace: true })
    }
  }, [params, setParams])

  const { data, error, isLoading } = useQuery({
    queryKey: ['cases', filter, mine],
    queryFn: () => get<{ items: Case[] }>('/api/cases', { status: FILTERS[filter], mine }),
  })

  return (
    <>
      <PageHead title="Cases" sub="Investigations: related alerts, an owner and a timeline of what was done."
        actions={canEdit && <button className="btn primary" onClick={() => setCreating([])}><Plus size={14} /> New case</button>} />
      <div className="toolbar">
        <Seg value={filter} onChange={setFilter} label="Status" options={[
          { value: 'active', label: 'Active' }, { value: 'resolved', label: 'Resolved' }, { value: 'all', label: 'All' },
        ]} />
        <button className={`chip ${mine ? 'on' : ''}`} onClick={() => setMine(!mine)} aria-pressed={mine}>Owned by me</button>
      </div>
      <ErrorBox error={error} />
      <Card flush>
        {isLoading ? <Skeleton rows={6} /> : !data?.items.length ? (
          <Empty title="No cases here" icon={<Briefcase size={20} />}
            action={canEdit && <><button className="btn primary" onClick={() => setCreating([])}><Plus size={14} /> New case</button> <Link className="btn" to="/alerts">Go to alerts</Link></>}>
            A case groups related alerts with an owner and a timeline. Start one here, or from any alert.
          </Empty>
        ) : (
          <table className="data">
            <thead>
              <tr><th>Severity</th><th>Case</th><th>Status</th><th>Owner</th><th className="num">Alerts</th><th>Updated</th></tr>
            </thead>
            <tbody>
              {data.items.map((c) => (
                <tr key={c.id} className="clickable" onClick={() => nav(`/cases/${c.id}`)}>
                  <td style={{ width: 100 }}><Sev s={c.severity} /></td>
                  <td className="title-cell">
                    <div className="title-text">{c.title}</div>
                    <div className="sub"><span className="mono">#{c.id}</span> · opened by {c.createdBy} <Ago iso={c.createdAt} />{c.tags.length ? ` · ${c.tags.join(', ')}` : ''}</div>
                  </td>
                  <td><Status s={c.status} /></td>
                  <td>{c.owner?.displayName ?? <span className="faint">—</span>}</td>
                  <td className="num">{c.alertCount}</td>
                  <td className="muted"><Ago iso={c.updatedAt} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {creating && <NewCaseDialog alertIds={creating} onClose={() => setCreating(null)} />}
    </>
  )
}
