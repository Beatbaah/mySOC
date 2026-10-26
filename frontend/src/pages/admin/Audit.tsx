import { useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { get } from '../../api/client'
import { Card, Empty, ErrorBox, PageHead, Skeleton } from '../../components/ui'
import { dateTime } from '../../lib/format'

interface Entry { id: number; at: string; actor: string; action: string; targetType: string; targetId: string; detail: Record<string, unknown>; ip: string }

export default function Audit() {
  const [action, setAction] = useState('')
  const [actor, setActor] = useState('')
  const { data, error, isLoading } = useQuery({
    queryKey: ['audit', action, actor],
    queryFn: () => get<{ items: Entry[]; actions: string[] }>('/api/audit', { action: action || undefined, actor: actor || undefined, limit: 500 }),
    placeholderData: keepPreviousData,
  })
  return (
    <>
      <PageHead title="Audit log" sub="Every sign-in, change and export, with who did it and from where." />
      <div className="toolbar">
        <select className="select" style={{ width: 'auto' }} value={action} onChange={(e) => setAction(e.target.value)} aria-label="Action">
          <option value="">All actions</option>
          {data?.actions.map((a) => <option key={a} value={a}>{a.replace(/_/g, ' ')}</option>)}
        </select>
        <input className="input" style={{ width: 200 }} value={actor} onChange={(e) => setActor(e.target.value)} placeholder="Username" aria-label="Filter by user" />
      </div>
      <ErrorBox error={error} />
      <Card flush>
        {isLoading ? <Skeleton rows={10} /> : !data?.items.length ? <Empty title="Nothing recorded" /> : (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Time</th><th>Who</th><th>Action</th><th>Target</th><th>Details</th><th>From</th></tr></thead>
              <tbody>
                {data.items.map((e) => (
                  <tr key={e.id}>
                    <td className="muted nowrap">{dateTime(e.at)}</td>
                    <td>{e.actor}</td>
                    <td style={{ color: e.action.includes('failed') || e.action.includes('locked') ? 'var(--sev-high)' : undefined }}>{e.action.replace(/_/g, ' ')}</td>
                    <td className="mono" style={{ fontSize: 12 }}>{e.targetType}{e.targetId ? ` ${e.targetId}` : ''}</td>
                    <td className="mono faint" style={{ fontSize: 11, maxWidth: 420, wordBreak: 'break-word' }}>{Object.keys(e.detail).length ? JSON.stringify(e.detail) : ''}</td>
                    <td className="mono faint" style={{ fontSize: 12 }}>{e.ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  )
}
