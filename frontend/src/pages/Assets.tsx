import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { get } from '../api/client'
import type { Asset } from '../api/types'
import { Ago, Card, Empty, ErrorBox, Ip, PageHead, Skeleton } from '../components/ui'

const CRIT = ['critical', 'high', 'medium', 'low'] as const
const CRIT_COLOR: Record<string, string> = { critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--text-2)', low: 'var(--text-3)' }

export default function Assets() {
  const nav = useNavigate()
  const [q, setQ] = useState('')
  const [crit, setCrit] = useState<string[]>([])
  const { data, error, isLoading } = useQuery({
    queryKey: ['assets', q, crit],
    queryFn: () => get<{ items: Asset[] }>('/api/assets', { q: q || undefined, criticality: crit }),
  })
  return (
    <>
      <PageHead title="Assets" sub="Internal hosts, discovered from traffic. Mark the important ones: their alerts score higher." />
      <div className="toolbar">
        <div className="input-wrap" style={{ width: 280 }}>
          <Search size={14} />
          <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="IP, hostname, owner or OS" aria-label="Filter assets" />
        </div>
        {CRIT.map((c) => (
          <button key={c} className={`chip ${crit.includes(c) ? 'on' : ''}`} aria-pressed={crit.includes(c)}
            onClick={() => setCrit(crit.includes(c) ? crit.filter((x) => x !== c) : [...crit, c])} style={{ textTransform: 'capitalize' }}>
            {c}
          </button>
        ))}
      </div>
      <ErrorBox error={error} />
      <Card flush>
        {isLoading ? <Skeleton rows={10} /> : !data?.items.length ? <Empty title="No assets yet">They appear as soon as the sensor sees internal traffic.</Empty> : (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Address</th><th>Hostname</th><th>Criticality</th><th>OS</th><th>Owner</th><th>Tags</th><th className="num">Open alerts</th><th>Last seen</th></tr></thead>
              <tbody>
                {data.items.map((a) => (
                  <tr key={a.id} className="clickable" onClick={() => nav(`/entities/ip/${a.ip}`)}>
                    <td><Ip ip={a.ip} /></td>
                    <td>{a.hostname || <span className="faint">—</span>}</td>
                    <td style={{ color: CRIT_COLOR[a.criticality], textTransform: 'capitalize' }}>{a.criticality}</td>
                    <td className="muted">{a.os || '—'}</td>
                    <td className="muted">{a.owner || '—'}</td>
                    <td>{a.tags.map((t) => <span key={t} className="badge tag" style={{ marginRight: 4 }}>{t}</span>)}</td>
                    <td className="num" style={{ color: a.openAlerts ? 'var(--sev-high)' : undefined }}>{a.openAlerts || ''}</td>
                    <td className="muted"><Ago iso={a.lastSeen} /></td>
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
