import { useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { get } from '../api/client'
import type { LogEvent } from '../api/types'
import { Card, Empty, ErrorBox, Ip, PageHead, Seg, Skeleton } from '../components/ui'
import { dateTime } from '../lib/format'

const SYSLOG_SEV = ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Info', 'Debug']
const SEV_COLOR = ['var(--sev-critical)', 'var(--sev-critical)', 'var(--sev-critical)', 'var(--sev-high)', 'var(--sev-medium)', 'var(--text-2)', 'var(--text-3)', 'var(--text-3)']

interface Result { items: LogEvent[]; hosts: { value: string; count: number }[]; apps: { value: string; count: number }[] }

export default function Logs() {
  const [q, setQ] = useState('')
  const [query, setQuery] = useState('')
  const [host, setHost] = useState('')
  const [app, setApp] = useState('')
  const [maxSeverity, setMaxSeverity] = useState(7)
  const [hours, setHours] = useState(24)
  const { data, error, isLoading } = useQuery({
    queryKey: ['logs', query, host, app, maxSeverity, hours],
    queryFn: () => get<Result>('/api/logs', { q: query || undefined, host: host || undefined, app: app || undefined, max_severity: maxSeverity, hours, limit: 300 }),
    placeholderData: keepPreviousData,
    refetchInterval: 15_000,
  })
  return (
    <>
      <PageHead title="Logs" sub="Messages from firewalls, servers and other devices sent over syslog." />
      <div className="toolbar">
        <form className="input-wrap grow" style={{ minWidth: 240 }} onSubmit={(e) => { e.preventDefault(); setQuery(q.trim()) }}>
          <Search size={14} />
          <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search messages, e.g. “Failed password”" aria-label="Search logs" />
        </form>
        <select className="select" style={{ width: 'auto' }} value={host} onChange={(e) => setHost(e.target.value)} aria-label="Host">
          <option value="">All hosts</option>
          {data?.hosts.map((h) => <option key={h.value} value={h.value}>{h.value} ({h.count})</option>)}
        </select>
        <select className="select" style={{ width: 'auto' }} value={app} onChange={(e) => setApp(e.target.value)} aria-label="Program">
          <option value="">All programs</option>
          {data?.apps.map((a) => <option key={a.value} value={a.value}>{a.value || '(none)'} ({a.count})</option>)}
        </select>
        <select className="select" style={{ width: 'auto' }} value={maxSeverity} onChange={(e) => setMaxSeverity(Number(e.target.value))} aria-label="Minimum severity">
          <option value={7}>Any severity</option>
          <option value={4}>Warning and worse</option>
          <option value={3}>Error and worse</option>
        </select>
        <Seg value={hours} onChange={setHours} label="Range" options={[{ value: 1, label: '1h' }, { value: 24, label: '24h' }, { value: 168, label: '7d' }]} />
      </div>
      <ErrorBox error={error} />
      <Card flush>
        {isLoading ? <Skeleton rows={10} /> : !data?.items.length ? (
          <Empty title="No log messages">Point devices’ syslog at the sensor (UDP, see Settings) or widen the search.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Time</th><th>Severity</th><th>Host</th><th>Program</th><th>Message</th></tr></thead>
              <tbody>
                {data.items.map((l) => (
                  <tr key={l.id}>
                    <td className="muted nowrap">{dateTime(l.at)}</td>
                    <td className="nowrap" style={{ color: SEV_COLOR[l.severity] }}>{SYSLOG_SEV[l.severity]}</td>
                    <td className="nowrap">{l.host} <span className="faint" style={{ fontSize: 11 }}><Ip ip={l.sourceIp} /></span></td>
                    <td className="mono" style={{ fontSize: 12 }}>{l.app}</td>
                    <td className="mono" style={{ fontSize: 12, wordBreak: 'break-word' }}>{l.message}</td>
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
