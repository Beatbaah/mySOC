import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { get } from '../api/client'
import type { Flow } from '../api/types'
import { TrafficArea, WorldMap } from '../components/charts'
import { FlowTable } from '../components/FlowTable'
import { BarList, Card, Country, Empty, ErrorBox, Ip, PageHead, Seg, Skeleton } from '../components/ui'
import { bytes, compact, num, portLabel } from '../lib/format'

interface Summary {
  minutes: number
  stepSeconds: number
  series: { t: string; flows: number; bytes: number; packets: number }[]
  topSources: { ip: string; flows: number; bytes: number }[]
  topDestinations: { ip: string; flows: number; bytes: number }[]
  protocols: { protocol: string; flows: number; bytes: number }[]
  ports: { port: number; protocol: string; flows: number; bytes: number }[]
  countriesIn: { country: string; flows: number; bytes: number }[]
  countriesOut: { country: string; flows: number; bytes: number }[]
}

export default function Traffic() {
  const [minutes, setMinutes] = useState(60)
  const [metric, setMetric] = useState<'flows' | 'bytes'>('flows')
  const [direction, setDirection] = useState<'in' | 'out'>('in')
  const { data, error, isLoading } = useQuery({
    queryKey: ['traffic', minutes],
    queryFn: () => get<Summary>('/api/traffic/summary', { minutes }),
    refetchInterval: minutes <= 60 ? 10_000 : 60_000,
  })
  const recent = useQuery({
    queryKey: ['traffic', 'largest', minutes],
    queryFn: () => get<{ items: Flow[] }>('/api/traffic/flows', { since: new Date(Date.now() - minutes * 60_000).toISOString(), sort: 'bytes', limit: 15 }),
    refetchInterval: 30_000,
  })

  const totalFlows = data?.series.reduce((n, s) => n + s.flows, 0) ?? 0
  const totalBytes = data?.series.reduce((n, s) => n + s.bytes, 0) ?? 0
  const countries = direction === 'in' ? data?.countriesIn : data?.countriesOut

  return (
    <>
      <PageHead title="Traffic" sub="Network flows seen by the sensors."
        actions={<Seg value={minutes} onChange={setMinutes} label="Time range" options={[
          { value: 15, label: '15m' }, { value: 60, label: '1h' }, { value: 360, label: '6h' }, { value: 1440, label: '24h' },
        ]} />} />
      <ErrorBox error={error} />
      {isLoading || !data ? <Skeleton rows={10} /> : (
        <div className="grid">
          <div className="grid cols-4">
            <div className="card kpi"><div className="label">Flows</div><div className="value">{compact(totalFlows)}</div><div className="note">{num(Math.round(totalFlows / (minutes * 60) * 10) / 10)} per second</div></div>
            <div className="card kpi"><div className="label">Volume</div><div className="value">{bytes(totalBytes)}</div></div>
            <div className="card kpi"><div className="label">Protocols</div><div className="value" style={{ fontSize: 16, marginTop: 10 }}>
              {data.protocols.map((p) => `${p.protocol} ${Math.round((p.flows / Math.max(totalFlows, 1)) * 100)}%`).join(' · ') || '—'}
            </div></div>
            <div className="card kpi"><div className="label">External countries</div><div className="value">{new Set([...data.countriesIn, ...data.countriesOut].map((c) => c.country)).size}</div></div>
          </div>

          <Card title="Activity" actions={<Seg value={metric} onChange={setMetric} label="Metric" options={[{ value: 'flows', label: 'Flows' }, { value: 'bytes', label: 'Bytes' }]} />}>
            <TrafficArea data={data.series} step={data.stepSeconds} metric={metric} height={230} />
          </Card>

          <div className="grid cols-3">
            <Card title="Top sources" sub="By bytes sent">
              <BarList items={data.topSources.map((s) => ({ key: s.ip, label: <Ip ip={s.ip} />, value: s.bytes, display: bytes(s.bytes) }))} />
            </Card>
            <Card title="Top destinations" sub="By bytes received">
              <BarList items={data.topDestinations.map((s) => ({ key: s.ip, label: <Ip ip={s.ip} />, value: s.bytes, display: bytes(s.bytes) }))} />
            </Card>
            <Card title="Top services" sub="Destination ports by flows">
              <BarList items={data.ports.map((p) => ({ key: `${p.port}/${p.protocol}`, label: <span className="mono">{portLabel(p.port)} <span className="faint">{p.protocol}</span></span>, value: p.flows, display: compact(p.flows) }))} />
            </Card>
          </div>

          <Card title="Geography" sub={direction === 'in' ? 'Where inbound traffic came from' : 'Where outbound traffic went'}
            actions={<Seg value={direction} onChange={setDirection} label="Direction" options={[{ value: 'in', label: 'Inbound' }, { value: 'out', label: 'Outbound' }]} />}>
            <div className="split" style={{ gridTemplateColumns: 'minmax(0,1fr) 260px' }}>
              <WorldMap values={Object.fromEntries((countries ?? []).map((c) => [c.country, c.bytes]))} label="traffic" format={bytes} height={300} />
              <BarList items={[...(countries ?? [])].sort((a, b) => b.bytes - a.bytes).slice(0, 10).map((c) => ({
                key: c.country, label: <Country code={c.country} name />, value: c.bytes, display: bytes(c.bytes),
              }))} />
            </div>
          </Card>

          <Card title="Largest flows" sub="In the selected range" flush>
            {recent.data?.items.length ? <FlowTable flows={recent.data.items} /> : <Empty title="No flows" />}
          </Card>
        </div>
      )}
    </>
  )
}
