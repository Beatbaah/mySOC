import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowDownRight, ArrowUpRight } from 'lucide-react'
import { get } from '../api/client'
import type { Alert, Sensor } from '../api/types'
import { KillChain, SeverityTimeline, WorldMap } from '../components/charts'
import { Ago, BarList, Card, Country, Empty, ErrorBox, Ip, PageHead, Risk, Seg, Sev, Skeleton } from '../components/ui'
import { bytes, compact, minutes, num, SEVERITIES } from '../lib/format'
import { useChanged } from '../lib/useChanged'

interface OverviewData {
  hours: number
  kpis: {
    openBySeverity: Record<string, number>
    openTotal: number
    newUnassigned: number
    alertsInPeriod: number
    alertsPrevPeriod: number
    meanMinutesToClose: number | null
    falsePositiveRate: number | null
    flows: number
    bytes: number
    openCases: number
  }
  timeline: Record<string, number | string>[]
  stepSeconds: number
  tactics: { tactic: string; count: number }[]
  topRules: { ruleId: string; title: string; alerts: number; events: number }[]
  topSources: { ip: string; country: string; alerts: number; maxRisk: number }[]
  countries: { country: string; alerts: number }[]
  urgent: Alert[]
  sensors: (Sensor & { online: boolean })[]
}

function Delta({ now, before }: { now: number; before: number }) {
  if (!before) return <span className="faint">no earlier data</span>
  const pct = Math.round(((now - before) / before) * 100)
  if (pct === 0) return <span className="faint">same as previous period</span>
  const up = pct > 0
  return (
    <span className={up ? 'delta-up' : 'delta-down'}>
      {up ? <ArrowUpRight size={12} /> : <ArrowDownRight size={12} />} {Math.abs(pct)}% vs previous period
    </span>
  )
}

export function Overview() {
  const [hours, setHours] = useState(24)
  const nav = useNavigate()
  const { data, error, isLoading } = useQuery({
    queryKey: ['overview', hours],
    queryFn: () => get<OverviewData>('/api/overview', { hours }),
    refetchInterval: 30_000,
  })

  const k = data?.kpis
  const [urgency, setUrgency] = useState<'all' | 'critical' | 'high'>('all')
  const urgent = data?.urgent.filter((a) => urgency === 'all' || a.severity === urgency)
  const changed = useChanged(data?.urgent, (a) => a.id, (a) => a.lastSeen)
  return (
    <>
      <PageHead
        title="Overview"
        sub="Where the queue stands and what’s hitting the network."
        actions={
          <Seg value={hours} onChange={setHours} label="Time range" options={[
            { value: 1, label: '1h' }, { value: 24, label: '24h' }, { value: 24 * 7, label: '7d' },
          ]} />
        }
      />
      <ErrorBox error={error} />
      {isLoading || !data || !k ? (
        <Skeleton rows={10} />
      ) : (
        <div className="grid" style={{ gap: 14 }}>
          <div className="grid cols-4">
            <Link to="/alerts?status=new&status=in_progress" className="card kpi">
              <div className="label">Open alerts</div>
              <div className="value">{num(k.openTotal)}</div>
              <div className="note" style={{ display: 'flex', gap: 10 }}>
                {SEVERITIES.slice(0, 4).map((s) => (
                  <span key={s} title={s} className="nowrap">
                    <span className={`badge sev sev-${s}`} style={{ height: 'auto' }}><span className="sev-dot" /></span>{' '}
                    {k.openBySeverity[s] ?? 0}
                  </span>
                ))}
              </div>
            </Link>
            <Link to="/alerts?status=new&assignee=unassigned" className="card kpi">
              <div className="label">Waiting for someone</div>
              <div className="value" style={{ color: k.newUnassigned ? 'var(--sev-medium)' : undefined }}>{num(k.newUnassigned)}</div>
              <div className="note">new and unassigned</div>
            </Link>
            <div className="card kpi">
              <div className="label">Alerts in period</div>
              <div className="value">{num(k.alertsInPeriod)}</div>
              <div className="note"><Delta now={k.alertsInPeriod} before={k.alertsPrevPeriod} /></div>
            </div>
            <div className="card kpi">
              <div className="label">Mean time to close</div>
              <div className="value">{minutes(k.meanMinutesToClose)}</div>
              <div className="note">
                {k.falsePositiveRate == null ? 'nothing closed yet' : `${Math.round(k.falsePositiveRate * 100)}% closed as false positive`}
              </div>
            </div>
          </div>

          {/* Left: what happened over time and how far along the attack chain it got.
              Right: the queue, stretched to the left column's height and scrolling inside it. */}
          <div className="split stretch">
            <div className="grid">
              <Card title="Alerts over time" sub={`By severity, ${hours === 1 ? 'per minute' : 'per hour'}`}>
                <SeverityTimeline data={data.timeline} step={data.stepSeconds} height={230} />
              </Card>
              <Card title="Attack stages seen" sub="MITRE ATT&CK tactics of alerts in this period, in kill-chain order">
                <KillChain counts={data.tactics} />
              </Card>
            </div>
            <Card title="Needs attention" sub="Open, highest risk first" flush className="fill-row"
              actions={
                <div className="mini-seg" role="group" aria-label="Show">
                  {(['all', 'critical', 'high'] as const).map((u) => (
                    <button key={u} type="button" className={urgency === u ? 'on' : ''} aria-pressed={urgency === u} onClick={() => setUrgency(u)}>
                      {u === 'all' ? 'All' : u === 'critical' ? `Critical ${data.urgent.filter((a) => a.severity === 'critical').length}` : `High ${data.urgent.filter((a) => a.severity === 'high').length}`}
                    </button>
                  ))}
                </div>
              }>
              {!urgent?.length ? (
                <Empty title="Nothing urgent">No open {urgency === 'all' ? 'high or critical' : urgency} alerts.</Empty>
              ) : (
                <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
                  {urgent.map((a) => (
                    <li key={a.id} className={`clickable ${changed.has(a.id) ? 'arrived' : ''}`} onClick={() => nav(`/alerts/${a.id}`)}
                      style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', cursor: 'pointer' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                        <Sev s={a.severity} />
                        <span className="faint" style={{ fontSize: 12 }}><Ago iso={a.lastSeen} /></span>
                      </div>
                      <div style={{ fontWeight: 500, marginTop: 3 }}>{a.title}</div>
                      <div style={{ display: 'flex', gap: 10, marginTop: 4, alignItems: 'center' }}>
                        <Risk score={a.riskScore} />
                        <span className="faint" style={{ fontSize: 12 }}>{a.mitreTactic}</span>
                      </div>
                    </li>
                  ))}
                  <li><Link to="/alerts?severity=critical&severity=high" className="see-all">See every open high and critical alert</Link></li>
                </ul>
              )}
            </Card>
          </div>

          <div className="grid cols-2">
            <Card title="Top sources" sub="By highest risk" flush>
              {data.topSources.length === 0 ? <Empty title="No sources" /> : (
                <table className="data">
                  <tbody>
                    {data.topSources.map((s) => (
                      <tr key={s.ip}>
                        <td><Ip ip={s.ip} /> <span className="faint" style={{ fontSize: 12 }}><Country code={s.country} /></span></td>
                        <td className="num">{s.alerts}</td>
                        <td style={{ width: 90 }}><Risk score={s.maxRisk} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
            <Card title="Busiest detections">
              <BarList items={data.topRules.map((r) => ({
                key: r.ruleId,
                label: <Link to={`/alerts?rule=${r.ruleId}`}><span className="mono faint">{r.ruleId}</span> {r.title}</Link>,
                value: r.alerts,
                display: `${r.alerts} · ${compact(r.events)} events`,
              }))} />
            </Card>
          </div>

          <div className="split stretch">
            <Card title="Where alerts come from" sub="Alert sources by country">
              <WorldMap values={Object.fromEntries(data.countries.map((c) => [c.country, c.alerts]))} height={300} />
            </Card>
            <Card title="Top countries" sub="By alerts raised" className="fill-row">
              {data.countries.length === 0 ? <Empty title="No countries yet" /> : (
                <BarList items={[...data.countries].sort((a, b) => b.alerts - a.alerts).slice(0, 10).map((c) => ({
                  key: c.country,
                  label: <Country code={c.country} name />,
                  value: c.alerts,
                  display: num(c.alerts),
                }))} />
              )}
            </Card>
          </div>

          <section className="card net-strip" aria-label="Network">
            <span className="faint">Last {hours === 1 ? 'hour' : hours === 24 ? '24 hours' : '7 days'}</span>
            <span><span className="faint">Flows</span> <b className="mono">{num(k.flows)}</b></span>
            <span><span className="faint">Traffic</span> <b className="mono">{bytes(k.bytes)}</b></span>
            <span><span className="faint">Open cases</span> <Link to="/cases" className="mono"><b>{k.openCases}</b></Link></span>
            <span className="net-sensors">
              {data.sensors.length === 0 && <span className="error-box">No sensor has reported. Start one with <code>python -m mysoc.sensor</code>.</span>}
              {data.sensors.map((s) => (
                <span key={s.name} style={{ display: 'inline-flex', gap: 8, alignItems: 'center' }}>
                  <span className={`dot ${s.online ? 'on' : 'off'}`} />
                  <span>{s.name}</span>
                  <span className="badge tag">{s.source}</span>
                  <span className="faint">{s.online ? `${s.stats.flows_per_second ?? 0} flows/s` : <>last seen <Ago iso={s.lastSeen} /></>}</span>
                </span>
              ))}
            </span>
          </section>
        </div>
      )}
    </>
  )
}
