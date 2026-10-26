import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowDownRight, ArrowUpRight } from 'lucide-react'
import { get } from '../api/client'
import type { Alert, Sensor } from '../api/types'
import { KillChain, SeverityTimeline, WorldMap } from '../components/charts'
import { Ago, BarList, Card, Country, Empty, ErrorBox, Ip, PageHead, Risk, Seg, Sev, Skeleton, Ticker } from '../components/ui'
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

// Share of open alerts by severity, as one stacked bar.
function SevBar({ counts }: { counts: Record<string, number> }) {
  const total = SEVERITIES.slice(0, 4).reduce((sum, s) => sum + (counts[s] ?? 0), 0)
  return (
    <div className="sev-bar" role="img" aria-label="Open alerts by severity">
      {total > 0 && SEVERITIES.slice(0, 4).map((s) => (counts[s] ? <i key={s} className={`sev-${s}`} style={{ flexGrow: counts[s] }} /> : null))}
    </div>
  )
}

function Meter({ share, tone }: { share: number; tone: string }) {
  return <div className="meter"><i style={{ width: `${Math.min(1, Math.max(0, share)) * 100}%`, background: tone }} /></div>
}

// Alerts per time step across the period: the shape, not the scale.
function Spark({ points }: { points: number[] }) {
  if (points.length < 2) return <div className="spark" />
  const max = Math.max(1, ...points)
  const d = points.map((v, i) => `${((i / (points.length - 1)) * 100).toFixed(2)},${(22 - (v / max) * 20).toFixed(2)}`).join(' ')
  return (
    <svg className="spark" viewBox="0 0 100 24" preserveAspectRatio="none" aria-hidden>
      <polyline points={`0,24 ${d} 100,24`} className="spark-fill" />
      <polyline points={d} className="spark-line" />
    </svg>
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
  const topRuleMax = Math.max(1, ...(data?.topRules ?? []).map((r) => r.alerts))
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
            <Link to="/alerts?status=new&status=in_progress" className="card kpi link">
              <div className="label">Open alerts</div>
              <div className="value"><Ticker value={k.openTotal} format={num} /></div>
              <div className="kpi-foot">
                <SevBar counts={k.openBySeverity} />
                <div className="kpi-legend">
                  {SEVERITIES.slice(0, 4).map((s) => (
                    <span key={s} className={`sev-${s}`} title={`${k.openBySeverity[s] ?? 0} ${s}`}><i className="sev-dot" />{num(k.openBySeverity[s] ?? 0)}<span className="lg-name">{s}</span></span>
                  ))}
                </div>
              </div>
            </Link>
            <Link to="/alerts?status=new&assignee=unassigned" className="card kpi link">
              <div className="label">Waiting for someone</div>
              <div className="value"><Ticker value={k.newUnassigned} format={num} /><span className="of">of {num(k.openTotal)} open</span></div>
              <div className="kpi-foot">
                <Meter share={k.openTotal ? k.newUnassigned / k.openTotal : 0} tone="var(--sev-medium)" />
                <div className="note">New and nobody has taken them yet</div>
              </div>
            </Link>
            <div className="card kpi">
              <div className="label">Alerts in period</div>
              <div className="value"><Ticker value={k.alertsInPeriod} format={num} /></div>
              <div className="kpi-foot">
                <Spark points={data.timeline.map((p) => SEVERITIES.reduce((sum, s) => sum + Number(p[s] ?? 0), 0))} />
                <div className="note"><Delta now={k.alertsInPeriod} before={k.alertsPrevPeriod} /></div>
              </div>
            </div>
            <div className="card kpi">
              <div className="label">Mean time to close</div>
              <div className="value">{minutes(k.meanMinutesToClose)}</div>
              <div className="kpi-foot">
                <Meter share={k.falsePositiveRate ?? 0} tone="var(--text-3)" />
                <div className="note">
                  {k.falsePositiveRate == null ? 'Nothing closed yet' : `${Math.round(k.falsePositiveRate * 100)}% closed as false positive`}
                </div>
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
            <Card title="Busiest detections" sub="Rules raising the most alerts">
              {data.topRules.length === 0 ? <Empty title="Nothing in this period" /> : (
                <ol className="rule-list">
                  {data.topRules.slice(0, 6).map((r) => (
                    <li key={r.ruleId}>
                      <Link to={`/alerts?rule=${r.ruleId}`}>
                        <b className="rule-count"><Ticker value={r.alerts} /></b>
                        <span className="rule-title">{r.title}</span>
                        <span className="rule-meta">
                          <span className="mono">{r.ruleId}</span>
                          <span>{compact(r.events)} events</span>
                          <span className="track"><i style={{ width: `${(r.alerts / topRuleMax) * 100}%` }} /></span>
                        </span>
                      </Link>
                    </li>
                  ))}
                </ol>
              )}
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
