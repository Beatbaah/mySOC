import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Download, Printer } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useCan } from '../api/auth'
import { get } from '../api/client'
import { BarList, Card, Country, ErrorBox, Ip, PageHead, Risk, Seg, Skeleton } from '../components/ui'
import { minutes, num } from '../lib/format'

interface Report {
  days: number
  totals: {
    alerts: number; criticalHigh: number; dispositions: Record<string, number>
    medianMinutesToClose: number | null; p90MinutesToClose: number | null; casesOpened: number; casesResolved: number; riskIndex: number
  }
  perDay: Record<string, number | string>[]
  byRule: { ruleId: string; alerts: number }[]
  byTactic: { tactic: string; alerts: number }[]
  topSources: { ip: string; country: string; alerts: number; maxRisk: number }[]
}

const SEVS = ['info', 'low', 'medium', 'high', 'critical']

export default function Reports() {
  const [days, setDays] = useState(7)
  const canExport = useCan('analyst')
  const { data, error, isLoading } = useQuery({ queryKey: ['report', days], queryFn: () => get<Report>('/api/reports/summary', { days }) })
  const t = data?.totals
  const closed = t ? t.dispositions.true_positive + t.dispositions.false_positive + t.dispositions.benign : 0
  return (
    <>
      <PageHead title="Reports" sub="Detection and response performance for the period."
        actions={<>
          <Seg value={days} onChange={setDays} label="Period" options={[{ value: 1, label: '24h' }, { value: 7, label: '7 days' }, { value: 30, label: '30 days' }]} />
          <button className="btn no-print" onClick={() => window.print()}><Printer size={14} /> Print</button>
          {canExport && <a className="btn no-print" href={`/api/reports/alerts.csv?days=${days}`}><Download size={14} /> Alerts CSV</a>}
        </>} />
      <ErrorBox error={error} />
      {isLoading || !data || !t ? <Skeleton rows={10} /> : (
        <div className="grid">
          <div className="grid cols-4">
            <div className="card kpi"><div className="label">Alerts</div><div className="value">{num(t.alerts)}</div><div className="note">{num(t.criticalHigh)} high or critical</div></div>
            <div className="card kpi"><div className="label">Median time to close</div><div className="value">{minutes(t.medianMinutesToClose)}</div><div className="note">90th percentile {minutes(t.p90MinutesToClose)}</div></div>
            <div className="card kpi"><div className="label">Confirmed incidents</div><div className="value">{num(t.dispositions.true_positive)}</div><div className="note">{closed ? `${Math.round((t.dispositions.false_positive / closed) * 100)}% false positives` : 'nothing closed'}</div></div>
            <div className="card kpi"><div className="label">Cases</div><div className="value">{t.casesOpened}</div><div className="note">{t.casesResolved} resolved</div></div>
          </div>
          <Card title="Alerts per day" sub="By severity">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={data.perDay} margin={{ top: 6, right: 4, left: -18, bottom: 0 }}>
                <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
                <XAxis dataKey="date" stroke="var(--text-3)" fontSize={11} tickLine={false} axisLine={false}
                  tickFormatter={(d) => new Date(d).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} />
                <YAxis stroke="var(--text-3)" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} width={44} />
                <Tooltip cursor={{ fill: 'var(--hover)' }} contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
                {SEVS.map((s) => <Bar key={s} dataKey={s} stackId="a" fill={`var(--sev-${s})`} isAnimationActive={false} />)}
              </BarChart>
            </ResponsiveContainer>
          </Card>
          <div className="grid cols-3">
            <Card title="How alerts were closed">
              <div className="card-stat">
                <b>{num(t.dispositions.true_positive + t.dispositions.benign + t.dispositions.false_positive)}</b>
                <span>closed in this period, {num(t.dispositions.open)} still open</span>
              </div>
              <BarList items={[
                { key: 'tp', label: 'True positive', value: t.dispositions.true_positive },
                { key: 'benign', label: 'Benign', value: t.dispositions.benign },
                { key: 'fp', label: 'False positive', value: t.dispositions.false_positive },
                { key: 'open', label: 'Still open', value: t.dispositions.open },
              ]} />
            </Card>
            <Card title="Noisiest rules"><BarList items={data.byRule.slice(0, 7).map((r) => ({ key: r.ruleId, label: <Link to={`/alerts?rule=${r.ruleId}&view=all`} className="mono">{r.ruleId}</Link>, value: r.alerts }))} /></Card>
            <Card title="ATT&CK tactics"><BarList items={data.byTactic.map((r) => ({ key: r.tactic, label: r.tactic, value: r.alerts }))} /></Card>
          </div>
          <Card title="Top sources" sub="Highest risk first" flush>
            <table className="data fixed">
              <colgroup><col /><col /><col /><col /></colgroup>
              <thead><tr><th>Source</th><th>Country</th><th>Alerts</th><th>Highest risk</th></tr></thead>
              <tbody>
                {data.topSources.map((s) => (
                  <tr key={s.ip}><td><Ip ip={s.ip} /></td><td><Country code={s.country} name /></td><td className="mono">{s.alerts}</td><td><Risk score={s.maxRisk} /></td></tr>
                ))}
              </tbody>
            </table>
          </Card>
        </div>
      )}
    </>
  )
}
