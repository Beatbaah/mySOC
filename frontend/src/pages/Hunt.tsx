import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Crosshair, Play } from 'lucide-react'
import { useCan } from '../api/auth'
import { get, post } from '../api/client'
import { Card, Country, Empty, ErrorBox, Ip, PageHead, Skeleton } from '../components/ui'
import { bytes, num } from '../lib/format'

interface Column { key: string; label: string; type: 'ip' | 'int' | 'num' | 'pct' | 'bytes' | 'country' | 'text' }
interface HuntDef { id: string; name: string; question: string; mitre: string; params: Record<string, number>; columns: Column[] }
interface HuntResult extends HuntDef { rows: Record<string, string | number>[] }

const PARAM_LABEL: Record<string, string> = {
  hours: 'Look back (hours)', min_connections: 'Minimum connections', max_jitter: 'Maximum jitter (0–1)',
  min_flows: 'Minimum flows', min_mb: 'Minimum MB', min_hosts: 'Minimum hosts',
}

function Cell({ col, v }: { col: Column; v: string | number }) {
  switch (col.type) {
    case 'ip': return <Ip ip={String(v)} />
    case 'bytes': return <span className="mono">{bytes(Number(v))}</span>
    case 'pct': return <span className="mono">{(Number(v) * 100).toFixed(1)}%</span>
    case 'country': return <Country code={String(v)} name />
    case 'int': case 'num': return <span className="mono">{num(Number(v))}</span>
    default: return <>{v}</>
  }
}

export default function Hunt() {
  const canRun = useCan('analyst')
  const hunts = useQuery({ queryKey: ['hunts'], queryFn: () => get<{ items: HuntDef[] }>('/api/hunts') })
  const [active, setActive] = useState<string | null>(null)
  const [params, setParams] = useState<Record<string, number>>({})
  const run = useMutation({ mutationFn: (id: string) => post<HuntResult>(`/api/hunts/${id}/run`, { params }) })

  const current = hunts.data?.items.find((h) => h.id === active)
  const pick = (h: HuntDef) => {
    setActive(h.id)
    setParams(h.params)
    run.reset()
  }

  return (
    <>
      <PageHead title="Hunt" sub="Look for threats the detection rules didn’t flag. Each hunt answers one question over stored flows." />
      <div className="split stretch" style={{ gridTemplateColumns: '320px minmax(0, 1fr)' }}>
        <Card title="Hunts" flush className="self-start">
          {hunts.isLoading ? <Skeleton rows={6} /> : (
            <div style={{ display: 'grid' }}>
              {hunts.data?.items.map((h) => (
                <button key={h.id} onClick={() => pick(h)}
                  style={{
                    textAlign: 'left', border: 0, borderBottom: '1px solid var(--border)', padding: '11px 16px', cursor: 'pointer',
                    background: active === h.id ? 'var(--accent-bg)' : 'transparent',
                  }}>
                  <div style={{ fontWeight: 500, display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                    {h.name} {h.mitre && <span className="badge mitre">{h.mitre}</span>}
                  </div>
                  <div className="muted" style={{ fontSize: 12, marginTop: 3 }}>{h.question}</div>
                </button>
              ))}
            </div>
          )}
        </Card>

        <div className="grid">
          {!current ? (
            <Card className="centered"><Empty title="Pick a hunt" icon={<Crosshair size={20} />}>Choose a question on the left. Results show here, with every address linked to its entity page.</Empty></Card>
          ) : (
            <>
              <Card title={current.name} sub={current.question}>
                <form className="btn-row" style={{ alignItems: 'flex-end' }} onSubmit={(e) => { e.preventDefault(); run.mutate(current.id) }}>
                  {Object.keys(current.params).map((k) => (
                    <label key={k} className="field" style={{ width: 170 }}>
                      <span>{PARAM_LABEL[k] ?? k}</span>
                      <input className="input mono" type="number" step="any" value={params[k] ?? ''} onChange={(e) => setParams({ ...params, [k]: Number(e.target.value) })} />
                    </label>
                  ))}
                  <button className="btn primary" disabled={!canRun || run.isPending}><Play size={13} /> {run.isPending ? 'Running…' : 'Run hunt'}</button>
                </form>
                {!canRun && <p className="faint" style={{ marginTop: 8 }}>Running hunts needs the analyst role.</p>}
              </Card>
              <ErrorBox error={run.error} />
              {run.data && (
                <Card title={`${run.data.rows.length} result${run.data.rows.length === 1 ? '' : 's'}`} flush>
                  {run.data.rows.length === 0 ? <Empty title="Nothing found">That’s a good outcome. Try a longer look-back or looser thresholds.</Empty> : (
                    <div className="table-wrap">
                      <table className="data">
                        <thead><tr>{run.data.columns.map((c) => <th key={c.key} className={['int', 'num', 'bytes', 'pct'].includes(c.type) ? 'num' : ''}>{c.label}</th>)}</tr></thead>
                        <tbody>
                          {run.data.rows.map((r, i) => (
                            <tr key={i}>{run.data!.columns.map((c) => <td key={c.key} className={['int', 'num', 'bytes', 'pct'].includes(c.type) ? 'num' : ''}><Cell col={c} v={r[c.key]} /></td>)}</tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Card>
              )}
            </>
          )}
        </div>
      </div>
    </>
  )
}
