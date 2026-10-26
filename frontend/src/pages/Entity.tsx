import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Pencil, ShieldAlert } from 'lucide-react'
import { useCan } from '../api/auth'
import { get, patch, post } from '../api/client'
import type { Alert, Asset, Indicator, LogEvent } from '../api/types'
import { TrafficArea } from '../components/charts'
import { Ago, BarList, Card, Country, Empty, ErrorBox, errorText, Ip, Mitre, Modal, PageHead, Seg, Sev, Skeleton, Status, useToast } from '../components/ui'
import { bytes, dateTime, num, portLabel } from '../lib/format'

interface Peer { ip: string; country: string; flows: number; bytes: number }
interface EntityData {
  ip: string
  internal: boolean
  country: string
  asset: Asset | null
  indicator: Indicator | null
  intel: Record<string, { verdict: string; summary: string; provider?: string; fetchedAt?: string }>
  traffic: {
    flows: number; bytes: number; bytesSent: number; firstSeen: string | null; lastSeen: string | null
    peersOut: Peer[]; peersIn: Peer[]; ports: { port: number; protocol: string; flows: number }[]
    activity: { t: string; flows: number; bytes: number }[]; stepSeconds: number
  }
  alerts: Alert[]
  logs: LogEvent[]
}

function AssetDialog({ ip, asset, onClose }: { ip: string; asset: Asset | null; onClose: () => void }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [form, setForm] = useState({
    hostname: asset?.hostname ?? '', owner: asset?.owner ?? '', os: asset?.os ?? '',
    criticality: asset?.criticality ?? 'medium', tags: (asset?.tags ?? []).join(', '),
  })
  const save = useMutation({
    mutationFn: () => patch(`/api/assets/${encodeURIComponent(ip)}`, { ...form, tags: form.tags.split(',').map((t) => t.trim()).filter(Boolean) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['entity'] }); qc.invalidateQueries({ queryKey: ['assets'] }); toast('Asset saved'); onClose() },
    onError: (e) => toast(errorText(e), true),
  })
  const field = (k: keyof typeof form, label: string) => (
    <label className="field"><span>{label}</span><input className="input" value={form[k]} onChange={(e) => setForm({ ...form, [k]: e.target.value })} /></label>
  )
  return (
    <Modal title={`Asset ${ip}`} onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" onClick={() => save.mutate()} disabled={save.isPending}>Save</button></>}>
      <div className="form">
        {field('hostname', 'Hostname')}
        {field('owner', 'Owner / team')}
        {field('os', 'Operating system')}
        <label className="field"><span>Criticality</span>
          <select className="select" value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value as Asset['criticality'] })}>
            <option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical (crown jewel)</option>
          </select>
          <span className="hint">Alerts touching critical assets get a higher risk score.</span>
        </label>
        {field('tags', 'Tags (comma separated)')}
      </div>
    </Modal>
  )
}

export default function Entity() {
  const { ip = '' } = useParams()
  const [hours, setHours] = useState(24)
  const [editing, setEditing] = useState(false)
  const canEdit = useCan('analyst')
  const qc = useQueryClient()
  const toast = useToast()
  const { data, error, isLoading } = useQuery({ queryKey: ['entity', ip, hours], queryFn: () => get<EntityData>(`/api/entities/ip/${encodeURIComponent(ip)}`, { hours }) })
  const block = useMutation({
    mutationFn: () => post('/api/indicators', { value: ip, threat: 'Added from entity page', confidence: 80 }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['entity'] }); toast(`${ip} added to the indicator list`) },
    onError: (e) => toast(errorText(e), true),
  })

  if (isLoading) return <Skeleton rows={10} />
  if (error || !data) return <ErrorBox error={error ?? 'Not found'} />
  const t = data.traffic
  const peers = (list: Peer[]) => list.map((p) => ({ key: p.ip, label: <><Ip ip={p.ip} /> <span className="faint" style={{ fontSize: 12 }}><Country code={p.country} /></span></>, value: p.bytes, display: bytes(p.bytes) }))

  return (
    <>
      <PageHead
        crumbs={<span>Entities</span>}
        title={<span className="mono" style={{ fontSize: 22 }}>{data.ip}</span>}
        sub={<span style={{ display: 'inline-flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <span className="badge tag">{data.internal ? 'Internal' : 'External'}</span>
          {data.asset?.hostname && <span>{data.asset.hostname}</span>}
          {data.country && <Country code={data.country} name />}
          {data.indicator && <span className="badge" style={{ background: 'var(--danger-bg)', color: 'var(--danger)' }}><ShieldAlert size={12} /> {data.indicator.threat || 'Known bad'}</span>}
        </span>}
        actions={<>
          <Seg value={hours} onChange={setHours} label="Range" options={[{ value: 1, label: '1h' }, { value: 24, label: '24h' }, { value: 168, label: '7d' }]} />
          {canEdit && <Link className="btn" to={`/intel?lookup=${encodeURIComponent(data.ip)}`}>Reputation</Link>}
          {canEdit && data.internal && <button className="btn" onClick={() => setEditing(true)}><Pencil size={13} /> Asset details</button>}
          {canEdit && !data.internal && !data.indicator && <button className="btn" onClick={() => block.mutate()}>Mark as malicious</button>}
        </>}
      />
      <div className="grid">
        <div className="grid cols-4">
          <div className="card kpi"><div className="label">Flows</div><div className="value">{num(t.flows)}</div></div>
          <div className="card kpi"><div className="label">Traffic</div><div className="value">{bytes(t.bytes)}</div><div className="note">{bytes(t.bytesSent)} sent</div></div>
          <div className="card kpi"><div className="label">Alerts</div><div className="value">{data.alerts.length}</div><div className="note">{data.alerts.filter((a) => a.status !== 'closed').length} open</div></div>
          <div className="card kpi"><div className="label">Last seen</div><div className="value" style={{ fontSize: 18, marginTop: 8 }}><Ago iso={t.lastSeen} /></div><div className="note">first seen {dateTime(t.firstSeen)}</div></div>
        </div>

        <Card title="Activity">
          {t.activity.length ? <TrafficArea data={t.activity} step={t.stepSeconds} metric="bytes" height={180} /> : <Empty title="No traffic in this range" />}
        </Card>

        <div className="grid cols-3">
          <Card title="Talks to" sub="Outbound, by bytes"><BarList items={peers(t.peersOut)} /></Card>
          <Card title="Contacted by" sub="Inbound, by bytes"><BarList items={peers(t.peersIn)} /></Card>
          <Card title="Services"><BarList items={t.ports.map((p) => ({ key: `${p.port}${p.protocol}`, label: <span className="mono">{portLabel(p.port)} <span className="faint">{p.protocol}</span></span>, value: p.flows }))} /></Card>
        </div>

        <div className="grid cols-2">
          <Card title="Alerts" flush>
            {data.alerts.length === 0 ? <Empty title="No alerts involve this address" /> : (
              <table className="data">
                <tbody>
                  {data.alerts.slice(0, 20).map((a) => (
                    <tr key={a.id}>
                      <td style={{ width: 90 }}><Sev s={a.severity} /></td>
                      <td><Link to={`/alerts/${a.id}`} className="title-text">{a.title}</Link><div className="sub"><Ago iso={a.lastSeen} /></div></td>
                      <td><Mitre id={a.mitreTechnique} /></td>
                      <td><Status s={a.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
          <div className="grid">
            {data.asset && (
              <Card title="Asset">
                <dl className="kv">
                  <dt>Hostname</dt><dd>{data.asset.hostname || '—'}</dd>
                  <dt>Owner</dt><dd>{data.asset.owner || '—'}</dd>
                  <dt>OS</dt><dd>{data.asset.os || '—'}</dd>
                  <dt>Criticality</dt><dd style={{ textTransform: 'capitalize' }}>{data.asset.criticality}</dd>
                  <dt>Tags</dt><dd>{data.asset.tags.length ? data.asset.tags.map((x) => <span key={x} className="badge tag" style={{ marginRight: 4 }}>{x}</span>) : '—'}</dd>
                </dl>
              </Card>
            )}
            <Card title="Reputation" sub="Cached lookups">
              {Object.keys(data.intel).length === 0 ? (
                <span className="faint">Not looked up yet.{canEdit && <> <Link className="ip" to={`/intel?lookup=${encodeURIComponent(data.ip)}`}>Look it up</Link></>}</span>
              ) : (
                <dl className="kv">
                  {Object.entries(data.intel).map(([k, v]) => (
                    <div key={k} style={{ display: 'contents' }}><dt>{v.provider ?? k}</dt><dd>{v.summary}</dd></div>
                  ))}
                </dl>
              )}
            </Card>
            <Card title="Log mentions" flush>
              {data.logs.length === 0 ? <Empty title="No log lines mention this address" /> : (
                <table className="data">
                  <tbody>
                    {data.logs.slice(0, 10).map((l) => (
                      <tr key={l.id}><td className="muted nowrap" style={{ width: 130 }}>{dateTime(l.at)}</td><td className="mono" style={{ fontSize: 12 }}>{l.host} {l.app}: {l.message}</td></tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
          </div>
        </div>
      </div>
      {editing && <AssetDialog ip={data.ip} asset={data.asset} onClose={() => setEditing(false)} />}
    </>
  )
}
