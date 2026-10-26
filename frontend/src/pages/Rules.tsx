import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2 } from 'lucide-react'
import { useCan } from '../api/auth'
import { del, get, patch, post } from '../api/client'
import type { Rule, Severity } from '../api/types'
import { Ago, Card, ErrorBox, errorText, Mitre, Modal, PageHead, Sev, Skeleton, useToast } from '../components/ui'
import { SEVERITIES } from '../lib/format'

const PARAM_HELP: Record<string, string> = {
  distinct_ports: 'Distinct ports', window_seconds: 'Window (seconds)', syn_packets: 'SYN packets', icmp_packets: 'ICMP packets',
  connections: 'Connections', queries: 'DNS queries', bytes: 'Bytes', min_connections: 'Minimum connections',
  max_jitter: 'Maximum jitter (0–1)', lookback_seconds: 'Look-back (seconds)', distinct_hosts: 'Distinct hosts', failures: 'Failed logins',
  min_training_flows: 'Flows before training', score_threshold: 'Score threshold', ports: 'Ports',
}

function TuneDialog({ rule, onClose }: { rule: Rule; onClose: () => void }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [severity, setSeverity] = useState<Severity>(rule.severity)
  const [params, setParams] = useState<Record<string, string>>(() =>
    Object.fromEntries(Object.entries(rule.params).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v)])))
  const save = useMutation({
    mutationFn: () => {
      const out: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(params)) {
        const orig = rule.params[k]
        out[k] = Array.isArray(orig) ? v.split(',').map((x) => Number(x.trim())).filter((x) => !Number.isNaN(x))
          : typeof orig === 'object' ? JSON.parse(v) : Number(v)
      }
      return patch(`/api/rules/${rule.id}`, { severity, params: out })
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['rules'] }); toast('Rule updated. The sensor picks it up within seconds.'); onClose() },
    onError: (e) => toast(e instanceof SyntaxError ? 'Conditions must be valid JSON.' : errorText(e), true),
  })
  return (
    <Modal title={`Tune ${rule.id}: ${rule.name}`} onClose={onClose} wide footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" onClick={() => save.mutate()} disabled={save.isPending}>Save</button></>}>
      <div className="form">
        <p className="muted">{rule.description}</p>
        <label className="field"><span>Severity</span>
          <select className="select" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select>
        </label>
        {Object.entries(params).map(([k, v]) => (
          <label className="field" key={k}><span>{PARAM_HELP[k] ?? k}</span>
            {typeof rule.params[k] === 'object' && !Array.isArray(rule.params[k])
              ? <textarea className="textarea mono" value={v} onChange={(e) => setParams({ ...params, [k]: e.target.value })} />
              : <input className="input mono" value={v} onChange={(e) => setParams({ ...params, [k]: e.target.value })} />}
          </label>
        ))}
      </div>
    </Modal>
  )
}

function NewRuleDialog({ fields, onClose }: { fields: Record<string, string>; onClose: () => void }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState<Severity>('medium')
  const [technique, setTechnique] = useState('')
  const [tactic, setTactic] = useState('')
  const [conditions, setConditions] = useState('{\n  "protocol": "TCP",\n  "dst_port": 21,\n  "dst_internal": false\n}')
  const save = useMutation({
    mutationFn: () => post('/api/rules', { name, description, severity, mitreTechnique: technique, mitreTactic: tactic, conditions: JSON.parse(conditions) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['rules'] }); toast('Rule created'); onClose() },
    onError: (e) => toast(e instanceof SyntaxError ? 'Conditions must be valid JSON.' : errorText(e), true),
  })
  return (
    <Modal title="New match rule" onClose={onClose} wide footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={name.trim().length < 3 || save.isPending} onClick={() => save.mutate()}>Create</button></>}>
      <div className="form">
        <label className="field"><span>Name</span><input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. FTP to the internet" /></label>
        <label className="field"><span>Why it matters</span><input className="input" value={description} onChange={(e) => setDescription(e.target.value)} /></label>
        <div className="grid cols-3">
          <label className="field"><span>Severity</span><select className="select" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select></label>
          <label className="field"><span>ATT&CK technique</span><input className="input mono" value={technique} onChange={(e) => setTechnique(e.target.value)} placeholder="T1048" /></label>
          <label className="field"><span>Tactic</span><input className="input" value={tactic} onChange={(e) => setTactic(e.target.value)} placeholder="Exfiltration" /></label>
        </div>
        <label className="field"><span>Conditions (all must match)</span>
          <textarea className="textarea mono" style={{ minHeight: 120 }} value={conditions} onChange={(e) => setConditions(e.target.value)} />
          <span className="hint">Fields: {Object.entries(fields).map(([k, v]) => `${k} (${v})`).join(' · ')}</span>
        </label>
      </div>
    </Modal>
  )
}

export default function Rules() {
  const isAdmin = useCan('admin')
  const qc = useQueryClient()
  const toast = useToast()
  const [tuning, setTuning] = useState<Rule | null>(null)
  const [creating, setCreating] = useState(false)
  const { data, error, isLoading } = useQuery({ queryKey: ['rules'], queryFn: () => get<{ items: Rule[]; matchFields: Record<string, string> }>('/api/rules') })
  const toggle = useMutation({
    mutationFn: (r: Rule) => patch(`/api/rules/${r.id}`, { enabled: !r.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
    onError: (e) => toast(errorText(e), true),
  })
  const remove = useMutation({
    mutationFn: (r: Rule) => del(`/api/rules/${r.id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
    onError: (e) => toast(errorText(e), true),
  })
  const groups: [string, Rule[]][] = data ? [
    ['Built-in detections', data.items.filter((r) => r.kind === 'builtin')],
    ['Match rules', data.items.filter((r) => r.kind === 'match')],
  ] : []
  return (
    <>
      <PageHead title="Detection rules" sub="What the sensor looks for. Changes apply live, without restarting anything."
        actions={isAdmin && <button className="btn primary" onClick={() => setCreating(true)}><Plus size={14} /> New match rule</button>} />
      <ErrorBox error={error} />
      {isLoading ? <Skeleton rows={10} /> : (
        <div className="grid">
          {groups.map(([title, rules]) => (
            <Card key={title} title={title} flush>
              <table className="data">
                <thead><tr><th style={{ width: 70 }}>On</th><th>Rule</th><th>Severity</th><th>Technique</th><th className="num">Alerts (7d)</th><th className="num">False positives</th><th>Last alert</th>{isAdmin && <th />}</tr></thead>
                <tbody>
                  {rules.map((r) => (
                    <tr key={r.id} style={{ opacity: r.enabled ? 1 : 0.55 }}>
                      <td>
                        <label style={{ display: 'inline-flex', gap: 6, alignItems: 'center', cursor: isAdmin ? 'pointer' : 'default' }}>
                          <input type="checkbox" checked={r.enabled} disabled={!isAdmin || toggle.isPending} onChange={() => toggle.mutate(r)} aria-label={`${r.enabled ? 'Disable' : 'Enable'} ${r.name}`} />
                        </label>
                      </td>
                      <td className="title-cell">
                        <div className="title-text"><span className="mono faint">{r.id}</span> {r.name}</div>
                        <div className="sub" style={{ maxWidth: 560 }}>{r.description}</div>
                      </td>
                      <td><Sev s={r.severity} /></td>
                      <td><Mitre id={r.mitreTechnique} tactic={r.mitreTactic} /></td>
                      <td className="num"><Link to={`/alerts?rule=${r.id}&view=all`}>{r.stats.alerts7d ?? 0}</Link></td>
                      <td className="num" style={{ color: r.stats.falsePositives7d ? 'var(--sev-medium)' : undefined }}>{r.stats.falsePositives7d ?? 0}</td>
                      <td className="muted">{r.stats.lastAlert ? <Ago iso={r.stats.lastAlert} /> : '—'}</td>
                      {isAdmin && (
                        <td className="nowrap" style={{ width: 120 }}>
                          <button className="btn sm" onClick={() => setTuning(r)}>Tune</button>{' '}
                          {r.kind === 'match' && <button className="btn sm ghost icon" aria-label={`Delete ${r.name}`} onClick={() => remove.mutate(r)}><Trash2 size={13} /></button>}
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          ))}
        </div>
      )}
      {tuning && <TuneDialog rule={tuning} onClose={() => setTuning(null)} />}
      {creating && data && <NewRuleDialog fields={data.matchFields} onClose={() => setCreating(false)} />}
    </>
  )
}
