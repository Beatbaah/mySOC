import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { del, get, put } from '../../api/client'
import type { Sensor } from '../../api/types'
import { Ago, Card, ErrorBox, errorText, Modal, PageHead, Skeleton, useToast } from '../../components/ui'
import { bytes, num } from '../../lib/format'

interface SettingsView {
  sensors: Sensor[]
  sensor: { source: string; syslog: boolean; syslogPort: number; internalNetworks: string[]; allowlist: string[]; dedupMinutes: number; geoip: boolean }
  retention: { flowsDays: number; logsDays: number; alertsDays: number }
  security: { sessionIdleMinutes: number; sessionMaxHours: number; adminMfaRequired: boolean; vaultKeyConfigured: boolean; environment: string }
  notifications: { email: boolean; emailTo: string[]; telegram: boolean }
  secrets: { key: string; label: string; set: boolean; updatedAt: string | null }[]
}

const yes = (b: boolean) => (b ? <span className="badge status-ok">Yes</span> : <span className="badge tag">No</span>)

export default function Settings() {
  const qc = useQueryClient()
  const toast = useToast()
  const [editing, setEditing] = useState<{ key: string; label: string } | null>(null)
  const [value, setValue] = useState('')
  const { data, error, isLoading } = useQuery({ queryKey: ['settings'], queryFn: () => get<SettingsView>('/api/settings'), refetchInterval: 15_000 })
  const save = useMutation({
    mutationFn: () => put(`/api/settings/secrets/${editing!.key}`, { value }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['settings'] }); toast('Saved (encrypted)'); setEditing(null); setValue('') },
    onError: (e) => toast(errorText(e), true),
  })
  const remove = useMutation({
    mutationFn: (key: string) => del(`/api/settings/secrets/${key}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings'] }),
    onError: (e) => toast(errorText(e), true),
  })
  if (isLoading) return <Skeleton rows={10} />
  if (error || !data) return <ErrorBox error={error} />
  return (
    <>
      <PageHead title="Settings" sub="Most settings come from environment variables (see the README) so they can be reviewed and versioned. API keys are set here and stored encrypted." />
      <div className="grid">
        {!data.security.vaultKeyConfigured && (
          <div className="note-box">MYSOC_VAULT_KEY isn’t set, so secrets are encrypted with a development key kept on this machine. Set the variable before going to production.</div>
        )}
        <Card title="Sensors" flush>
          <table className="data">
            <thead><tr><th>Sensor</th><th>Source</th><th>Status</th><th className="num">Flows</th><th className="num">Traffic</th><th className="num">Alerts</th><th>ML model</th><th>Started</th></tr></thead>
            <tbody>
              {data.sensors.map((s) => (
                <tr key={s.name}>
                  <td>{s.name}</td>
                  <td><span className="badge tag">{s.source}</span></td>
                  <td>{s.online ? <span className="badge status-ok">Online</span> : <span className="badge" style={{ color: 'var(--danger)', background: 'var(--danger-bg)' }}>Offline · <Ago iso={s.lastSeen} /></span>}</td>
                  <td className="num">{num(s.stats.flows)}</td>
                  <td className="num">{bytes(s.stats.bytes)}</td>
                  <td className="num">{num(s.stats.alerts)}</td>
                  <td className="muted">{s.stats.ml?.trained ? `trained on ${num(s.stats.ml.training_flows)} flows` : 'learning'}</td>
                  <td className="muted"><Ago iso={s.startedAt} /></td>
                </tr>
              ))}
              {data.sensors.length === 0 && <tr><td colSpan={8} className="faint">No sensor has reported yet.</td></tr>}
            </tbody>
          </table>
        </Card>

        <Card title="Integrations" sub="Write-only: values are never sent back to the browser." flush>
          <table className="data">
            <tbody>
              {data.secrets.map((x) => (
                <tr key={x.key}>
                  <td>{x.label}</td>
                  <td>{x.set ? <span className="badge status-ok">Set</span> : <span className="badge tag">Not set</span>}</td>
                  <td className="muted">{x.updatedAt ? <>updated <Ago iso={x.updatedAt} /></> : ''}</td>
                  <td style={{ textAlign: 'right' }} className="nowrap">
                    <button className="btn sm" onClick={() => { setEditing(x); setValue('') }}>{x.set ? 'Replace' : 'Set'}</button>{' '}
                    {x.set && <button className="btn sm ghost" onClick={() => remove.mutate(x.key)}>Remove</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        <div className="grid cols-3">
          <Card title="Detection">
            <dl className="kv">
              <dt>Source</dt><dd>{data.sensor.source}</dd>
              <dt>Syslog</dt><dd>{data.sensor.syslog ? `UDP ${data.sensor.syslogPort}` : 'off'}</dd>
              <dt>Internal networks</dt><dd className="mono">{data.sensor.internalNetworks.join(', ')}</dd>
              <dt>Never alert on</dt><dd className="mono">{data.sensor.allowlist.join(', ') || '—'}</dd>
              <dt>Fold repeats within</dt><dd>{data.sensor.dedupMinutes} min</dd>
              <dt>GeoIP database</dt><dd>{yes(data.sensor.geoip)}</dd>
            </dl>
          </Card>
          <Card title="Security">
            <dl className="kv">
              <dt>Environment</dt><dd>{data.security.environment}</dd>
              <dt>Idle sign-out</dt><dd>{data.security.sessionIdleMinutes} min</dd>
              <dt>Max session</dt><dd>{data.security.sessionMaxHours} h</dd>
              <dt>Admins need 2-step</dt><dd>{yes(data.security.adminMfaRequired)}</dd>
              <dt>Vault key set</dt><dd>{yes(data.security.vaultKeyConfigured)}</dd>
            </dl>
          </Card>
          <Card title="Retention & notifications">
            <dl className="kv">
              <dt>Flows</dt><dd>{data.retention.flowsDays} days</dd>
              <dt>Logs</dt><dd>{data.retention.logsDays} days</dd>
              <dt>Closed alerts</dt><dd>{data.retention.alertsDays} days</dd>
              <dt>Email</dt><dd>{data.notifications.email ? data.notifications.emailTo.join(', ') : yes(false)}</dd>
              <dt>Telegram</dt><dd>{yes(data.notifications.telegram)}</dd>
            </dl>
          </Card>
        </div>
      </div>
      {editing && (
        <Modal title={editing.label} onClose={() => setEditing(null)} footer={<><button className="btn" onClick={() => setEditing(null)}>Cancel</button><button className="btn primary" disabled={!value.trim() || save.isPending} onClick={() => save.mutate()}>Save</button></>}>
          <label className="field"><span>Value</span>
            <input className="input mono" type="password" autoComplete="off" value={value} onChange={(e) => setValue(e.target.value)} />
            <span className="hint">Stored encrypted. The change is recorded in the audit log (the value isn’t).</span>
          </label>
        </Modal>
      )}
    </>
  )
}
