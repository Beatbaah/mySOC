import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, Plus } from 'lucide-react'
import { useMe } from '../../api/auth'
import { get, patch, post } from '../../api/client'
import type { Role, UserRow } from '../../api/types'
import { Ago, Card, ErrorBox, errorText, Modal, PageHead, Skeleton, useToast } from '../../components/ui'

const ROLE_HELP: Record<Role, string> = {
  viewer: 'Can see everything, change nothing.',
  analyst: 'Triages alerts, runs cases and hunts, manages indicators and assets.',
  admin: 'Everything, plus people, rules and settings. Must use an authenticator app.',
}

function OneTimePassword({ username, password, onClose }: { username: string; password: string; onClose: () => void }) {
  const toast = useToast()
  return (
    <Modal title="Temporary password" onClose={onClose} footer={<button className="btn primary" onClick={onClose}>Done</button>}>
      <div className="form">
        <p>Give this to <strong>{username}</strong> over a trusted channel. It works once; they’ll choose their own at sign-in. It won’t be shown again.</p>
        <div className="btn-row">
          <code className="mono" style={{ fontSize: 16, padding: '8px 12px', background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 6, flex: 1 }}>{password}</code>
          <button className="btn" onClick={() => navigator.clipboard.writeText(password).then(() => toast('Copied'))}><Copy size={13} /> Copy</button>
        </div>
      </div>
    </Modal>
  )
}

export default function Users() {
  const me = useMe()
  const qc = useQueryClient()
  const toast = useToast()
  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState({ username: '', displayName: '', role: 'analyst' as Role })
  const [secret, setSecret] = useState<{ username: string; password: string } | null>(null)
  const { data, error, isLoading } = useQuery({ queryKey: ['users'], queryFn: () => get<{ items: UserRow[] }>('/api/users') })
  const refresh = () => qc.invalidateQueries({ queryKey: ['users'] })
  const create = useMutation({
    mutationFn: () => post<{ user: UserRow; temporaryPassword: string }>('/api/users', form),
    onSuccess: (r) => { refresh(); setAdding(false); setSecret({ username: r.user.username, password: r.temporaryPassword }); setForm({ username: '', displayName: '', role: 'analyst' }) },
    onError: (e) => toast(errorText(e), true),
  })
  const update = useMutation({
    mutationFn: ({ id, body }: { id: number; body: Record<string, unknown> }) => patch(`/api/users/${id}`, body),
    onSuccess: refresh,
    onError: (e) => toast(errorText(e), true),
  })
  const action = useMutation({
    mutationFn: ({ u, what }: { u: UserRow; what: 'reset-password' | 'reset-mfa' | 'unlock' }) => post<{ temporaryPassword?: string }>(`/api/users/${u.id}/${what}`).then((r) => ({ r, u, what })),
    onSuccess: ({ r, u, what }) => {
      refresh()
      if (r.temporaryPassword) setSecret({ username: u.username, password: r.temporaryPassword })
      else toast(what === 'reset-mfa' ? `Authenticator removed for ${u.username}` : `${u.username} unlocked`)
    },
    onError: (e) => toast(errorText(e), true),
  })

  return (
    <>
      <PageHead title="People" sub="Who can use mySOC and what they can do."
        actions={<button className="btn primary" onClick={() => setAdding(true)}><Plus size={14} /> Add person</button>} />
      <ErrorBox error={error} />
      <Card flush>
        {isLoading ? <Skeleton rows={5} /> : (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Person</th><th>Role</th><th>Two-step</th><th>Status</th><th>Last sign-in</th><th /></tr></thead>
              <tbody>
                {data?.items.map((u) => (
                  <tr key={u.id} style={{ opacity: u.isActive ? 1 : 0.5 }}>
                    <td><div className="title-text">{u.displayName}</div><div className="sub">@{u.username}{u.id === me.id ? ' (you)' : ''}</div></td>
                    <td>
                      <select className="select" style={{ width: 120 }} value={u.role} disabled={u.id === me.id} aria-label={`Role for ${u.username}`}
                        onChange={(e) => update.mutate({ id: u.id, body: { role: e.target.value } })}>
                        <option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option>
                      </select>
                    </td>
                    <td>{u.mfaEnabled ? <span className="badge status-ok">On</span> : <span className="badge tag">Off</span>}</td>
                    <td className="nowrap">
                      {!u.isActive ? <span className="badge tag">Disabled</span> : u.locked ? <span className="badge" style={{ color: 'var(--danger)', background: 'var(--danger-bg)' }}>Locked</span> : u.mustChangePassword ? <span className="badge tag">Invited</span> : <span className="badge status-ok">Active</span>}
                    </td>
                    <td className="muted">{u.lastLoginAt ? <Ago iso={u.lastLoginAt} /> : 'never'}</td>
                    <td className="nowrap" style={{ textAlign: 'right' }}>
                      {u.locked && <button className="btn sm" onClick={() => action.mutate({ u, what: 'unlock' })}>Unlock</button>}{' '}
                      {u.id !== me.id && <button className="btn sm" onClick={() => action.mutate({ u, what: 'reset-password' })}>Reset password</button>}{' '}
                      {u.mfaEnabled && u.id !== me.id && <button className="btn sm" onClick={() => action.mutate({ u, what: 'reset-mfa' })}>Reset two-step</button>}{' '}
                      {u.id !== me.id && <button className="btn sm ghost" onClick={() => update.mutate({ id: u.id, body: { isActive: !u.isActive } })}>{u.isActive ? 'Disable' : 'Enable'}</button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {adding && (
        <Modal title="Add a person" onClose={() => setAdding(false)} footer={<><button className="btn" onClick={() => setAdding(false)}>Cancel</button><button className="btn primary" disabled={create.isPending || form.username.length < 2} onClick={() => create.mutate()}>Add</button></>}>
          <div className="form">
            <label className="field"><span>Username</span><input className="input" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value.toLowerCase() })} placeholder="lowercase, e.g. kofi.mensah" /></label>
            <label className="field"><span>Name</span><input className="input" value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} /></label>
            <label className="field"><span>Role</span>
              <select className="select" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
                <option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option>
              </select>
              <span className="hint">{ROLE_HELP[form.role]}</span>
            </label>
          </div>
        </Modal>
      )}
      {secret && <OneTimePassword {...secret} onClose={() => setSecret(null)} />}
    </>
  )
}
