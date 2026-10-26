import { useState, type FormEvent } from 'react'
import { useAuth, useMe } from '../api/auth'
import { post } from '../api/client'
import { Card, ErrorBox, errorText, PageHead, useToast } from '../components/ui'

export function ChangePassword({ forced }: { forced?: boolean }) {
  const { refresh } = useAuth()
  const toast = useToast()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [again, setAgain] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (next !== again) return setError('The new passwords don’t match.')
    setBusy(true)
    setError(null)
    try {
      await post('/api/auth/password', { current, new: next })
      toast('Password changed. Other sessions were signed out.')
      setCurrent('')
      setNext('')
      setAgain('')
      await refresh()
    } catch (err) {
      setError(errorText(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <form className="form" onSubmit={submit} style={{ maxWidth: 380 }}>
      {forced && <div className="note-box">Choose your own password before you start. The one you were given only works once.</div>}
      {error && <ErrorBox error={error} />}
      <label className="field">
        <span>Current password</span>
        <input className="input" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
      </label>
      <label className="field">
        <span>New password</span>
        <input className="input" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required minLength={12} />
        <span className="hint">At least 12 characters. A few unrelated words works well.</span>
      </label>
      <label className="field">
        <span>New password again</span>
        <input className="input" type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} required />
      </label>
      <div><button className="btn primary" disabled={busy}>Change password</button></div>
    </form>
  )
}

export function Account() {
  const me = useMe()
  return (
    <>
      <PageHead title="Password & sign-in" sub={`Signed in as ${me.username} (${me.role})`} />
      <div className="grid cols-2">
        <Card title="Change password"><ChangePassword /></Card>
        <Card title="Two-step verification">
          {me.mfaEnabled ? (
            <p>An authenticator app is set up for your account. If you lose your phone, ask an admin to reset it.</p>
          ) : (
            <p className="muted">
              Not set up. Admin accounts are asked to set one up at sign-in; analysts and viewers can ask an admin to require it.
            </p>
          )}
        </Card>
      </div>
    </>
  )
}
