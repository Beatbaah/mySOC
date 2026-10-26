import { useEffect, useState, type FormEvent } from 'react'
import { useAuth } from '../api/auth'
import { post } from '../api/client'
import type { SessionState } from '../api/types'
import { Logo } from '../components/Logo'
import { ErrorBox, errorText } from '../components/ui'

function Side() {
  return (
    <div className="auth-side">
      <div className="brand" style={{ padding: 0 }}>
        <div className="brand-mark"><Logo size={18} /></div>
        <div className="brand-name">my<b>SOC</b></div>
      </div>
      <div className="pitch">
        <h1>See the attack while it’s still a story, not an incident.</h1>
        <p>
          Network flows and device logs, checked against detections mapped to MITRE ATT&amp;CK, folded into a queue your
          team can actually work.
        </p>
        <svg className="trace" viewBox="0 30 520 250" aria-hidden>
          {Array.from({ length: 9 }, (_, i) => (
            <polyline
              key={i}
              fill="none"
              stroke={i === 5 ? 'var(--sev-high)' : 'var(--border-strong)'}
              strokeWidth={i === 5 ? 1.6 : 1}
              points={Array.from({ length: 27 }, (_, x) => {
                const spike = i === 5 && x > 15 && x < 20 ? 60 * Math.sin((x - 15) * 0.9) : 0
                return `${x * 20},${40 + i * 26 + 6 * Math.sin(x * 0.7 + i) - spike}`
              }).join(' ')}
            />
          ))}
        </svg>
      </div>
      <div className="faint" style={{ fontSize: 12 }}>Access is restricted and audited.</div>
    </div>
  )
}

function PasswordStep() {
  const { login, state } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(state.phase === 'signed-out' ? state.reason ?? null : null)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(username, password)
    } catch (err) {
      setError(errorText(err))
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="form" onSubmit={submit}>
      <div>
        <h2>Sign in</h2>
        <p className="lead">Use your mySOC account.</p>
      </div>
      {error && <ErrorBox error={error} />}
      <label className="field">
        <span>Username</span>
        <input className="input" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
      </label>
      <label className="field">
        <span>Password</span>
        <input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
      </label>
      <button className="btn primary" disabled={busy || !username || !password} style={{ height: 36 }}>
        {busy ? 'Signing in…' : 'Sign in'}
      </button>
    </form>
  )
}

function CodeField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <input
      className="input code-input"
      inputMode="numeric"
      autoComplete="one-time-code"
      maxLength={6}
      value={value}
      onChange={(e) => onChange(e.target.value.replace(/\D/g, ''))}
      aria-label="6-digit code"
      autoFocus
    />
  )
}

function VerifyStep() {
  const { accept, logout } = useAuth()
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      accept(await post<SessionState>('/api/auth/mfa/verify', { code }))
    } catch (err) {
      setError(errorText(err))
      setCode('')
    } finally {
      setBusy(false)
    }
  }
  return (
    <form className="form" onSubmit={submit}>
      <div>
        <h2>Two-step verification</h2>
        <p className="lead">Enter the 6-digit code from your authenticator app.</p>
      </div>
      {error && <ErrorBox error={error} />}
      <CodeField value={code} onChange={setCode} />
      <button className="btn primary" disabled={busy || code.length !== 6} style={{ height: 36 }}>Verify</button>
      <button type="button" className="btn ghost" onClick={() => logout()}>Use a different account</button>
    </form>
  )
}

function EnrollStep() {
  const { accept, logout } = useAuth()
  const [setup, setSetup] = useState<{ secret: string; qr: string } | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    post<{ secret: string; qr: string }>('/api/auth/mfa/enroll/start').then(setSetup, (e) => setError(errorText(e)))
  }, [])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      accept(await post<SessionState>('/api/auth/mfa/enroll/confirm', { code }))
    } catch (err) {
      setError(errorText(err))
      setCode('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="form" onSubmit={submit}>
      <div>
        <h2>Set up two-step verification</h2>
        <p className="lead">Admin accounts need an authenticator app (Google Authenticator, 1Password, Authy…). Scan the code, then enter the 6 digits it shows.</p>
      </div>
      {error && <ErrorBox error={error} />}
      {setup && (
        <>
          <img className="qr" src={setup.qr} alt="QR code for your authenticator app" />
          <details>
            <summary className="muted" style={{ cursor: 'pointer', fontSize: 12 }}>Can’t scan? Enter this key instead</summary>
            <code className="mono" style={{ display: 'block', marginTop: 6, wordBreak: 'break-all' }}>{setup.secret}</code>
          </details>
          <CodeField value={code} onChange={setCode} />
          <button className="btn primary" disabled={busy || code.length !== 6} style={{ height: 36 }}>Turn on and continue</button>
        </>
      )}
      <button type="button" className="btn ghost" onClick={() => logout()}>Cancel</button>
    </form>
  )
}

export function Login() {
  const { state } = useAuth()
  return (
    <div className="auth">
      <Side />
      <main className="auth-main">
        <div className="auth-card">
          {state.phase === 'mfa' ? state.step === 'verify' ? <VerifyStep /> : <EnrollStep /> : <PasswordStep />}
          <p className="auth-fine">Sessions end after 30 minutes without activity.</p>
        </div>
      </main>
    </div>
  )
}
