import { useEffect, useState, type FormEvent } from 'react'
import { useAuth } from '../api/auth'
import { post } from '../api/client'
import type { SessionState } from '../api/types'
import { Logo } from '../components/Logo'
import { ErrorBox, errorText } from '../components/ui'

// Sharp up-down-settle shape of the alert spike, u in units of 20 px from its start.
const SPIKE: [number, number][] = [[0, 0], [1, 48], [1.6, 58], [3, -26], [3.9, 0]]
function spikeShape(u: number) {
  for (let k = 1; k < SPIKE.length; k++) {
    const [u0, y0] = SPIKE[k - 1]
    const [u1, y1] = SPIKE[k]
    if (u >= u0 && u <= u1) return y0 + ((u - u0) / (u1 - u0)) * (y1 - y0)
  }
  return 0
}

// Twelve hosts' traffic drifting left like a live monitor. Every few seconds the demo's compromised workstation
// spikes: the spike runs along its lane with a glowing tail and an alert tag riding its peak.
// With reduced motion it holds still with the spike in view.
const HOSTS = ['10.20.0.12', '10.20.0.19', '10.20.0.22', '10.20.0.31', '10.20.0.40', '10.20.0.45', '10.20.0.58',
  '10.10.0.10', '10.10.0.20', '10.10.0.25', '10.10.0.30', '10.10.0.53']
const HOT = 5 // 10.20.0.45
const W = 640
const X0 = 148 // lanes start after the host labels
const LANE = 24
const TOP = 70

function Trace() {
  const [t, setT] = useState(4)
  useEffect(() => {
    // Still under reduced motion; and no loop at all where the panel is hidden (narrow screens).
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || !window.matchMedia('(min-width: 861px)').matches) return
    let raf = 0
    const start = performance.now() - 4000
    const tick = (now: number) => {
      setT((now - start) / 1000)
      raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [])

  const spikeAt = W + 20 - ((t * 70) % 760) // off-screen for about 3 s of each ~11 s loop
  const live = spikeAt > X0 - 40 && spikeAt < W
  const laneY = (i: number, x: number) =>
    TOP + i * LANE + 4.5 * Math.sin(x * 0.034 + i * 1.7 + t * 0.9) + 2 * Math.sin(x * 0.11 + i * 2.3 + t * 1.6)
  const line = (i: number) =>
    Array.from({ length: (W - X0) / 4 + 1 }, (_, n) => {
      const x = X0 + n * 4
      const y = laneY(i, x) - (i === HOT ? spikeShape((x - spikeAt) / 20) : 0)
      return `${x},${y.toFixed(1)}`
    }).join(' ')
  const peakX = spikeAt + 32
  const peakY = laneY(HOT, peakX) - 58

  return (
    <svg className="trace" viewBox={`0 0 ${W} ${TOP + HOSTS.length * LANE}`} aria-hidden>
      <defs>
        {/* The spike travels left, so its tail trails off to the right. */}
        <linearGradient id="trace-tail" gradientUnits="userSpaceOnUse" x1={spikeAt - 30} x2={spikeAt + 300} y1="0" y2="0">
          <stop offset="0" stopColor="var(--sev-high)" stopOpacity="0" />
          <stop offset="0.08" stopColor="var(--sev-high)" stopOpacity="1" />
          <stop offset="0.35" stopColor="var(--sev-high)" stopOpacity="1" />
          <stop offset="1" stopColor="var(--sev-high)" stopOpacity="0" />
        </linearGradient>
        <filter id="trace-glow" x="-10%" y="-50%" width="120%" height="200%"><feGaussianBlur stdDeviation="4" /></filter>
        <linearGradient id="trace-in" gradientUnits="userSpaceOnUse" x1={X0} x2={X0 + 70} y1="0" y2="0">
          <stop offset="0" stopColor="#fff" stopOpacity="0" />
          <stop offset="1" stopColor="#fff" stopOpacity="1" />
        </linearGradient>
        <mask id="trace-fade"><rect x="0" y="0" width={W} height="1000" fill="url(#trace-in)" /></mask>
      </defs>
      {HOSTS.map((h, i) => (
        <text key={h} x="48" y={TOP + i * LANE + 4} className={`trace-host${i === HOT && live ? ' hot' : ''}`}>{h}</text>
      ))}
      <g mask="url(#trace-fade)">
        {HOSTS.map((h, i) => (
          <polyline key={h} points={line(i)} className="trace-lane" />
        ))}
        <polyline points={line(HOT)} className="trace-alert glow" stroke="url(#trace-tail)" filter="url(#trace-glow)" />
        <polyline points={line(HOT)} className="trace-alert" stroke="url(#trace-tail)" />
      </g>
      {live && (
        <g transform={`translate(${Math.min(Math.max(peakX, X0 + 10), W - 190)} ${peakY - 34})`} className="trace-tag">
          <rect width="180" height="24" rx="6" />
          <rect x="10" y="8.5" width="7" height="7" rx="1.5" className="dot" />
          <text x="24" y="16">Beaconing to 198.51.100.77</text>
        </g>
      )}
    </svg>
  )
}

function Side() {
  return (
    <div className="auth-side">
      <div className="brand" style={{ padding: 0 }}>
        <Logo />
      </div>
      <div className="pitch">
        <h1>See the attack while it’s still a story, not an incident.</h1>
        <p>
          Network flows and device logs, checked against detections mapped to MITRE ATT&amp;CK, folded into a queue your
          team can actually work.
        </p>
      </div>
      <Trace />
      <div className="muted" style={{ fontSize: 12 }}>Access is restricted and audited.</div>
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
    if (!username || !password) {
      setError('Enter your username and password.')
      return
    }
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
    <form className="form" onSubmit={submit} noValidate>
      <div>
        <h2>Sign in</h2>
        <p className="lead">Your administrator gives you an account.</p>
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
      <button className="btn primary" disabled={busy}>
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
    if (code.length !== 6) {
      setError('Enter the 6-digit code from your authenticator app.')
      return
    }
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
    <form className="form" onSubmit={submit} noValidate>
      <div>
        <h2>Two-step verification</h2>
        <p className="lead">Enter the 6-digit code from your authenticator app.</p>
      </div>
      {error && <ErrorBox error={error} />}
      <CodeField value={code} onChange={setCode} />
      <button className="btn primary" disabled={busy}>Verify</button>
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
    if (code.length !== 6) {
      setError('Enter the 6-digit code from your authenticator app.')
      return
    }
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
    <form className="form" onSubmit={submit} noValidate>
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
          <button className="btn primary" disabled={busy}>Turn on and continue</button>
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
