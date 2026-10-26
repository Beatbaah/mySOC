import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import {
  Activity, Bell, BookOpen, Briefcase, ChevronDown, Crosshair, FileText, Gauge, KeyRound, LogOut, Moon, Network,
  PanelLeftClose, PanelLeftOpen, ScrollText, Server, Settings, ShieldCheck, SlidersHorizontal, Sun, Repeat, UserRound, Users,
} from 'lucide-react'
import { useAuth, useCan, useMe } from '../api/auth'
import { LiveProvider, useLive } from '../api/live'
import { applyTheme, initialTheme, type Theme } from '../lib/theme'
import { Logo, LogoMark } from './Logo'
import { GlobalSearch } from './Search'
import { Ticker } from './ui'
import { useSegIndicators } from '../lib/motion'

function NavItem({ to, icon, children, count, hot }: { to: string; icon: ReactNode; children: string; count?: number; hot?: boolean }) {
  return (
    <NavLink to={to} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} end={to === '/'} data-tip={children}>
      {icon}
      <span className="nav-text">{children}</span>
      {count ? <span className={`count ${hot ? 'hot' : ''}`}><Ticker value={count} /></span> : null}
    </NavLink>
  )
}

function Sidebar({ rail, onToggle }: { rail: boolean; onToggle: () => void }) {
  const isAdmin = useCan('admin')
  const { pulse } = useLive()
  const open = pulse?.openBySeverity
  const urgent = open ? open.critical + open.high : 0
  const sensors = pulse?.sensors ?? []
  const { pathname } = useLocation()

  // One highlight slides to the active page, like the segmented controls. It's the nav's ::before,
  // placed through --nav-y / --nav-h, and only switched on after its first position so it doesn't fly in.
  const navRef = useRef<HTMLElement>(null)
  const placeHighlight = useCallback(() => {
    const nav = navRef.current
    const active = nav?.querySelector<HTMLElement>('.nav-link.active')
    if (!nav) return
    if (!active) {
      nav.removeAttribute('data-ind')
      return
    }
    const box = active.getBoundingClientRect()
    nav.style.setProperty('--nav-y', `${box.top - nav.getBoundingClientRect().top}px`)
    nav.style.setProperty('--nav-h', `${box.height}px`)
    if (!nav.hasAttribute('data-ind')) requestAnimationFrame(() => nav.setAttribute('data-ind', ''))
  }, [])
  useLayoutEffect(placeHighlight, [placeHighlight, pathname, rail, isAdmin])
  // Link sizes change when the web font arrives, on zoom and across breakpoints.
  useEffect(() => {
    window.addEventListener('resize', placeHighlight)
    document.fonts?.ready.then(placeHighlight)
    return () => window.removeEventListener('resize', placeHighlight)
  }, [placeHighlight])

  return (
    <aside className="sidebar" aria-label="Main navigation">
      <div className="brand">
        {rail ? <LogoMark size={26} /> : <Logo />}
      </div>
      <nav ref={navRef}>
        <div className="nav-group">
          <div className="nav-label">Monitor</div>
          <NavItem to="/" icon={<Gauge size={16} />}>Overview</NavItem>
          <NavItem to="/alerts" icon={<Bell size={16} />} count={urgent} hot={!!open?.critical}>Alerts</NavItem>
          <NavItem to="/cases" icon={<Briefcase size={16} />}>Cases</NavItem>
          <NavItem to="/traffic" icon={<Activity size={16} />}>Traffic</NavItem>
        </div>
        <div className="nav-group">
          <div className="nav-label">Investigate</div>
          <NavItem to="/hunt" icon={<Crosshair size={16} />}>Hunt</NavItem>
          <NavItem to="/intel" icon={<ShieldCheck size={16} />}>Threat intel</NavItem>
          <NavItem to="/logs" icon={<ScrollText size={16} />}>Logs</NavItem>
          <NavItem to="/assets" icon={<Server size={16} />}>Assets</NavItem>
        </div>
        <div className="nav-group">
          <div className="nav-label">Operate</div>
          <NavItem to="/handover" icon={<Repeat size={16} />}>Shift handover</NavItem>
          <NavItem to="/reports" icon={<FileText size={16} />}>Reports</NavItem>
          <NavItem to="/rules" icon={<SlidersHorizontal size={16} />}>Detection rules</NavItem>
        </div>
        {isAdmin && (
          <div className="nav-group">
            <div className="nav-label">Admin</div>
            <NavItem to="/admin/users" icon={<Users size={16} />}>People</NavItem>
            <NavItem to="/admin/settings" icon={<Settings size={16} />}>Settings</NavItem>
            <NavItem to="/admin/audit" icon={<BookOpen size={16} />}>Audit log</NavItem>
          </div>
        )}
      </nav>
      <div className="sidebar-foot">
        {sensors.length === 0 && (
          <div className="sensor-line"><span className="dot off" /> No sensor reporting</div>
        )}
        {sensors.map((s) => (
          <div className="sensor-line" key={s.name} title={s.online ? 'Sensor online' : 'Sensor offline'}>
            <span className={`dot ${s.online ? 'on' : 'off'}`} />
            <Network size={13} />
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.name}</span>
            <span className="mono faint sensor-rate">{s.online ? `${(s.flowsPerSecond ?? 0).toFixed(1)}/s` : 'offline'}</span>
          </div>
        ))}
        <button type="button" className="nav-link rail-toggle" onClick={onToggle} data-tip="Expand sidebar"
          aria-label={rail ? 'Expand sidebar' : 'Collapse sidebar'} title={rail ? undefined : 'Collapse sidebar ( [ )'}>
          {rail ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
          <span className="nav-text">Collapse</span>
        </button>
      </div>
    </aside>
  )
}

function UserMenu() {
  const me = useMe()
  const { logout } = useAuth()
  const nav = useNavigate()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const close = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false)
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [])
  return (
    <div style={{ position: 'relative' }} ref={ref}>
      <button className="btn ghost" onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-haspopup="menu">
        <UserRound size={15} />
        {me.displayName}
        <span className="badge tag" style={{ textTransform: 'capitalize' }}>{me.role}</span>
        <ChevronDown size={14} />
      </button>
      {open && (
        <div className="menu" role="menu">
          <button role="menuitem" onClick={() => { setOpen(false); nav('/account') }}><KeyRound size={14} /> Password & sign-in</button>
          <hr />
          <button role="menuitem" onClick={() => logout()}><LogOut size={14} /> Sign out</button>
        </div>
      )}
    </div>
  )
}

function Topbar() {
  const [theme, setTheme] = useState<Theme>(initialTheme)
  const { connected, pulse } = useLive()
  useEffect(() => applyTheme(theme), [theme])
  // The dot beats once per update from the server, so "Live" visibly is.
  const beats = useRef(0)
  const lastPulse = useRef(pulse)
  if (pulse !== lastPulse.current) {
    lastPulse.current = pulse
    beats.current += 1
  }
  return (
    <header className="topbar">
      <GlobalSearch />
      <div style={{ flex: 1 }} />
      <span className="badge tag" title={connected ? 'Receiving live updates' : 'Reconnecting…'}>
        <span key={beats.current} className={`dot ${connected ? 'on beat' : ''}`} /> {connected ? 'Live' : 'Reconnecting'}
      </span>
      <button className="btn ghost icon" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>
        {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
      </button>
      <UserMenu />
    </header>
  )
}

export function Layout() {
  const { refresh } = useAuth()
  const onExpired = useCallback(() => {
    refresh()
  }, [refresh])
  const { pathname } = useLocation()
  useSegIndicators()
  // The sidebar can shrink to an icon rail. The choice is a per-browser convenience.
  const [rail, setRail] = useState(() => {
    try {
      return localStorage.getItem('mysoc.sidebar') === 'rail'
    } catch {
      return false
    }
  })
  const toggleRail = useCallback(() => {
    setRail((r) => {
      try {
        localStorage.setItem('mysoc.sidebar', r ? 'full' : 'rail')
      } catch {
        /* private mode: the choice just isn't remembered */
      }
      return !r
    })
  }, [])
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement
      if (e.key !== '[' || e.metaKey || e.ctrlKey || e.altKey || t.closest('input, textarea, select, [contenteditable]')) return
      toggleRail()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [toggleRail])
  return (
    <LiveProvider onExpired={onExpired}>
      <div className="shell" data-rail={rail ? '' : undefined}>
        <Sidebar rail={rail} onToggle={toggleRail} />
        <div className="main">
          <Topbar />
          <main className="content" id="main">
            {/* Keyed by page, so moving to another page fades its content in once. */}
            <div key={pathname} className="page-in">
              <Outlet />
            </div>
          </main>
        </div>
      </div>
    </LiveProvider>
  )
}
