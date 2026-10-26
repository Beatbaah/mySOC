import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  Activity, Bell, BookOpen, Briefcase, ChevronDown, Crosshair, FileText, Gauge, KeyRound, LogOut, Moon, Network,
  ScrollText, Server, Settings, ShieldCheck, SlidersHorizontal, Sun, Repeat, UserRound, Users,
} from 'lucide-react'
import { useAuth, useCan, useMe } from '../api/auth'
import { LiveProvider, useLive } from '../api/live'
import { applyTheme, initialTheme, type Theme } from '../lib/theme'
import { Logo } from './Logo'
import { GlobalSearch } from './Search'

function NavItem({ to, icon, children, count, hot }: { to: string; icon: ReactNode; children: ReactNode; count?: number; hot?: boolean }) {
  return (
    <NavLink to={to} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} end={to === '/'}>
      {icon}
      <span>{children}</span>
      {count ? <span className={`count ${hot ? 'hot' : ''}`}>{count}</span> : null}
    </NavLink>
  )
}

function Sidebar() {
  const isAdmin = useCan('admin')
  const { pulse } = useLive()
  const open = pulse?.openBySeverity
  const urgent = open ? open.critical + open.high : 0
  const sensors = pulse?.sensors ?? []
  return (
    <aside className="sidebar" aria-label="Main navigation">
      <div className="brand">
        <div className="brand-mark"><Logo size={18} /></div>
        <div className="brand-name">my<b>SOC</b></div>
      </div>
      <nav>
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
            <span className="mono faint" style={{ marginLeft: 'auto' }}>{s.online ? `${(s.flowsPerSecond ?? 0).toFixed(1)}/s` : 'offline'}</span>
          </div>
        ))}
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
  const { connected } = useLive()
  useEffect(() => applyTheme(theme), [theme])
  return (
    <header className="topbar">
      <GlobalSearch />
      <div style={{ flex: 1 }} />
      <span className="badge tag" title={connected ? 'Receiving live updates' : 'Reconnecting…'}>
        <span className={`dot ${connected ? 'on' : ''}`} /> {connected ? 'Live' : 'Reconnecting'}
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
  return (
    <LiveProvider onExpired={onExpired}>
      <div className="shell">
        <Sidebar />
        <div className="main">
          <Topbar />
          <main className="content" id="main">
            <Outlet />
          </main>
        </div>
      </div>
    </LiveProvider>
  )
}
