import countries from 'i18n-iso-countries'
import en from 'i18n-iso-countries/langs/en.json'

countries.registerLocale(en)

export function timeAgo(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return '—'
  const s = Math.round((now - new Date(iso).getTime()) / 1000)
  if (s < 0) return 'just now'
  if (s < 45) return `${s}s ago`
  if (s < 3600) return `${Math.round(s / 60)}m ago`
  if (s < 86400) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function shortTime(iso: string): string {
  return new Date(iso).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

export function bytes(n: number | null | undefined): string {
  if (n == null) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = n
  let i = 0
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000
    i++
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`
}

export function num(n: number | null | undefined): string {
  if (n == null) return '—'
  return n.toLocaleString()
}

export function compact(n: number): string {
  return Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(n)
}

export function minutes(m: number | null | undefined): string {
  if (m == null) return '—'
  if (m < 60) return `${Math.round(m)} min`
  if (m < 1440) return `${(m / 60).toFixed(1)} h`
  return `${(m / 1440).toFixed(1)} d`
}

export function countryName(code: string): string {
  if (!code) return ''
  return countries.getName(code, 'en', { select: 'alias' }) ?? code
}

export function flag(code: string): string {
  if (!code || code.length !== 2) return ''
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0)))
}

export function alpha3ToAlpha2(numeric: string): string {
  return countries.numericToAlpha2(numeric) ?? ''
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const

export const PORT_NAMES: Record<number, string> = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 88: 'Kerberos', 123: 'NTP', 135: 'RPC',
  389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 587: 'SMTP', 993: 'IMAPS', 1433: 'MS SQL', 3306: 'MySQL', 3389: 'RDP',
  4444: 'Metasploit', 5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 8080: 'HTTP alt',
}

export function portLabel(port: number): string {
  return PORT_NAMES[port] ? `${port} ${PORT_NAMES[port]}` : String(port)
}

export const DISPOSITION_LABEL: Record<string, string> = {
  true_positive: 'True positive',
  false_positive: 'False positive',
  benign: 'Benign',
}

export const STATUS_LABEL: Record<string, string> = {
  new: 'New', in_progress: 'In progress', closed: 'Closed',
  open: 'Open', investigating: 'Investigating', contained: 'Contained', resolved: 'Resolved',
}
