import { useMemo, useState } from 'react'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { geoEqualEarth, geoPath } from 'd3-geo'
import { feature } from 'topojson-client'
import type { FeatureCollection, Geometry } from 'geojson'
import type { Topology, GeometryCollection } from 'topojson-specification'
import world from 'world-atlas/countries-110m.json'
import { alpha3ToAlpha2, bytes, compact, countryName, num } from '../lib/format'
import { TACTICS } from '../lib/mitre'

const SEV_ORDER = ['info', 'low', 'medium', 'high', 'critical'] as const
const axis = { stroke: 'var(--text-3)', fontSize: 11, tickLine: false, axisLine: false }

function tickTime(step: number) {
  return (t: string) => {
    const d = new Date(t)
    return step >= 3600 * 24
      ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
      : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  }
}

function TipBox({ title, rows }: { title: string; rows: { label: string; value: string; color?: string }[] }) {
  return (
    <div className="card" style={{ padding: '8px 10px', boxShadow: 'var(--shadow)', fontSize: 12, minWidth: 140 }}>
      <div className="muted" style={{ marginBottom: 4 }}>{title}</div>
      {rows.map((r) => (
        <div key={r.label} style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          {r.color && <span style={{ width: 8, height: 8, borderRadius: 2, background: r.color }} />}
          <span style={{ textTransform: 'capitalize' }}>{r.label}</span>
          <span className="mono" style={{ marginLeft: 'auto' }}>{r.value}</span>
        </div>
      ))}
    </div>
  )
}

export function SeverityTimeline({ data, step, height = 200 }: { data: Record<string, number | string>[]; step: number; height?: number }) {
  const fmt = tickTime(step)
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 6, right: 4, left: -18, bottom: 0 }} barCategoryGap={2}>
        <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
        <XAxis dataKey="t" tickFormatter={fmt} {...axis} minTickGap={36} />
        <YAxis allowDecimals={false} {...axis} width={44} />
        <Tooltip
          cursor={{ fill: 'var(--hover)' }}
          content={({ active, payload, label }) =>
            active && payload?.length ? (
              <TipBox
                title={new Date(String(label)).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                rows={[...payload].reverse().filter((p) => Number(p.value) > 0).map((p) => ({
                  label: String(p.dataKey), value: String(p.value), color: `var(--sev-${p.dataKey})`,
                }))}
              />
            ) : null
          }
        />
        {SEV_ORDER.map((s) => (
          <Bar key={s} dataKey={s} stackId="a" fill={`var(--sev-${s})`} isAnimationActive={false} radius={s === 'critical' ? [2, 2, 0, 0] : 0} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  )
}

export function TrafficArea({ data, step, metric, height = 220 }: {
  data: { t: string; flows: number; bytes: number }[]; step: number; metric: 'flows' | 'bytes'; height?: number
}) {
  const fmt = tickTime(step)
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 6, right: 4, left: -10, bottom: 0 }}>
        <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
        <XAxis dataKey="t" tickFormatter={fmt} {...axis} minTickGap={40} />
        <YAxis {...axis} width={52} tickFormatter={(v) => (metric === 'bytes' ? bytes(v) : compact(v))} />
        <Tooltip
          cursor={{ stroke: 'var(--border-strong)' }}
          content={({ active, payload, label }) =>
            active && payload?.length ? (
              <TipBox
                title={new Date(String(label)).toLocaleString(undefined, { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' })}
                rows={[{ label: metric, value: metric === 'bytes' ? bytes(Number(payload[0].value)) : num(Number(payload[0].value)) }]}
              />
            ) : null
          }
        />
        <Area type="monotone" dataKey={metric} stroke="var(--chart-line)" strokeWidth={1.5} fill="var(--chart-fill)" isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

// Soft hyphens so long tactic names break between syllables, not mid-letter, in narrow columns.
const breakable = (t: string) =>
  t.replace('Reconnaissance', 'Recon\u00ADnaissance').replace('Development', 'Develop\u00ADment')
    .replace('Persistence', 'Persist\u00ADence').replace('Exfiltration', 'Exfil\u00ADtration').replace('Escalation', 'Escala\u00ADtion')

// The ATT&CK tactics as one track in kill-chain order. Each stage the alerts reached gets a bar sized
// to its count; the track fills from the first stage seen to the furthest, and the headline says how far
// the attack got, which is the question this panel answers.
export function KillChain({ counts }: { counts: { tactic: string; count: number }[] }) {
  const by = Object.fromEntries(counts.map((c) => [c.tactic, c.count]))
  const max = Math.max(1, ...counts.map((c) => c.count))
  const seen = TACTICS.map((t, i) => ((by[t] ?? 0) > 0 ? i : -1)).filter((i) => i >= 0)
  const first = seen[0] ?? -1
  const last = seen[seen.length - 1] ?? -1
  const step = 100 / TACTICS.length
  return (
    <div className="kc">
      <div className="kc-head">
        {last < 0 ? <span className="faint">No attack stages seen in this period.</span> : (
          <>
            <span>Furthest stage reached</span>
            <b>{TACTICS[last]}</b>
            <span className="faint">{seen.length} of {TACTICS.length} stages seen</span>
          </>
        )}
      </div>
      <div className="kc-track" style={{ ['--kc-from' as string]: `${(first + 0.5) * step}%`, ['--kc-to' as string]: `${(last + 0.5) * step}%` }}>
        {TACTICS.map((t, i) => {
          const n = by[t] ?? 0
          return (
            <div key={t} className={`kc-stage${n ? ' on' : ''}${i === last ? ' last' : ''}`} title={`${t}: ${n} alert${n === 1 ? '' : 's'}`}>
              <div className="kc-bar-wrap">
                {n > 0 && <span className="kc-n">{num(n)}</span>}
                <i className="kc-bar" style={{ height: n ? `${8 + 56 * Math.sqrt(n / max)}px` : 0 }} />
              </div>
              <span className="kc-dot" />
              <span className="kc-name">{breakable(t)}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

const topo = world as unknown as Topology<{ countries: GeometryCollection }>
const countriesGeo = feature(topo, topo.objects.countries) as unknown as FeatureCollection<Geometry, { name: string }>

export function WorldMap({ values, label = 'alerts', format = num, height = 320 }: {
  values: Record<string, number>; label?: string; format?: (n: number) => string; height?: number
}) {
  const [hover, setHover] = useState<{ code: string; name: string; x: number; y: number } | null>(null)
  const { paths, max } = useMemo(() => {
    const projection = geoEqualEarth().fitSize([960, 470], countriesGeo)
    const path = geoPath(projection)
    return {
      paths: countriesGeo.features
        .filter((f) => f.properties.name !== 'Antarctica')
        .map((f) => ({ d: path(f) ?? '', code: alpha3ToAlpha2(String(f.id ?? '')), name: f.properties.name })),
      max: Math.max(1, ...Object.values(values)),
    }
  }, [values])
  return (
    <div style={{ position: 'relative' }} onMouseLeave={() => setHover(null)}>
      <svg viewBox="0 0 960 470" style={{ width: '100%', height, display: 'block' }} role="img" aria-label={`World map of ${label} by country`}>
        {paths.map((p, i) => {
          const v = values[p.code] ?? 0
          const pct = v ? Math.round(25 + 65 * Math.sqrt(v / max)) : 0
          return (
            <path
              key={i}
              d={p.d}
              fill={v ? `color-mix(in srgb, var(--sev-high) ${pct}%, var(--map-land))` : 'var(--map-land)'}
              stroke="var(--map-stroke)"
              strokeWidth={0.6}
              onMouseMove={(e) => {
                const r = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect()
                setHover({ code: p.code, name: p.name, x: e.clientX - r.left, y: e.clientY - r.top })
              }}
            />
          )
        })}
      </svg>
      {hover && (
        <div style={{ position: 'absolute', left: hover.x + 12, top: hover.y + 12, pointerEvents: 'none' }}>
          <TipBox title={countryName(hover.code) || hover.name} rows={[{ label, value: format(values[hover.code] ?? 0) }]} />
        </div>
      )}
    </div>
  )
}
