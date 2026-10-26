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

// ATT&CK kill chain: every tactic shown in order, lit by how many alerts it had.
export function KillChain({ counts }: { counts: { tactic: string; count: number }[] }) {
  const by = Object.fromEntries(counts.map((c) => [c.tactic, c.count]))
  const max = Math.max(1, ...counts.map((c) => c.count))
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, minmax(0, 1fr))', gap: 6 }}>
      {TACTICS.map((t) => {
        const n = by[t] ?? 0
        const strength = n ? 0.18 + 0.62 * (n / max) : 0
        return (
          <div
            key={t}
            title={`${t}: ${n} alert${n === 1 ? '' : 's'}`}
            style={{
              border: '1px solid var(--border)',
              borderRadius: 6,
              padding: '8px 9px',
              minHeight: 58,
              background: n ? `color-mix(in srgb, var(--sev-high) ${Math.round(strength * 100)}%, var(--surface))` : 'var(--surface-2)',
              color: n ? 'var(--text)' : 'var(--text-3)',
            }}
          >
            <div style={{ fontSize: 11, lineHeight: 1.25 }}>{t}</div>
            <div className="mono" style={{ fontSize: 15, marginTop: 4 }}>{n || '·'}</div>
          </div>
        )
      })}
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
