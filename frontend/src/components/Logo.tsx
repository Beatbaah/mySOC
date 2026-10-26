// The m of mySOC, with its last leg cut short into an exclamation mark: the name and an alert in one letter.
const M_PATH = 'M2.6 21V7.4h3.6v1.5A4.3 4.3 0 0 1 9.6 7.1c1.7 0 2.9.7 3.5 2a4.6 4.6 0 0 1 3.9-2c1.6 0 2.7.5 3.4 1.5.6.9.9 2 .9 3.6V13.8h-3.6v-1.4c0-1.6-.6-2.4-1.9-2.4-1.4 0-2.2 1-2.2 2.8V21h-3.6v-8.3c0-1.7-.6-2.6-1.9-2.6-1.4 0-2.1 1-2.1 2.8V21z'

function MGlyph({ viewBox, ...size }: { viewBox: string; width?: number | string; height?: number | string }) {
  return (
    <svg viewBox={viewBox} {...size} aria-hidden>
      <path d={M_PATH} fill="currentColor" />
      <rect x="17.7" y="17.4" width="3.6" height="3.6" rx=".6" fill="var(--sev-high)" />
    </svg>
  )
}

/** The wordmark: "mySOC" with the m! standing in for the typed m. */
export function Logo() {
  return (
    <span className="brand-name" role="img" aria-label="mySOC">
      <MGlyph viewBox="2.2 7 19.4 14" />ySOC
    </span>
  )
}

/** The m! on its own, for places with no room for the name. */
export function LogoMark({ size = 20 }: { size?: number }) {
  return (
    <span role="img" aria-label="mySOC" style={{ display: 'inline-flex' }}>
      <MGlyph viewBox="0 0 24 24" width={size} height={size} />
    </span>
  )
}
