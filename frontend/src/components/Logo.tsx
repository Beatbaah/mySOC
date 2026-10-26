export function Logo({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M12 2.5l7.5 2.9v5.3c0 4.7-3.2 8.4-7.5 10.3-4.3-1.9-7.5-5.6-7.5-10.3V5.4L12 2.5z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
      <circle cx="12" cy="11" r="2.2" fill="currentColor" />
      <path d="M12 13.2v3" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  )
}
