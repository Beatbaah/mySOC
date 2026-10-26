import { useEffect, useMemo, useRef } from 'react'

// Ids of items that are new, or whose version changed, since the previous
// data the component rendered. Empty on first load, so only live changes
// are marked (a refetch after a new alert, a repeat folding into an alert).
export function useChanged<T>(items: T[] | undefined, id: (t: T) => number, version: (t: T) => string): Set<number> {
  const prev = useRef<Map<number, string> | null>(null)
  const changed = useMemo(() => {
    const out = new Set<number>()
    if (!items || !prev.current) return out
    for (const t of items) if (prev.current.get(id(t)) !== version(t)) out.add(id(t))
    return out
    // id/version are read-only accessors; only new data should recompute.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items])
  useEffect(() => {
    if (items) prev.current = new Map(items.map((t) => [id(t), version(t)]))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items])
  return changed
}
