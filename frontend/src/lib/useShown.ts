import { useState } from 'react'

// Long lists show their first rows and grow on request, instead of rendering
// hundreds of rows at once. `fresh(i)` marks rows revealed by the last
// "show more", so they can fade in and the eye finds where the new ones start.
// A new `resetKey` (a filter or time range changed) collapses the list again;
// a plain refetch of the same view keeps it expanded.
export function useShown<T>(items: T[], first = 12, step = first, resetKey: unknown = null) {
  const [state, setState] = useState({ key: resetKey, count: first, prev: first })
  let { count, prev } = state
  if (!Object.is(state.key, resetKey)) {
    count = first
    prev = first
    setState({ key: resetKey, count, prev })
  }
  return {
    shown: items.slice(0, count),
    remaining: Math.max(0, items.length - count),
    next: Math.min(step, Math.max(0, items.length - count)),
    showMore: () => setState({ key: resetKey, count: count + step, prev: count }),
    fresh: (i: number) => count > first && i >= prev,
  }
}
