import { useEffect, useRef, useState } from 'react'

export const reducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches

// Every segmented control (.seg, .mini-seg) gets one highlight that slides to the
// chosen option, instead of the old one blinking off and the new one on. The
// controls are hand-built on several pages, so this watches the DOM for them
// rather than asking each page to opt in. The highlight is the container's
// ::before, positioned through --seg-x / --seg-w.
export function useSegIndicators() {
  useEffect(() => {
    const place = () => {
      for (const seg of document.querySelectorAll<HTMLElement>('.seg, .mini-seg')) {
        const on = seg.querySelector<HTMLElement>(':scope > button.on')
        if (!on) {
          seg.removeAttribute('data-ind')
          continue
        }
        seg.style.setProperty('--seg-x', `${on.offsetLeft}px`)
        seg.style.setProperty('--seg-w', `${on.offsetWidth}px`)
        // Turn the highlight on one frame after its first position, so it
        // doesn't slide in from the left edge when a control first appears.
        if (!seg.hasAttribute('data-ind')) requestAnimationFrame(() => seg.setAttribute('data-ind', ''))
      }
    }
    let queued = 0
    const schedule = () => {
      cancelAnimationFrame(queued)
      queued = requestAnimationFrame(place)
    }
    // Only mutations that touch a segmented control matter; live updates elsewhere are ignored.
    const touchesSeg = (n: Node) =>
      n instanceof Element && (n.matches('.seg, .mini-seg, .seg *, .mini-seg *') || n.querySelector('.seg, .mini-seg') !== null)
    const mo = new MutationObserver((records) => {
      if (records.some((r) => touchesSeg(r.target) || [...r.addedNodes].some(touchesSeg))) schedule()
    })
    mo.observe(document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ['class'] })
    window.addEventListener('resize', schedule)
    document.fonts?.ready.then(schedule)
    schedule()
    return () => {
      mo.disconnect()
      window.removeEventListener('resize', schedule)
      cancelAnimationFrame(queued)
    }
  }, [])
}

// A number that counts to its new value when live data changes it, and says
// how many times it has changed so the caller can flash it once per change.
export function useTween(value: number, ms = 500): [number, number] {
  const [shown, setShown] = useState(value)
  const [changes, setChanges] = useState(0)
  const target = useRef(value)
  const onScreen = useRef(value)
  onScreen.current = shown
  useEffect(() => {
    // Start from the number on screen, so a change that lands mid-count doesn't jump back.
    const from = onScreen.current
    if (target.current === value) return
    target.current = value
    setChanges((c) => c + 1)
    if (reducedMotion()) {
      setShown(value)
      return
    }
    const start = performance.now()
    let raf = 0
    const step = (now: number) => {
      const k = Math.min(1, (now - start) / ms)
      setShown(Math.round(from + (value - from) * (1 - (1 - k) ** 3)))
      if (k < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [value, ms])
  return [shown, changes]
}
