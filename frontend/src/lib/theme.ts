export type Theme = 'dark' | 'light'

export function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem('mysoc-theme')
    if (saved === 'dark' || saved === 'light') return saved
  } catch {
    /* storage unavailable */
  }
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

export function applyTheme(t: Theme) {
  document.documentElement.dataset.theme = t
  try {
    localStorage.setItem('mysoc-theme', t)
  } catch {
    /* ignore */
  }
}
