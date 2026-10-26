// Thin fetch wrapper. The session lives in an HttpOnly cookie the browser
// sends automatically; mutations also carry the CSRF token from /auth/me.

let csrfToken = ''
export function setCsrf(token: string) {
  csrfToken = token
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

type Listener = () => void
const unauthorizedListeners = new Set<Listener>()
export function onUnauthorized(fn: Listener) {
  unauthorizedListeners.add(fn)
  return () => {
    unauthorizedListeners.delete(fn)
  }
}

function detail(body: unknown, fallback: string): string {
  if (body && typeof body === 'object' && 'detail' in body) {
    const d = (body as { detail: unknown }).detail
    if (typeof d === 'string') return d
    if (Array.isArray(d) && d[0]?.msg) return `${d[0].loc?.slice(-1)[0] ?? 'Input'}: ${d[0].msg}`
  }
  return fallback
}

export async function api<T>(method: string, path: string, body?: unknown, params?: Record<string, unknown>): Promise<T> {
  let url = path
  if (params) {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null || v === '') continue
      if (Array.isArray(v)) v.forEach((x) => q.append(k, String(x)))
      else q.set(k, String(v))
    }
    const s = q.toString()
    if (s) url += `?${s}`
  }
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken
  const res = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
  })
  const text = await res.text()
  const data = text ? safeJson(text) : null
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/api/auth/')) unauthorizedListeners.forEach((fn) => fn())
    throw new ApiError(res.status, detail(data, res.statusText || 'Request failed'))
  }
  return data as T
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

export const get = <T,>(path: string, params?: Record<string, unknown>) => api<T>('GET', path, undefined, params)
export const post = <T,>(path: string, body?: unknown) => api<T>('POST', path, body ?? {})
export const patch = <T,>(path: string, body: unknown) => api<T>('PATCH', path, body)
export const put = <T,>(path: string, body: unknown) => api<T>('PUT', path, body)
export const del = <T,>(path: string) => api<T>('DELETE', path)
