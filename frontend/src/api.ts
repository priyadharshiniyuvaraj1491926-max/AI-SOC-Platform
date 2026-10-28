const API_BASE = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8009').replace(/\/$/, '')
let csrfToken = ''

export function setCsrf(token: string) { csrfToken = token }
export function clearCsrf() { csrfToken = '' }

export async function api<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {})
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (['POST', 'PATCH', 'PUT', 'DELETE'].includes((options.method || 'GET').toUpperCase()) && csrfToken) headers.set('X-CSRF-Token', csrfToken)
  const response = await fetch(`${API_BASE}/api${path}`, { ...options, headers, credentials: 'include' })
  if (!response.ok) {
    const data = await response.json().catch(() => ({}))
    const detail = data.detail
    throw new Error(typeof detail === 'string' ? detail : `Request failed (${response.status})`)
  }
  return response.status === 204 ? undefined as T : response.json()
}
