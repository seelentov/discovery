/**
 * Low-level fetch wrapper. The session is an `HttpOnly` cookie set by `POST /api/auth/
 * login` (see docs/Architecture/Dashboard (Web UI).md) — the browser attaches it
 * automatically on same-origin requests, so this never reads or sets it manually, only
 * makes sure `credentials: 'include'` is on every call (needed even same-origin once the
 * Vite dev server proxies to a different port).
 *
 * Error bodies from the backend are **plain text**, not JSON — `ApiError` on the Rust
 * side is `(StatusCode, String)`, and axum's `impl IntoResponse` for that tuple writes
 * the string as a raw text body. `ApiHttpError` below carries that text verbatim.
 */
export class ApiHttpError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiHttpError'
    this.status = status
  }

  /** Keeps status checks at the HTTP boundary readable without treating every
   * failed request as an authentication failure. */
  hasStatus(status: number): boolean {
    return this.status === status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: 'include',
    headers: init?.body ? { 'Content-Type': 'application/json', ...init.headers } : init?.headers,
    ...init,
  })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new ApiHttpError(res.status, text || res.statusText)
  }
  if (res.status === 204) return undefined as T
  const contentType = res.headers.get('content-type') ?? ''
  if (!contentType.includes('application/json')) return undefined as T
  return (await res.json()) as T
}

/** `query` is typed `object` rather than `Record<string, ...>` on purpose: callers pass
 * real query interfaces (`DevicesQuery`, ...) which TS won't structurally match against
 * an indexed `Record` type even when every property lines up — an index-signature
 * technicality, not a real type-safety concern here since every value just gets
 * `String(value)`'d into a query string; the cast below is local to this one function. */
function withQuery(path: string, query?: object): string {
  if (!query) return path
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query as Record<string, unknown>)) {
    if (value !== undefined && value !== '') params.set(key, String(value))
  }
  const qs = params.toString()
  return qs ? `${path}?${qs}` : path
}

export const http = {
  get: <T>(path: string, query?: object) => request<T>(withQuery(path, query)),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PUT', body: body !== undefined ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
}
