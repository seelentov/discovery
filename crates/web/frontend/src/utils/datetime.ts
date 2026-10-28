/** `<input type="datetime-local">` has no timezone (local wall-clock time) — `new
 * Date(local)` interprets it in the browser's own zone, `.toISOString()` then gives the
 * UTC instant a `DateTime<Utc>` backend field expects. */
export function localToIso(local: string): string | undefined {
  if (!local) return undefined
  const d = new Date(local)
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString()
}

/** Inverse-ish of `localToIso` — formats a `Date` as a `datetime-local` value in the
 * browser's own zone (that input type has no way to accept a raw ISO/UTC string
 * directly). */
export function toLocalInputValue(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}
