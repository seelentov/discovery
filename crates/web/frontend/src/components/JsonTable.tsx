function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function cellText(v: unknown): string {
  return v === undefined ? '' : typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)
}

function looksLikeCsv(s: string): boolean {
  const lines = s.trim().split(/\r?\n/).filter(Boolean)
  if (lines.length < 2) return false
  const delim = s.includes(';') && !s.includes(',') ? ';' : ','
  const counts = lines.map((l) => l.split(delim).length)
  return counts[0] > 1 && counts.every((c) => c === counts[0])
}

function parseCsv(s: string): string[][] {
  const delim = s.includes(';') && !s.includes(',') ? ';' : ','
  return s
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => line.split(delim).map((c) => c.trim()))
}

function looksLikeXml(s: string): boolean {
  const trimmed = s.trim()
  return trimmed.startsWith('<') && trimmed.endsWith('>')
}

/** Leaf elements only (no children) — deep enough to make simple XML readable as a flat
 * table without building a full recursive tree viewer, which nothing here needs. */
function parseXmlRows(s: string): string[][] | null {
  try {
    const doc = new DOMParser().parseFromString(s, 'application/xml')
    if (doc.querySelector('parsererror')) return null
    const rows: string[][] = [['Тег', 'Значение']]
    const walk = (el: Element) => {
      if (el.children.length === 0) {
        rows.push([el.tagName, el.textContent ?? ''])
      } else {
        Array.from(el.children).forEach(walk)
      }
    }
    if (doc.documentElement) walk(doc.documentElement)
    return rows.length > 1 ? rows : null
  } catch {
    return null
  }
}

/** Renders arbitrary JSON (or JSON-shaped text) as a readable table whenever a structure
 * can be recognized, instead of a raw dump — originally built for Alerts' `facts` column
 * (direct user request 2026-08-28: "если json то строить таблицу, аналогично если csv
 * или в xml и подобных форматах"), and reused as-is for the Журнал page's `details`
 * column (direct user follow-up request — same "JSON as a table" treatment for a
 * before/after diff). Recognizes, in order: a JSON array of objects (table, one column
 * per key seen across all rows); a JSON object (key/value table, recursing one level into
 * any nested object/array value so a diff's `{"old": ..., "new": ...}` shape reads as
 * nested tables, not a raw `[object Object]`); a string that's itself JSON-encoded
 * (recurses once); a string that looks like CSV (comma/semicolon-delimited, consistent
 * column count); a string that looks like XML (parsed, leaf elements as tag/value rows).
 * Anything else — a bare number/boolean/string matching none of the above — falls back to
 * plain text, still strictly more readable than a raw `title` tooltip. */
export function renderJsonAsTable(value: unknown, emptyMessage = 'Данные не заданы.'): React.JSX.Element {
  if (value == null) {
    return <p className="stamp">{emptyMessage}</p>
  }
  if (Array.isArray(value) && value.length === 0) {
    return <p className="stamp">{emptyMessage}</p>
  }
  if (Array.isArray(value) && value.length > 0 && value.every(isPlainObject)) {
    const rowsArr = value as Record<string, unknown>[]
    const columns = Array.from(new Set(rowsArr.flatMap((r) => Object.keys(r))))
    return (
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c}>{c}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rowsArr.map((r, i) => (
              <tr key={i}>
                {columns.map((c) => (
                  <td key={c} className="mono">
                    {cellText(r[c])}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )
  }
  if (isPlainObject(value)) {
    return (
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>Поле</th>
              <th>Значение</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(value).map(([k, v]) => (
              <tr key={k}>
                <td className="mono">{k}</td>
                <td className="mono">{isPlainObject(v) || (Array.isArray(v) && v.length > 0) ? renderJsonAsTable(v) : cellText(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )
  }
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value)
      if (isPlainObject(parsed) || Array.isArray(parsed)) return renderJsonAsTable(parsed, emptyMessage)
    } catch {
      // not JSON-encoded text — fall through to CSV/XML/plain-text detection below.
    }
    const tableRows = looksLikeCsv(value) ? parseCsv(value) : looksLikeXml(value) ? parseXmlRows(value) : null
    if (tableRows) {
      const [header, ...body] = tableRows
      return (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                {header.map((h, i) => (
                  <th key={i}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {body.map((row, i) => (
                <tr key={i}>
                  {row.map((cell, j) => (
                    <td key={j} className="mono">
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
    }
    return (
      <pre className="mono" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
        {value}
      </pre>
    )
  }
  return <pre className="mono">{String(value)}</pre>
}
