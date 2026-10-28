/**
 * Server-side pagination — unlike the design mockup (which paginated an
 * already-fully-fetched client-side array), `page`/`total` here come straight from the
 * REST response (`DevicesPage.total`, etc.): the backend already applied `page`/
 * `page_size` in SQL (see docs/Architecture/REST API Reference.md and the
 * discovery-sort-filter-backend memory note this was built to satisfy). This component
 * only renders page buttons and reports the page number clicked — it never re-slices
 * data itself.
 */
export function Pagination({
  page,
  pageSize,
  total,
  itemCount,
  onPageChange,
}: {
  page: number
  pageSize: number
  total: number
  /** How many items are on the current page — used only to compute the "показаны X–Y"
   * range label (can differ from `pageSize` on the last page). */
  itemCount: number
  onPageChange: (page: number) => void
}) {
  if (total === 0) return null
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const startN = (page - 1) * pageSize + 1
  const endN = Math.min((page - 1) * pageSize + itemCount, total)

  const buttons: React.ReactNode[] = []
  for (let p = 1; p <= pages; p++) {
    if (pages > 7 && p !== 1 && p !== pages && Math.abs(p - page) > 1) {
      if (p === 2 || p === pages - 1) buttons.push(<button key={p} disabled>…</button>)
      continue
    }
    buttons.push(
      <button key={p} className={p === page ? 'active' : ''} onClick={() => onPageChange(p)}>
        {p}
      </button>,
    )
  }

  return (
    <div className="pagination">
      <span>
        Показаны {startN}–{endN} из {total}
      </span>
      <div className="pagination__pages">{buttons}</div>
    </div>
  )
}
