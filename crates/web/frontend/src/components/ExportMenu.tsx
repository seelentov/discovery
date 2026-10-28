import { useEffect, useRef, useState } from 'react'
import { exportCsv, exportJson, exportXlsx, type ExportRow } from '../utils/export'
import { Button } from './Button'
import { Icon } from './Icon'
import { useToast } from '../hooks/useToast'

/** Small CSV/XLSX/JSON export dropdown — `getRows` is called lazily, only when the user
 * actually picks a format (it typically re-fetches every page of the current filtered
 * result set, not just what's on screen — see each call site), so that cost is only ever
 * paid on an explicit export click, never on a normal render/poll. */
export function ExportMenu({ filenameBase, getRows }: { filenameBase: string; getRows: () => Promise<ExportRow[]> }) {
  const toast = useToast()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    function onDocClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDocClick)
    return () => document.removeEventListener('mousedown', onDocClick)
  }, [open])

  async function pick(format: 'csv' | 'xlsx' | 'json') {
    setOpen(false)
    setBusy(true)
    try {
      const rows = await getRows()
      if (format === 'csv') exportCsv(`${filenameBase}.csv`, rows)
      else if (format === 'xlsx') exportXlsx(`${filenameBase}.xlsx`, rows)
      else exportJson(`${filenameBase}.json`, rows)
    } catch {
      toast('Не удалось выгрузить данные для экспорта', true)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={open ? 'dropdown open' : 'dropdown'} ref={ref}>
      <Button variant="ghost" small title="Экспортировать текущую (отфильтрованную) выборку в файл" onClick={() => setOpen((v) => !v)} disabled={busy}>
        <Icon name="download" />
        {busy ? 'Экспорт…' : 'Экспорт'}
        <Icon name="chevron-down" className="ic-chev" />
      </Button>
      <div className="dropdown-menu">
        <button title="Скачать как CSV — открывается в Excel/Google Sheets" onClick={() => pick('csv')}>
          <Icon name="download" />
          CSV
        </button>
        <button title="Скачать как настоящий XLSX-файл Excel" onClick={() => pick('xlsx')}>
          <Icon name="download" />
          XLSX
        </button>
        <button title="Скачать как JSON — удобно для дальнейшей обработки скриптом" onClick={() => pick('json')}>
          <Icon name="download" />
          JSON
        </button>
      </div>
    </div>
  )
}
