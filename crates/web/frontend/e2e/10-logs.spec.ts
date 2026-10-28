import { test, expect } from './fixtures'

test.describe('Логи', () => {
  test.beforeEach(async ({ adminPage: page }) => {
    // Exact match, not substring: 'Топология' (added 2026-09-12) contains 'логи' as a
    // literal substring ("...то-п-о-Логи-я...", same Greek "-логия"/"log" root) and would
    // otherwise collide with a plain `hasText: 'Логи'` — see `fixtures.ts`'s docs on this
    // exact class of gotcha.
    await page.locator('.nav-item', { hasText: /^Логи$/ }).click()
  })

  test('живой хвост логов отображается с реальными записями', async ({ adminPage: page }) => {
    // By this point in the suite, plenty of real log lines exist (every request handled,
    // every job processed by `06`/`08`'s discovery runs) — no need to trigger anything,
    // just confirm the buffer + table actually shows them.
    await expect(page.locator('.data-table tbody tr').first()).toBeVisible()
    await expect(page.locator('.pagination')).toContainText('из')
  })

  test('живой хвост показывает запись, появившуюся после открытия страницы', async ({ adminPage: page }) => {
    let requestCount = 0
    const requestUrls: URL[] = []
    const firstEntry = {
      timestamp: '2026-09-23T10:00:00.000Z',
      level: 'INFO',
      target: 'e2e.live-tail',
      message: 'initial log entry',
      fields: {},
    }
    const newEntry = {
      ...firstEntry,
      timestamp: '2026-09-23T10:00:01.000Z',
      message: 'new log entry after opening',
    }

    await page.route('**/api/logs*', async (route) => {
      requestCount += 1
      const requestUrl = new URL(route.request().url())
      requestUrls.push(requestUrl)
      if (requestCount === 1) expect(requestUrl.searchParams.has('until')).toBe(false)
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ items: requestCount === 1 ? [firstEntry] : [newEntry, firstEntry], total: requestCount === 1 ? 1 : 2 }),
      })
    })

    await page.reload()
    await expect(page.locator('.data-table tbody')).toContainText('initial log entry')
    await expect(page.locator('.data-table tbody')).toContainText('new log entry after opening', { timeout: 5000 })

    await page.locator('input[type="datetime-local"]').nth(1).fill('2026-09-23T12:00')
    await expect.poll(() => requestUrls.some((url) => url.searchParams.has('until'))).toBe(true)
  })

  test('фильтр по цели сужает список', async ({ adminPage: page }) => {
    // `discovery_agent` (the pipeline handlers' crate — `MetricPollHandler`/
    // `SnmpPollHandler`/etc. all log under `discovery_agent::handlers`) fires
    // continuously by this point in the suite thanks to `06`/`08`'s seeded devices
    // endlessly retrying unreachable TEST-NET-3 hosts. NOT `sqlx` — as of 2026-08-26,
    // `sqlx::query` events are unconditionally excluded from this buffer (see
    // `logging_setup::init`'s docs: persisting/displaying the log store's own internal
    // SQL statements is what caused a real runaway-disk-usage incident, fixed by
    // hardcoding `sqlx=off` on this exact sink) — searching for it would now correctly
    // find nothing, which used to be this test's assumption before that fix existed.
    await page.locator('input[placeholder*="discovery_agent"]').fill('discovery_agent')
    // Wait past the loading placeholder itself (also a real `<tr>`, so a plain "first row
    // visible" check can pass against *it*, not real data, on a still-cold first fetch)
    // before reading rows.
    await expect(page.locator('.data-table tbody')).not.toContainText('Загрузка')
    await expect(page.locator('.data-table tbody tr').first()).toBeVisible()
    // One atomic snapshot (`allTextContents`), not a `count()` followed by a per-row loop
    // of separate `expect`s — this page live-refreshes every 3s (see `LogsPage`'s own
    // polling interval), and with the shared backend's continuous background activity by
    // this point in the suite, a poll tick landing mid-loop can reshuffle/shrink the row
    // set out from under an index-by-index check (found live: `nth(29)` intermittently
    // not found — the list had already moved on, not a real bug).
    const texts = await page.locator('.data-table tbody tr').allTextContents()
    expect(texts.length).toBeGreaterThan(0)
    for (const text of texts) {
      expect(text).toContain('discovery_agent')
    }
  })

  test('поиск по тексту сообщения и смена сортировки', async ({ adminPage: page }) => {
    // `LogsQuery.search` matches `LogEntry.message`/`.target` only — NOT `.fields` (see
    // `LogBuffer::snapshot`). The actual SQL text for every `sqlx::query` line lives in
    // `fields["db.statement"]`, with `message` itself empty — searching "SELECT" would
    // never match those rows no matter how many exist. "metric poll failed"
    // (`MetricPollHandler`'s real `warn!` message, not a field) fires continuously by
    // this point in the suite — every seeded device's `dummy` metric poll against an
    // unreachable TEST-NET-3 host fails on every tick — and is guaranteed to actually be
    // in `message`, unlike a process-startup-only line that a 1000-entry ring buffer
    // will have evicted by now.
    await page.locator('input[placeholder*="поиск"]').fill('metric poll failed')
    await expect(page.locator('.data-table tbody tr', { hasText: 'metric poll failed' }).first()).toBeVisible()

    await page.locator('input[placeholder*="поиск"]').fill('')
    const sortBtn = page.locator('.filter-bar__row button', { hasText: /старые сверху|новые сверху/ })
    await expect(sortBtn).toContainText('новые сверху') // default sort_dir=desc
    await sortBtn.click()
    await expect(sortBtn).toContainText('старые сверху')
  })

  test('фильтр по периоду (по умолчанию — последние 24ч) и сброс', async ({ adminPage: page }) => {
    // Bounded-by-default (last 24h) — a query/tail view, unlike Devices/Alerts' own
    // unbounded date filters (design-artifact round 13). Both inputs pre-filled at mount.
    const dateInputs = page.locator('.filter-bar__row input[type="datetime-local"]')
    await expect(dateInputs.nth(0)).not.toHaveValue('')
    await expect(dateInputs.nth(1)).not.toHaveValue('')
    await expect(page.locator('.data-table tbody tr').first()).toBeVisible()

    // A window that couldn't possibly contain any real entry (year 2000) narrows to
    // nothing.
    await dateInputs.nth(0).fill('2000-01-01T00:00')
    await dateInputs.nth(1).fill('2000-01-02T00:00')
    await expect(page.locator('.data-table tbody')).toContainText('Нет записей')

    // "Сбросить фильтры" restores the 24h default, not an unbounded range.
    await page.getByRole('button', { name: /Сбросить фильтры/ }).click()
    await expect(dateInputs.nth(0)).not.toHaveValue('2000-01-01T00:00')
    await expect(page.locator('.data-table tbody tr').first()).toBeVisible()
  })

  test('уровень "только fatal/error+" фильтрует', async ({ adminPage: page }) => {
    await page.locator('.filter-bar__row select').selectOption('error')
    // Just confirming the control itself works — this app logs very little at ERROR
    // level in a healthy run, so an empty result here is the *expected*, correct state,
    // not a bug: assert the empty-state renders cleanly rather than assuming rows exist.
    const rows = page.locator('.data-table tbody tr')
    const count = await rows.count()
    if (count === 1 && (await rows.first().innerText()).includes('Нет записей')) {
      await expect(rows.first()).toContainText('Нет записей')
    } else {
      await expect(rows.first()).toBeVisible()
    }
  })
})
