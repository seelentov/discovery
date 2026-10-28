import { test, expect, fieldInput } from './fixtures'

test.describe('Очереди', () => {
  test.beforeEach(async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Очереди' }).click()
  })

  test('таблица очередей и воркеров отображается', async ({ adminPage: page }) => {
    // Direct user request 2026-08-28: this page always auto-refreshed on a hardcoded 3s
    // timer with no manual control — now the same configurable button+period pattern
    // every other live-updating page uses. Default changed from 3s to off (pre-release
    // audit finding 9, 2026-09-20, direct user request) -- auto-refresh anywhere should
    // be opt-in.
    await expect(page.getByRole('button', { name: 'Обновить' })).toBeVisible()
    await expect(page.locator('select[title="Период автообновления"]')).toHaveValue('0')

    // 2026-09-17 audit finding #8: the page header used to hardcode "9 очередей
    // обработки" — already stale by the time of the audit (a 10th queue,
    // `topology_recompute`, had been added). No number at all now, so it can't drift
    // again; the actual, always-accurate count is what the table below shows.
    await expect(page.locator('.topbar__subtitle')).toHaveText('Очереди обработки + активные воркеры')

    // Two `.table-wrap > .data-table` on this page (queue stats, then workers) — scope
    // to the first explicitly. A plain `hasText` match on "discovery"/"dedup" would
    // ambiguously also match the *workers* table's PascalCase `queue` column
    // ("Discovery"/"Dedup" case-insensitively contain "discovery"/"dedup").
    const queuesTable = page.locator('.table-wrap').first()
    await expect(queuesTable).toBeVisible()
    for (const q of [
      'discovery',
      'snmp_poll',
      'dedup',
      'profile_apply',
      'metric_poll',
      'alert_eval',
      'reachability_poll',
      'service_check_poll',
      'notification_dispatch',
      'topology_recompute',
    ]) {
      await expect(queuesTable.locator('tbody tr', { hasText: q })).toHaveCount(1)
    }
    await expect(page.locator('.section-title', { hasText: 'Воркеры' })).toBeVisible()
  })

  test('генерируем реальную нагрузку в discovery, раскрываем список задач, ставим на паузу и снимаем', async ({ adminPage: page }) => {
    // Fresh candidates, not already-known IPs — an already-known IP's `Discovery` job is
    // a same-tick no-op (`identity_chains.contains` short-circuits it), so it wouldn't
    // leave anything to actually see mid-flight in the queue. A /28 gives 14 new
    // candidates — enough for a real, briefly-visible pending/in-progress backlog.
    await page.locator('.nav-item', { hasText: 'Дискаверинг' }).click()
    await page.getByRole('button', { name: /Создать/ }).click()
    await fieldInput(page, 'Имя конфигурации').fill('e2e-queue-load')
    await fieldInput(page, 'Режим расписания').selectOption('periodic')
    await fieldInput(page, 'Период, сек').fill('3600')
    await page.getByRole('button', { name: /^Подсеть$/ }).click()
    const block = page.locator('.card', { hasText: 'IP сети' }).last()
    await block.locator('input[placeholder="10.0.0.0"]').fill('203.0.114.0')
    await block.locator('input[placeholder="255.255.255.0"]').fill('255.255.255.240')
    await block.locator('.checkbox-row', { hasText: 'Создавать устройства' }).locator('input').check()
    await page.getByRole('button', { name: 'Сохранить конфигурацию' }).click()
    const configCard = page.locator('.card', { hasText: 'e2e-queue-load' })
    await configCard.getByRole('button', { name: 'Запустить' }).click()
    await expect(configCard).toContainText(/поставлено в очередь: 14/)

    await page.locator('.nav-item', { hasText: 'Очереди' }).click()
    const discoveryRow = page.locator('.data-table tbody tr', { hasText: 'discovery' }).first()

    // Expand while there's still real activity to look at.
    await discoveryRow.locator('.expand-btn').click()
    const detail = discoveryRow.locator('xpath=following-sibling::tr[1]')
    await expect(detail).toBeVisible()

    // Whole-queue pause/resume — snmp_poll is where the 14 candidates actually spend
    // observable time (real SNMP timeout against dead hosts), pausing it keeps its
    // pending jobs sitting still long enough to interact with reliably.
    // Icon-only (2026-08-29, direct user request — was icon+"Пауза"/"Возобновить" text);
    // accessible name now comes from the title, "Приостановить очередь"/"Возобновить очередь".
    const snmpRow = page.locator('.data-table tbody tr', { hasText: 'snmp_poll' }).first()
    await snmpRow.getByRole('button', { name: /Приостановить|Возобновить/ }).click()
    await expect(page.locator('.toast-stack')).toContainText(/приостановлена|возобновлена/)
    // Toggle back to whatever it's not, so this doesn't leave the queue paused for good.
    await snmpRow.getByRole('button', { name: /Приостановить|Возобновить/ }).click()
  })

  test('очистка очереди целиком (discovery, после того как всё уже разобрано)', async ({ adminPage: page }) => {
    const discoveryRow = page.locator('.data-table tbody tr', { hasText: 'discovery' }).first()
    // Icon-only (2026-08-29) — accessible name now comes from the title, "Удалить все
    // задачи из очереди", not the old visible "Очистить" text.
    await discoveryRow.getByRole('button', { name: 'Удалить все задачи из очереди' }).click()
    await expect(page.getByRole('heading', { name: 'Подтверждение' })).toBeVisible()
    await page.locator('.modal-footer').getByRole('button', { name: 'Очистить' }).click()
    await expect(page.locator('.toast-stack')).toContainText('Удалено задач')
  })
})
