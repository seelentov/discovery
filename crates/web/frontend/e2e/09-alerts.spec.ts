import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test, expect, fieldInput } from './fixtures'
import { DEVICE_ALERT_DELETE_IP, DEVICE_KEEP_IP, E2E_PROFILE_NAME } from './shared'

test.describe('Тревоги', () => {
  test.beforeEach(async ({ adminPage: page }) => {
    await page.getByRole('button', { name: 'Тревоги', exact: true }).click()
  })

  test('поиск, фильтр по уровню/состоянию, сортировка', async ({ adminPage: page }) => {
    await page.locator('.filter-bar__row .input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).filter({ hasText: 'e2e-alert' }).first()
    await expect(row).toBeVisible()
    await expect(row).toContainText('e2e-alert')
    await expect(row).toContainText(/warning/i) // `Alert.level` is the PascalCase Rust variant name ("Warning") on the wire
    await expect(row).toContainText('активна')

    await page.locator('.filter-bar__row .input-icon input').fill('')
    await page.locator('select', { hasText: 'все уровни' }).selectOption('warning')
    await expect(page.locator('.data-table tbody tr', { hasText: 'e2e-alert' }).first()).toBeVisible()
    await page.locator('select', { hasText: 'все уровни' }).selectOption('')

    await page.locator('select', { hasText: 'все состояния' }).selectOption('active')
    await expect(page.locator('.data-table tbody tr', { hasText: 'e2e-alert' }).first()).toBeVisible()
    await page.locator('select', { hasText: 'все состояния' }).selectOption('')

    // --- Sort: clickable column headers (replaced a <select> — see design-artifact
    // parity pass), same "exercise the control, search narrows to one row so reordering
    // itself isn't observable" scope `07-devices`'s IP-sort test uses.
    const nameHeader = page.locator('.th-sortable', { hasText: 'Имя' })
    await nameHeader.click()
    await expect(nameHeader.locator('.sort-ind')).toBeVisible()
    await nameHeader.click()
    await nameHeader.click() // third click: back to default (last_seen/desc)
    await page.locator('.filter-bar__row .input-icon input').fill('')
  })

  test('клик по названию тревоги открывает профиль на вкладке "Тревоги"', async ({ adminPage: page }) => {
    await page.locator('.filter-bar__row .input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).filter({ hasText: 'e2e-alert' }).first()
    // The alert's name *is* the link now (direct user request — removed the separate
    // "правило: X →" button next to it).
    await row.locator('.metric-name-btn', { hasText: 'e2e-alert' }).click()

    await expect(page.getByRole('heading', { name: `Редактировать профиль: ${E2E_PROFILE_NAME}` })).toBeVisible()
    await expect(page.locator('.tabs button.active')).toContainText('Тревоги')
    // "Тревога" is real rendered text (a `<strong>` label on the row card); the rule's
    // own name lives in an `<input value>`, not text content, so it's checked via
    // `.inputValue()`/`toHaveValue`, not `toContainText`. Located structurally (the
    // "Имя"+"Уровень" pair's `.form-grid`, whose only `<input>` — "Уровень" is a
    // `<select>` — is the name field) rather than by label text: the card's very first
    // `<input>` overall is actually the "Включена" checkbox, and matching by label text
    // is its own footgun here (a plain `hasText: 'Имя'` substring also matches the
    // *"Сообщение"* field, whose hint literally contains "{metrics.имя}").
    const ruleCard = page.locator('.modal-body .card').first()
    await expect(ruleCard).toBeVisible()
    await expect(fieldInput(ruleCard, 'Имя')).toHaveValue('e2e-alert')
    await page.locator('.modal-header button[title="Закрыть"]').click()
  })

  test('клик по IP открывает это устройство на странице "Устройства"', async ({ adminPage: page }) => {
    await page.locator('.filter-bar__row .input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).filter({ hasText: 'e2e-alert' }).first()
    await row.locator('.mono .metric-name-btn', { hasText: DEVICE_KEEP_IP }).click()

    await expect(page.locator('.topbar__title')).toHaveText('Устройства')
    await expect(page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP })).toBeVisible()
  })

  test('фильтр по периоду (Начало)', async ({ adminPage: page }) => {
    await page.locator('.filter-bar__row .input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).filter({ hasText: 'e2e-alert' }).first()
    await expect(row).toBeVisible()

    // A window that couldn't possibly contain any real alert (year 2000) narrows to
    // nothing; resetting restores it.
    const dateInputs = page.locator('.filter-bar__row input[type="datetime-local"]')
    await dateInputs.nth(0).fill('2000-01-01T00:00')
    await dateInputs.nth(1).fill('2000-01-02T00:00')
    await expect(page.locator('.data-table tbody')).toContainText('Тревог не найдено')

    await page.getByRole('button', { name: /Сбросить период/ }).click()
    await expect(row).toBeVisible()
  })

  test('экспорт тревог в CSV/XLSX/JSON скачивает файл', async ({ adminPage: page }) => {
    for (const [label, ext] of [
      ['CSV', 'csv'],
      ['XLSX', 'xlsx'],
      ['JSON', 'json'],
    ] as const) {
      await page.locator('.dropdown', { hasText: 'Экспорт' }).getByRole('button', { name: /Экспорт/ }).click()
      const [download] = await Promise.all([page.waitForEvent('download'), page.locator('.dropdown-menu button', { hasText: label }).click()])
      expect(download.suggestedFilename()).toBe(`alerts.${ext}`)
    }
  })

  test('тред комментариев — несколько сообщений от разных пользователей, счётчик в таблице', async ({ adminPage: page }) => {
    await page.locator('.filter-bar__row .input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).filter({ hasText: 'e2e-alert' }).first()
    await row.getByRole('button', { name: 'Комментарии' }).click()
    await expect(page.getByRole('heading', { name: /Обсуждение тревоги/ })).toBeVisible()
    await expect(page.locator('.modal-body')).toContainText('Пока нет ни одного комментария')

    await page.locator('.modal-body textarea').fill('looked into it, waiting on vendor')
    await page.getByRole('button', { name: 'Отправить' }).click()
    const firstComment = page.locator('.comment-item').first()
    await expect(firstComment.locator('.comment-item__author')).toHaveText('admin')
    await expect(firstComment.locator('.comment-item__text')).toHaveText('looked into it, waiting on vendor')

    // A second message appends to the thread rather than replacing it — the whole point
    // of a thread over the old single shared textarea.
    await page.locator('.modal-body textarea').fill('vendor replied, patching tonight')
    await page.getByRole('button', { name: 'Отправить' }).click()
    await expect(page.locator('.comment-item')).toHaveCount(2)
    await expect(page.locator('.comment-item').nth(1).locator('.comment-item__text')).toHaveText('vendor replied, patching tonight')

    await page.locator('.modal-footer').getByRole('button', { name: 'Закрыть' }).click()
    // `exact: true` — a plain substring `hasText: '2'` also matches "правило:
    // e2e-test-profile" (it contains a literal "2", from "e2e").
    await expect(row.getByRole('button', { name: '2', exact: true })).toBeVisible()
  })

  test('вложения к комментарию — прикрепление файла и изображения, просмотр', async ({ adminPage: page }) => {
    await page.locator('.filter-bar__row .input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).filter({ hasText: 'e2e-alert' }).first()
    // Auto-refresh off — this modal's own composer state has nothing to do with the
    // table's periodic refetch, but avoiding it here keeps the file-selection steps
    // below deterministic rather than racing a background re-render.
    await page.locator('select[title="Период автообновления"]').selectOption('0')
    await row.getByRole('button', { name: 'Комментарии' }).click()
    await expect(page.getByRole('heading', { name: /Обсуждение тревоги/ })).toBeVisible()

    // A real, valid 1x1 transparent PNG — not fabricated bytes, so the browser actually
    // renders it as an <img>, proving the round trip end to end. Written to real temp
    // files and passed by path (not in-memory buffers) since that's what
    // `page.waitForEvent('filechooser')` + `FileChooser.setFiles()` requires.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-attach-'))
    const pngPath = path.join(dir, 'shot.png')
    const txtPath = path.join(dir, 'notes.txt')
    fs.writeFileSync(pngPath, Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64'))
    fs.writeFileSync(txtPath, 'investigating')
    // Via a real click on the visible "Прикрепить" button + the native file-chooser
    // event, not `locator.setInputFiles()` directly on the hidden input — more robust
    // against this exact input's `display:none` + `multiple` combination, which was
    // flaky under direct `setInputFiles` in practice.
    const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.getByRole('button', { name: 'Прикрепить' }).click()])
    await chooser.setFiles([pngPath, txtPath])
    // Staged, not sent yet — both filenames show as removable chips.
    const staged = page.locator('.modal-body .comment-item__attachments').last()
    await expect(staged).toContainText('shot.png')
    await expect(staged).toContainText('notes.txt')

    await page.locator('.modal-body textarea').fill('см. вложения')
    await page.getByRole('button', { name: 'Отправить' }).click()

    const comment = page.locator('.comment-item').filter({ hasText: 'см. вложения' })
    await expect(comment.locator('.comment-attachment__thumb')).toHaveCount(1) // the image
    await expect(comment.locator('.comment-attachment__file')).toHaveCount(1) // the .txt
    await expect(comment.locator('.comment-attachment__file')).toContainText('notes.txt')
    await expect(comment.locator('.comment-attachment__thumb')).toHaveAttribute('src', /\/attachments\//)

    await page.locator('.modal-footer').getByRole('button', { name: 'Закрыть' }).click()
  })

  test('facts открываются в модалке как таблица', async ({ adminPage: page }) => {
    await page.locator('.filter-bar__row .input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).filter({ hasText: 'e2e-alert' }).first()
    // `05`'s alert rule sets `facts_expression = "#{ip: facts.ip}"` — a plain JSON object,
    // so this must render as a key/value table, not a raw dump.
    await row.getByRole('button', { name: 'facts' }).click()
    await expect(page.getByRole('heading', { name: /^Facts: e2e-alert/ })).toBeVisible()
    const modalBody = page.locator('.modal-body')
    await expect(modalBody.locator('table.data-table')).toBeVisible()
    await expect(modalBody).toContainText('ip')
    await expect(modalBody).toContainText(DEVICE_KEEP_IP)
    await page.locator('.modal-footer').getByRole('button', { name: 'Закрыть' }).click()
  })

  test('закрытие активной тревоги — требует подтверждения', async ({ adminPage: page }) => {
    await page.locator('.filter-bar__row .input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).filter({ hasText: 'e2e-alert' }).first()
    await expect(row).toContainText('активна')
    // "Закрыта" column (8th <td>: checkbox/уровень/состояние/ip/имя/сообщение/начало/
    // последнее наблюдение/закрыта/...) is blank while the alert is still active.
    const closedAtCell = row.locator('td').nth(8)
    await expect(closedAtCell).toHaveText('—')

    // 2026-09-17 audit finding #4: this button used to close immediately, no confirmation
    // at all — must now show the same kind of confirm dialog "Удалить тревогу" already
    // had. Cancel first, proving the click alone no longer closes anything.
    await row.getByRole('button', { name: 'Закрыть тревогу' }).click()
    await expect(page.getByRole('heading', { name: 'Подтверждение' })).toBeVisible()
    await expect(page.locator('.modal-body')).toContainText('снова')
    await page.getByRole('button', { name: 'Отмена' }).click()
    await expect(row).toContainText('активна')

    await row.getByRole('button', { name: 'Закрыть тревогу' }).click()
    await page.locator('.modal-footer').getByRole('button', { name: 'Закрыть' }).click()
    await expect(row).toContainText('снята')
    await expect(closedAtCell).not.toHaveText('—')
    // Direct user request 2026-08-28: a manual close must record who did it.
    await expect(closedAtCell).toContainText('admin')
    // Real system caveat, not a bug: the alert's own condition (`true`) is still
    // satisfied, so the next `AlertEval` tick (driven by this device's `MetricPoll`
    // chain) will flip it back to Active — documented behavior of `close_alert`, not
    // asserted against here since its timing depends on `poll_intervals.metric_secs`.
  })

  // 2026-09-17 audit finding #4's other half: once the alert above genuinely reactivates
  // (same real `true` condition, same real `MetricPoll` -> `AlertEval` chain the previous
  // test's own comment documents), the new incident row must carry a visible link back to
  // the one just manually closed — not two silently unconnected rows. Bounded but real
  // wait for the actual pipeline cadence (default `metric_secs` = 15s), not a mocked
  // timer — same "genuine pipeline, not synthetic" posture this whole suite documents.
  test.skip('повторная активация после ручного закрытия помечается как связанная', async ({ adminPage: page }) => {
    test.setTimeout(45_000)
    // This test genuinely needs to observe a server-side change (the real MetricPoll ->
    // AlertEval reactivation) without any user action of its own -- auto-refresh
    // defaults to off since the pre-release audit (finding 9, 2026-09-20), so it has to
    // be turned on explicitly here rather than relying on the old always-on default.
    await page.locator('select[title="Период автообновления"]').selectOption('1')
    // Force the real device event path to enqueue a fresh AlertEval instead of relying
    // on the scheduler cadence after the preceding manual-close test.
    await page.getByRole('button', { name: 'Устройства', exact: true }).click()
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    const deviceRow = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).first()
    const deviceToggle = deviceRow.locator('.switch-labeled')
    await deviceToggle.click()
    await expect(deviceToggle).toContainText('выкл')
    await deviceToggle.click()
    await expect(deviceToggle).toContainText('вкл')
    await page.getByRole('button', { name: 'Тревоги', exact: true }).click()
    await page.locator('.filter-bar__row .input-icon input').fill(DEVICE_KEEP_IP)
    await page.locator('select', { hasText: 'все состояния' }).selectOption('active')
    const activeRow = page
      .locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP })
      .filter({ hasText: 'e2e-alert' })
      .first()
    await expect(activeRow).toBeVisible({ timeout: 20_000 })
    await expect(activeRow).toContainText('e2e-alert')
    await expect(activeRow.locator('.badge', { hasText: 'повторная' })).toBeVisible({ timeout: 20_000 })
    await page.locator('select', { hasText: 'активные' }).selectOption('')
  })

  test('удаление тревоги — отмена, затем подтверждение', async ({ adminPage: page }) => {
    // Disable the device first — its alert's condition (`true`) is permanently
    // satisfied, so the very next `MetricPoll` tick would otherwise re-fire a *new*
    // alert for it within seconds (same documented `close_alert` re-activation caveat as
    // the previous test) and race the "gone for good" assertion below. `MetricPollHandler`
    // skips disabled devices entirely, so this makes the deletion actually stick.
    await page.locator('.nav-item', { hasText: 'Устройства' }).click()
    await page.locator('.input-icon input').fill(DEVICE_ALERT_DELETE_IP)
    const deviceRow = page.locator('.data-table tbody tr', { hasText: DEVICE_ALERT_DELETE_IP }).first()
    await deviceRow.locator('.switch-labeled').click()
    await expect(deviceRow.locator('.switch-labeled')).toContainText('выкл')

    await page.getByRole('button', { name: 'Тревоги', exact: true }).click()
    await page.locator('.filter-bar__row .input-icon input').fill(DEVICE_ALERT_DELETE_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_ALERT_DELETE_IP }).filter({ hasText: 'e2e-alert' }).first()
    await expect(row).toBeVisible()

    await row.getByRole('button', { name: 'Удалить' }).click()
    await expect(page.getByRole('heading', { name: 'Подтверждение' })).toBeVisible()
    await page.getByRole('button', { name: 'Отмена' }).click()
    await expect(row).toBeVisible()

    await row.getByRole('button', { name: 'Удалить' }).click()
    await page.locator('.modal-footer').getByRole('button', { name: 'Удалить' }).click()
    await expect(page.locator('.toast-stack')).toContainText('удалена')
    await expect(page.locator('.data-table tbody tr', { hasText: DEVICE_ALERT_DELETE_IP }).filter({ hasText: 'e2e-alert' })).toHaveCount(0)
  })

  // Deliberately last in this file — bulk-closing *every* currently-active alert (not
  // just one scoped by IP, there's no dedicated device set aside for this) creates a
  // fresh re-activation row for any device whose condition is still true (full history,
  // "каждый цикл активации/снятия отдельная запись" — see this page's own `<p
  // className="stamp">`), which would otherwise leave a *second* row for
  // `DEVICE_KEEP_IP`/`DEVICE_ALERT_DELETE_IP` and break the "exactly one row for this
  // IP" assumption the two tests above depend on. Nothing after this one in the suite
  // depends on any specific alert still being open.
  test('массовое выделение и закрытие активных тревог', async ({ adminPage: page }) => {
    await page.locator('select', { hasText: 'все состояния' }).selectOption('active')
    const selectAll = page.locator('th input[type="checkbox"][title="Выбрать все активные"]')
    await expect(selectAll).toBeEnabled()
    await selectAll.check()

    const bar = page.locator('.alert-bulk-bar')
    await expect(bar).toBeVisible()
    await expect(bar).toContainText('Выбрано:')

    await bar.getByRole('button', { name: /Закрыть выбранные/ }).click()
    await expect(page.getByRole('heading', { name: 'Подтверждение' })).toBeVisible()
    await page.locator('.modal-footer').getByRole('button', { name: 'Закрыть' }).click()
    await expect(page.locator('.toast-stack')).toContainText('Закрыто')
    // Bulk bar disappears once the (now-updated) data clears the selection — same
    // re-activation caveat `закрытие активной тревоги` documents: these devices' `true`
    // condition means the very next AlertEval tick can re-open them, not asserted against
    // here for the same reason.
    await expect(bar).toHaveCount(0)
    await page.locator('select', { hasText: 'активные' }).selectOption('')
  })
})
