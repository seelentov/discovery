import { test, expect, fieldByLabel, fieldInput } from './fixtures'

test.describe('Настройки', () => {
  test.beforeEach(async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Настройки' }).click()
  })

  test('периодичность опроса — round trip', async ({ adminPage: page }) => {
    await page.locator('.settings-nav button', { hasText: 'Периодичность опроса' }).click()
    const field = fieldInput(page, 'Опрос метрик профиля по умолчанию')
    await expect(field).toHaveValue('15')
    await field.fill('42')
    await page.locator('.form-actions').getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/сохранен/i)

    // Persistence proof: navigate away and back *within* the SPA (no full document
    // reload — `page.reload()` here would hit an unrelated real quirk: Chrome's default
    // scroll-restoration can leave the page scrolled from before the reload, and the
    // freshly re-rendered settings-nav's first button then ends up under the sticky
    // `.topbar` at that same offset, making it unclickable. Worth a follow-up fix in
    // `SettingsPage`/`global.css` but out of scope for proving this round trip).
    // `SettingsPage.loadAll()` refetches from the server on every mount either way, so
    // this equally proves the value actually persisted server-side, not just in local state.
    await page.locator('.nav-item', { hasText: 'Обзор' }).click()
    await page.locator('.nav-item', { hasText: 'Настройки' }).click()
    await page.locator('.settings-nav button', { hasText: 'Периодичность опроса' }).click()
    await expect(fieldInput(page, 'Опрос метрик профиля по умолчанию')).toHaveValue('42')
    // restore, so later specs (profiles/discovery) that rely on a fast metric_secs still
    // get one — 42s would make 06-discovery's alert-appears wait needlessly long.
    await fieldInput(page, 'Опрос метрик профиля по умолчанию').fill('5')
    await page.locator('.form-actions').getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/сохранен/i)
  })

  // Хранение тревог / Хранение логов / Удаление недоступных устройств now share one
  // "Хранение и очистка" tab (direct user request 2026-08-28 — same shape, one nav click
  // instead of three) — each keeps its own card + independent Сохранить button, so saves
  // below are scoped to the specific `.card-pad` by its `.card-title`, since a bare
  // `.form-actions button` locator would otherwise match all three cards' buttons at once.
  test('хранение тревог — чекбокс "вечно" блокирует числовое поле', async ({ adminPage: page }) => {
    await page.locator('.settings-nav button', { hasText: 'Хранение и очистка' }).click()
    const card = page.locator('.card-pad', { hasText: 'Хранение тревог' })
    const checkbox = card.locator('.checkbox-row', { hasText: 'Хранить снятые тревоги вечно' }).locator('input')
    const secsField = fieldInput(page, 'Хранить снятые тревоги, сек')
    await expect(checkbox).toBeChecked() // AlertRetentionConfig defaults to null = forever
    await expect(secsField).toBeDisabled()
    await checkbox.uncheck()
    await expect(secsField).toBeEnabled()
    await secsField.fill('604800')
    await card.getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/сохранен/i)
    // restore to forever, don't leave a side effect for other specs.
    await checkbox.check()
    await card.getByRole('button', { name: 'Сохранить' }).click()
  })

  test('хранение тревог — отклоняет пустое, нулевое, отрицательное и дробное значение', async ({ adminPage: page }) => {
    await page.locator('.settings-nav button', { hasText: 'Хранение и очистка' }).click()
    const card = page.locator('.card-pad', { hasText: 'Хранение тревог' })
    const checkbox = card.locator('.checkbox-row', { hasText: 'Хранить снятые тревоги вечно' }).locator('input')
    const secsField = fieldInput(page, 'Хранить снятые тревоги, сек')
    await checkbox.uncheck()
    for (const value of ['', '0', '-1', '1.5']) {
      await secsField.fill(value)
      await card.getByRole('button', { name: 'Сохранить' }).click()
      await expect(page.locator('.toast-stack')).toContainText('целое число секунд больше нуля')
    }
    await secsField.fill('604800')
    await card.getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/сохранен/i)
    await checkbox.check()
    await card.getByRole('button', { name: 'Сохранить' }).click()
  })

  test('хранение логов — тот же nullable-вечно контракт', async ({ adminPage: page }) => {
    await page.locator('.settings-nav button', { hasText: 'Хранение и очистка' }).click()
    const card = page.locator('.card-pad', { hasText: 'Хранение логов' })
    const checkbox = card.locator('.checkbox-row', { hasText: 'Хранить логи вечно' }).locator('input')
    await expect(checkbox).toBeChecked()
    await card.getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/сохранен/i)
  })

  test('ping — таймаут и повторы', async ({ adminPage: page }) => {
    await page.locator('.settings-nav button', { hasText: 'Ping' }).click()
    await expect(fieldInput(page, 'Таймаут пробы')).toHaveValue(/\d+/)
    await fieldInput(page, 'Повторов после первой неудачи').fill('3')
    await page.locator('.form-actions').getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/сохранен/i)
  })

  test('удаление недоступных устройств — "никогда" (0) блокирует поле', async ({ adminPage: page }) => {
    await page.locator('.settings-nav button', { hasText: 'Хранение и очистка' }).click()
    const card = page.locator('.card-pad', { hasText: 'Удаление недоступных устройств' })
    const checkbox = card.locator('.checkbox-row', { hasText: 'Никогда не удалять' }).locator('input')
    await expect(checkbox).toBeChecked()
    await expect(fieldInput(page, 'Удалять после недоступности')).toBeDisabled()
    await card.getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/сохранен/i)
  })

  test('базы данных — добавить БД, маршрутизация, баннер рестарта (без реального рестарта)', async ({ adminPage: page }) => {
    await page.locator('.settings-nav button', { hasText: 'Базы данных' }).click()
    // Direct user question 2026-08-28: an empty list with no explanation reads as a bug
    // ("на какой БД работает агент?") — it's actually the documented implicit
    // `sqlite::memory:` fallback (this suite's own zero-config `CONFIG_FILE` setup, see
    // `global-setup.ts`), just never said so on screen before this fix.
    await expect(page.getByText('sqlite::memory:')).toBeVisible()
    // 2026-09-17 audit finding #8: this text used to hardcode "8 доменов данных", already
    // stale by the time of the audit (real count: 12, `DOMAINS.length` in api/types.ts) —
    // now derived from that same array instead of repeating a number that can drift again.
    await expect(page.getByText(/все 12 доменов данных/)).toBeVisible()
    await page.getByRole('button', { name: 'Добавить БД' }).click()
    const nameInput = page.locator('input[placeholder="имя (уникальное)"]').last()
    await nameInput.fill('e2e-sqlite')
    const row = nameInput.locator('xpath=ancestor::div[contains(@class,"card-pad")][1]')
    await row.locator('select').selectOption('sqlite') // already the default kind, explicit for clarity
    await row.locator('input[type="radio"]').check() // "по умолчанию" — required once databases is non-empty
    await row.locator('input[placeholder="storage.sqlite3"]').fill('e2e.sqlite3')
    await page.getByRole('button', { name: 'Сохранить список БД' }).click()
    await expect(page.getByText(/Настройки БД сохранены/)).toBeVisible()
    // Explicitly NOT clicking "Перезапустить сейчас" — that calls POST /api/system/restart,
    // which kills the shared backend this whole suite depends on. Dismiss instead.
    await page.getByRole('button', { name: 'Позже' }).click()

    const routingField = fieldInput(page, 'Устройства')
    await expect(routingField.locator('option', { hasText: 'e2e-sqlite' })).toHaveCount(1)
    await routingField.selectOption('e2e-sqlite')
    await page.getByRole('button', { name: 'Сохранить маршрутизацию' }).click()
    await expect(page.getByText(/Настройки БД сохранены/)).toBeVisible()
    await page.getByRole('button', { name: 'Позже' }).click()
  })

  test('ClickHouse/Cassandra доступны в списке БД и ограничены нужными доменами в маршрутизации', async ({ adminPage: page }) => {
    await page.locator('.settings-nav button', { hasText: 'Базы данных' }).click()
    await page.getByRole('button', { name: 'Добавить БД' }).click()
    const nameInput = page.locator('input[placeholder="имя (уникальное)"]').last()
    await nameInput.fill('e2e-clickhouse')
    const row = nameInput.locator('xpath=ancestor::div[contains(@class,"card-pad")][1]')
    await row.locator('select').selectOption('clickhouse')
    // ClickHouse-specific field labels/hints — real UI gap this session closed, not a
    // design-artifact port (the backend already fully supported both kinds). Hints are a
    // hover tooltip on the control now (2026-08-29, direct user request: "убери лишние
    // текстовые подсказки в статичном тексте"), not always-visible text.
    await expect(fieldByLabel(row, 'Порт').locator('.field-control')).toHaveAttribute('title', 'пусто — 8123 по умолчанию')
    await row.locator('input[placeholder="127.0.0.1"]').fill('127.0.0.1')
    await page.getByRole('button', { name: 'Сохранить список БД' }).click()
    await expect(page.getByText(/Настройки БД сохранены/)).toBeVisible()
    await page.getByRole('button', { name: 'Позже' }).click()

    // Routing: ClickHouse only fits "Логи" (append-only) — every other domain's dropdown
    // must not offer it at all, matching `Config::validate`'s own restriction exactly.
    const logsRouting = fieldInput(page, 'Логи')
    await expect(logsRouting.locator('option', { hasText: 'e2e-clickhouse' })).toHaveCount(1)
    const devicesRouting = fieldInput(page, 'Устройства')
    await expect(devicesRouting.locator('option', { hasText: 'e2e-clickhouse' })).toHaveCount(0)
  })

  test('клонирование записи БД', async ({ adminPage: page }) => {
    await page.locator('.settings-nav button', { hasText: 'Базы данных' }).click()
    // `e2e-sqlite`, saved by the earlier "добавить БД" test, already persists server-side
    // by this point in the suite. No `hasText`/`getByRole` shortcut peeks into a plain
    // `<input>`'s current *value* the way it does for text content, so find the row by
    // checking each name input's live value directly instead.
    const nameInputs = page.locator('input[placeholder="имя (уникальное)"]')
    // The list loads async after the tab click (`databases` starts `[]`) — wait for it,
    // otherwise the loop below races an empty DOM.
    await expect(nameInputs.first()).toBeVisible()
    async function rowByName(name: string) {
      const count = await nameInputs.count()
      for (let i = 0; i < count; i++) {
        if ((await nameInputs.nth(i).inputValue()) === name) return nameInputs.nth(i)
      }
      throw new Error(`no БД row named "${name}"`)
    }

    const sourceNameInput = await rowByName('e2e-sqlite')
    const sourceRow = sourceNameInput.locator('xpath=ancestor::div[contains(@class,"card-pad")][1]')
    await sourceRow.getByRole('button', { name: /Клонировать/ }).click()

    // Clone appends a new row at the end with a blank name and the same kind — it doesn't
    // open a modal (this editor is inline, unlike Profiles/Discovery's clone).
    const cloneNameInput = nameInputs.last()
    await expect(cloneNameInput).toHaveValue('')
    const cloneRow = cloneNameInput.locator('xpath=ancestor::div[contains(@class,"card-pad")][1]')
    await expect(cloneRow.locator('select')).toHaveValue('sqlite')

    await cloneNameInput.fill('e2e-sqlite-clone')
    await page.getByRole('button', { name: 'Сохранить список БД' }).click()
    await expect(page.getByText(/Настройки БД сохранены/)).toBeVisible()
    await page.getByRole('button', { name: 'Позже' }).click()

    // The original is untouched by cloning it.
    await rowByName('e2e-sqlite')
    await rowByName('e2e-sqlite-clone')
  })
})
