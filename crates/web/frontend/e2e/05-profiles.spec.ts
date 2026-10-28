/**
 * Also seeds the profile `06`/`07`/`08`/`09` rely on: `match.expression = "true"` matches
 * every device unconditionally, and its one alert rule fires immediately on any device's
 * first metric-poll tick (`expression = "true"`, no `metrics.*` reference needed) — see
 * `06-discovery.spec.ts`'s docs for exactly how that turns into real devices/alerts/queue
 * activity without a real SNMP agent anywhere.
 */
import { test, expect, fieldByLabel, fieldInput } from './fixtures'
import { E2E_PROFILE_NAME } from './shared'

test.describe('Профили', () => {
  test('создание профиля (match + метрика + тревога), редактирование, синхронизация устройств', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Профили' }).click()

    await page.getByRole('button', { name: 'Создать', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Новый профиль' })).toBeVisible()
    await fieldInput(page, 'Имя профиля').fill(E2E_PROFILE_NAME)
    await fieldInput(page, 'Приоритет').fill('100')
    await fieldInput(page, 'Match-выражение').fill('true')

    await page.locator('.tabs button', { hasText: 'Метрики' }).click()
    await page.getByRole('button', { name: /Метрика$/ }).click()
    await fieldInput(page, 'Имя метрики').fill('dummy')
    await fieldInput(page, 'OID').fill('1.3.6.1.2.1.1.1.0')

    await page.locator('.tabs button', { hasText: 'Тревоги' }).click()
    await page.getByRole('button', { name: /Тревога$/ }).click()
    await fieldInput(page, 'Имя').fill('e2e-alert')
    await fieldInput(page, 'Условие активации').fill('true')
    // Snapshot, guaranteed to exist for every device (unlike `metrics.*`, which this
    // profile's TEST-NET-3 targets never successfully poll) — gives `09-alerts.spec.ts`'s
    // Facts-modal test a real, non-null `facts` object to open.
    await fieldInput(page, 'Facts-выражение').fill('#{ip: facts.ip}')
    await fieldInput(page, 'Сообщение').fill('e2e test alert on {facts.ip}')

    await page.getByRole('button', { name: 'Сохранить профиль' }).click()
    const card = page.locator('.card', { hasText: E2E_PROFILE_NAME })
    await expect(card).toBeVisible()
    await expect(card).toContainText('метрик: 1')
    await expect(card).toContainText('тревог: 1')

    // --- Edit: bump priority, verify it round-trips ---
    await card.getByRole('button', { name: 'Изменить' }).click()
    await expect(page.getByRole('heading', { name: `Редактировать профиль: ${E2E_PROFILE_NAME}` })).toBeVisible()
    await fieldInput(page, 'Приоритет').fill('200')
    await page.getByRole('button', { name: 'Сохранить профиль' }).click()
    // Save closes the modal immediately but `load()` (the refetch that actually updates
    // what the card renders) isn't awaited by the save handler — reopening the edit
    // modal before it resolves would hand back the pre-edit cached object. Wait for the
    // card's own text to reflect the new value first (auto-retrying, so this just waits
    // out however long the refetch actually takes).
    await expect(card).toContainText('приоритет 200')
    await card.getByRole('button', { name: 'Изменить' }).click()
    await expect(fieldInput(page, 'Приоритет')).toHaveValue('200')
    await page.locator('.modal-header button[title="Закрыть"]').click()

    // --- Sync devices: no devices matched yet at this point in the suite ---
    await card.getByRole('button', { name: /Синхр. устройства/ }).click()
    await expect(card).toContainText('синхронизировано устройств: 0')
  })

  test('настройки гистерезиса и flapping сохраняются в правиле тревоги', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Профили' }).click()
    await page.getByRole('button', { name: /Создать/ }).click()
    await fieldInput(page, 'Имя профиля').fill('e2e-hysteresis-profile')
    await fieldInput(page, 'Приоритет').fill('0')
    await fieldInput(page, 'Match-выражение').fill('metrics.sys_descr.contains("no-such-vendor-anywhere")')
    await page.locator('.tabs button', { hasText: 'Тревоги' }).click()
    await page.getByRole('button', { name: /Тревога$/ }).click()
    await fieldInput(page, 'Имя').fill('e2e-hysteresis-alert')
    await fieldInput(page, 'Условие активации').fill('metrics.cpu > 90')
    await fieldInput(page, 'Сообщение').fill('hysteresis test')
    await fieldInput(page, 'Задержка активации, секунд').fill('30')
    await fieldInput(page, 'Окно flapping, секунд').fill('300')
    await fieldInput(page, 'Порог flapping, переключений').fill('4')
    await fieldInput(page, 'Держать условие деактивации истинным столько секунд перед снятием').fill('60')
    await page.getByRole('button', { name: 'Сохранить профиль' }).click()

    const card = page.locator('.card', { hasText: 'e2e-hysteresis-profile' })
    await expect(card).toBeVisible()
    await card.getByRole('button', { name: 'Изменить' }).click()
    await page.locator('.tabs button', { hasText: 'Тревоги' }).click()
    await expect(fieldInput(page, 'Задержка активации, секунд')).toHaveValue('30')
    await expect(fieldInput(page, 'Окно flapping, секунд')).toHaveValue('300')
    await expect(fieldInput(page, 'Порог flapping, переключений')).toHaveValue('4')
    await expect(fieldInput(page, 'Держать условие деактивации истинным столько секунд перед снятием')).toHaveValue('60')
    await page.locator('.modal-header button[title="Закрыть"]').click()
  })

  // 2026-09-17 audit finding #3: before `ProfileMatcher::validate_expression`/
  // `AlertEvaluator::validate_expression` were wired into `upsert_profile`, a broken
  // match/alert expression saved with the same green "сохранён" toast as a well-formed
  // one — the only symptom was a later, disconnected-looking failed `dedup` job. Never
  // actually saves (each attempt is expected to fail), so nothing here needs cleanup or
  // affects any later spec's profile-count assumptions.
  test('битое Rhai-выражение (match или тревога) отклоняется при сохранении, не сохраняется молча', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Профили' }).click()

    await page.getByRole('button', { name: /Создать/ }).click()
    await fieldInput(page, 'Имя профиля').fill('e2e-broken-profile')
    await fieldInput(page, 'Приоритет').fill('0')
    await fieldInput(page, 'Match-выражение').fill('metrics.sys_object_id == ((( broken rhai')
    await page.getByRole('button', { name: 'Сохранить профиль' }).click()
    await expect(page.locator('.form-error')).toContainText('match.expression')
    // Must not have saved — the modal stays open on a rejected save (no navigation away),
    // and the profile must never show up in the list.
    await expect(page.getByRole('heading', { name: 'Новый профиль' })).toBeVisible()

    // Fix the match expression, break an alert rule's expression instead.
    await fieldInput(page, 'Match-выражение').fill('true')
    await page.locator('.tabs button', { hasText: 'Тревоги' }).click()
    await page.getByRole('button', { name: /Тревога$/ }).click()
    await fieldInput(page, 'Имя').fill('broken-alert')
    await fieldInput(page, 'Условие активации').fill('metrics.cpu > ((( broken rhai')
    await fieldInput(page, 'Сообщение').fill('should never save')
    await page.getByRole('button', { name: 'Сохранить профиль' }).click()
    await expect(page.locator('.form-error')).toContainText('broken-alert')

    await page.locator('.modal-header button[title="Закрыть"]').click()
    await expect(page.locator('.card', { hasText: 'e2e-broken-profile' })).toHaveCount(0)
  })

  test('поиск и сортировка (server-side)', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Профили' }).click()

    // Real server-side search — matches by name (typed here) or by a declared metric
    // name (`dummy`, from the previous test's profile).
    await page.locator('.filter-bar .input-icon input').fill('does-not-exist-anywhere')
    await expect(page.getByText('Профилей не найдено')).toBeVisible()

    await page.locator('.filter-bar .input-icon input').fill('dummy')
    await expect(page.locator('.card', { hasText: E2E_PROFILE_NAME })).toBeVisible()

    await page.locator('.filter-bar .input-icon input').fill('')
    await expect(page.locator('.card', { hasText: E2E_PROFILE_NAME })).toBeVisible()

    // Sort control round-trips asc/desc without erroring — same "exercise the control"
    // scope `07-devices`'s own sort test uses (a single seeded profile isn't enough to
    // observe reordering meaningfully).
    const sortSelect = page.locator('.filter-bar select')
    await sortSelect.selectOption('priority')
    const sortDirBtn = page.locator('.filter-bar button').last()
    await expect(page.locator('.card', { hasText: E2E_PROFILE_NAME })).toBeVisible()
    await sortDirBtn.click()
    await expect(page.locator('.card', { hasText: E2E_PROFILE_NAME })).toBeVisible()
    await sortSelect.selectOption('name')
  })

  test('клонирование профиля', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Профили' }).click()
    // Exact match matters here — the clone below is named `${E2E_PROFILE_NAME}-clone`,
    // which a plain substring `hasText: E2E_PROFILE_NAME` would also match once it exists.
    const sourceTitle = page.locator('.config-card__title', { hasText: new RegExp(`^${E2E_PROFILE_NAME}$`) })
    const sourceCard = sourceTitle.locator('xpath=ancestor::div[contains(@class,"card-pad")][1]')
    await sourceCard.getByRole('button', { name: /Клонировать/ }).click()

    await expect(page.getByRole('heading', { name: `Новый профиль (копия «${E2E_PROFILE_NAME}»)` })).toBeVisible()
    // Cloned settings carried over... (200, not the original 100 — the very first test in
    // this file bumps it via its own "Edit: bump priority" step before this one runs)
    await expect(fieldInput(page, 'Приоритет')).toHaveValue('200')
    await expect(fieldInput(page, 'Match-выражение')).toHaveValue('true')
    // ...but the name itself is blank, forcing a real choice instead of a silent overwrite.
    await expect(fieldInput(page, 'Имя профиля')).toHaveValue('')

    // Deliberately narrowed to never actually match a real device — this suite's shared
    // devices all matched `E2E_PROFILE_NAME`'s own "true" expression; a second profile
    // with the same always-true match (and the same alert rule name) would double-count
    // alerts for `06`/`09`'s assertions. Only the clone *mechanism* is under test here.
    await fieldInput(page, 'Match-выражение').fill('metrics.sys_descr.contains("no-such-vendor-anywhere")')
    // Deliberately does NOT contain `E2E_PROFILE_NAME` as a substring — this persists for
    // the rest of the suite, and other specs' `hasText: E2E_PROFILE_NAME` locators (a
    // plain case-insensitive substring match) would otherwise start matching this row too.
    const cloneName = 'e2e-cloned-profile'
    await fieldInput(page, 'Имя профиля').fill(cloneName)
    await page.getByRole('button', { name: 'Сохранить профиль' }).click()

    const cloneCard = page.locator('.card', { hasText: cloneName })
    await expect(cloneCard).toBeVisible()
    await expect(cloneCard).toContainText('метрик: 1')
    await expect(cloneCard).toContainText('тревог: 1')
    // The original must be untouched by cloning it.
    await expect(sourceCard).toBeVisible()
  })

  test('экспорт/импорт метрик профиля', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Профили' }).click()
    const sourceTitle = page.locator('.config-card__title', { hasText: new RegExp(`^${E2E_PROFILE_NAME}$`) })
    const sourceCard = sourceTitle.locator('xpath=ancestor::div[contains(@class,"card-pad")][1]')
    await sourceCard.getByRole('button', { name: 'Изменить' }).click()
    await page.locator('.tabs button', { hasText: 'Метрики' }).click()

    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Экспорт' }).click()])
    const filePath = await download.path()
    expect(filePath).toBeTruthy()
    await page.locator('.modal-footer').getByRole('button', { name: 'Отмена' }).click()

    // Import into a brand-new (unsaved) profile — proves this actually transfers between
    // profiles, not just a no-op round trip back into the same one.
    await page.getByRole('button', { name: /Создать/ }).click()
    await page.locator('.tabs button', { hasText: 'Метрики' }).click()
    await expect(fieldInput(page, 'Имя метрики')).toHaveCount(0)

    await page.setInputFiles('input[type="file"]', filePath!)
    await expect(page.locator('.toast-stack')).toContainText('Импортировано метрик: 1')
    await expect(fieldInput(page, 'Имя метрики')).toHaveValue('dummy')

    await page.locator('.modal-footer').getByRole('button', { name: 'Отмена' }).click()
  })

  test('создание syslog-биндинга, сохранение, round-trip после переоткрытия', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Профили' }).click()

    await page.getByRole('button', { name: /Создать/ }).click()
    await fieldInput(page, 'Имя профиля').fill('e2e-syslog-profile')
    // Deliberately never matches a real device — this suite's shared devices already
    // matched `E2E_PROFILE_NAME`'s always-true expression, and this test only cares about
    // the syslog-tab editor itself, not device matching. Also deliberately doesn't contain
    // `E2E_PROFILE_NAME` as a substring, same reasoning as the clone test above.
    await fieldInput(page, 'Match-выражение').fill('metrics.sys_descr.contains("no-such-vendor-anywhere")')

    await page.locator('.tabs button', { hasText: 'Syslog' }).click()
    await page.getByRole('button', { name: /Биндинг$/ }).click()
    await fieldInput(page, 'Имя биндинга').fill('iface_down')
    await fieldInput(page, 'TTL строки').fill('3600')
    await fieldInput(page, 'Regex-паттерн').fill('(?P<ifName>\\S+) is down')
    await fieldInput(page, 'Severity').fill('4')
    await fieldInput(page, 'Facility').fill('23')
    await fieldInput(page, 'Ключ идентичности строки').fill('fields.ifName')

    await page.getByRole('button', { name: 'Сохранить профиль' }).click()
    const card = page.locator('.card', { hasText: 'e2e-syslog-profile' })
    await expect(card).toBeVisible()

    // --- Reopen and verify every field round-tripped through the backend unchanged ---
    await card.getByRole('button', { name: 'Изменить' }).click()
    await page.locator('.tabs button', { hasText: 'Syslog' }).click()
    await expect(fieldInput(page, 'Имя биндинга')).toHaveValue('iface_down')
    await expect(fieldInput(page, 'TTL строки')).toHaveValue('3600')
    await expect(fieldInput(page, 'Regex-паттерн')).toHaveValue('(?P<ifName>\\S+) is down')
    await expect(fieldInput(page, 'Severity')).toHaveValue('4')
    await expect(fieldInput(page, 'Facility')).toHaveValue('23')
    await expect(fieldInput(page, 'Ключ идентичности строки')).toHaveValue('fields.ifName')

    await page.locator('.modal-footer').getByRole('button', { name: 'Отмена' }).click()
  })

  test('создание trap-биндинга, сохранение, round-trip после переоткрытия', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Профили' }).click()

    await page.getByRole('button', { name: /Создать/ }).click()
    await fieldInput(page, 'Имя профиля').fill('e2e-trap-profile')
    // Deliberately never matches a real device — same reasoning as the syslog/clone tests
    // above; this test only cares about the Trap-tab editor itself.
    await fieldInput(page, 'Match-выражение').fill('metrics.sys_descr.contains("no-such-vendor-anywhere")')

    await page.locator('.tabs button', { hasText: 'Trap' }).click()
    await page.getByRole('button', { name: /Биндинг$/ }).click()
    await fieldInput(page, 'Имя биндинга').fill('link_down')
    await fieldInput(page, 'TTL строки').fill('1800')
    await fieldInput(page, 'Trap OID').fill('1.3.6.1.6.3.1.1.5.3')
    await fieldByLabel(page, 'Варбинды').getByRole('button', { name: 'Добавить' }).click()
    const varbindRow = fieldByLabel(page, 'Варбинды').locator('.filter-bar__row').first()
    await varbindRow.locator('input').nth(0).fill('if_index')
    await varbindRow.locator('input').nth(1).fill('1.3.6.1.2.1.2.2.1.1')
    await fieldInput(page, 'Ключ идентичности строки').fill('varbinds.if_index')

    await page.getByRole('button', { name: 'Сохранить профиль' }).click()
    const card = page.locator('.card', { hasText: 'e2e-trap-profile' })
    await expect(card).toBeVisible()

    // --- Reopen and verify every field round-tripped through the backend unchanged ---
    await card.getByRole('button', { name: 'Изменить' }).click()
    await page.locator('.tabs button', { hasText: 'Trap' }).click()
    await expect(page.locator('.tabs button', { hasText: 'Trap' })).toContainText('Trap (1)')
    await expect(fieldInput(page, 'Имя биндинга')).toHaveValue('link_down')
    await expect(fieldInput(page, 'TTL строки')).toHaveValue('1800')
    await expect(fieldInput(page, 'Trap OID')).toHaveValue('1.3.6.1.6.3.1.1.5.3')
    const varbindRowReopened = fieldByLabel(page, 'Варбинды').locator('.filter-bar__row').first()
    await expect(varbindRowReopened.locator('input').nth(0)).toHaveValue('if_index')
    await expect(varbindRowReopened.locator('input').nth(1)).toHaveValue('1.3.6.1.2.1.2.2.1.1')
    await expect(fieldInput(page, 'Ключ идентичности строки')).toHaveValue('varbinds.if_index')

    await page.locator('.modal-footer').getByRole('button', { name: 'Отмена' }).click()
  })

  test('создание service-чека (http), сохранение, round-trip после переоткрытия', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Профили' }).click()

    await page.getByRole('button', { name: /Создать/ }).click()
    await fieldInput(page, 'Имя профиля').fill('e2e-servicecheck-profile')
    await fieldInput(page, 'Match-выражение').fill('metrics.sys_descr.contains("no-such-vendor-anywhere")')

    await page.locator('.tabs button', { hasText: 'Service Check' }).click()
    await page.getByRole('button', { name: /Чек$/ }).click()
    await fieldInput(page, 'Имя').fill('web_ui')
    await fieldInput(page, 'Протокол').selectOption('http')
    await fieldInput(page, 'Target').fill('203.0.113.50')
    await fieldInput(page, 'Порт').fill('8080')
    await fieldInput(page, 'Path').fill('/health')
    await fieldInput(page, 'Ожидаемый статус').fill('200')
    await fieldInput(page, 'Тело содержит').fill('ok')

    await page.getByRole('button', { name: 'Сохранить профиль' }).click()
    const card = page.locator('.card', { hasText: 'e2e-servicecheck-profile' })
    await expect(card).toBeVisible()

    await card.getByRole('button', { name: 'Изменить' }).click()
    await page.locator('.tabs button', { hasText: 'Service Check' }).click()
    await expect(page.locator('.tabs button', { hasText: 'Service Check' })).toContainText('Service Check (1)')
    await expect(fieldInput(page, 'Имя')).toHaveValue('web_ui')
    await expect(fieldInput(page, 'Протокол')).toHaveValue('http')
    await expect(fieldInput(page, 'Target')).toHaveValue('203.0.113.50')
    await expect(fieldInput(page, 'Порт')).toHaveValue('8080')
    await expect(fieldInput(page, 'Path')).toHaveValue('/health')
    await expect(fieldInput(page, 'Ожидаемый статус')).toHaveValue('200')
    await expect(fieldInput(page, 'Тело содержит')).toHaveValue('ok')

    await page.locator('.modal-footer').getByRole('button', { name: 'Отмена' }).click()
  })

  test('метрика с источником ssh — сохранение, round-trip после переоткрытия', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Профили' }).click()

    await page.getByRole('button', { name: /Создать/ }).click()
    await fieldInput(page, 'Имя профиля').fill('e2e-ssh-metric-profile')
    await fieldInput(page, 'Match-выражение').fill('metrics.sys_descr.contains("no-such-vendor-anywhere")')

    await page.locator('.tabs button', { hasText: 'Метрики' }).click()
    await page.getByRole('button', { name: /Метрика$/ }).click()
    await fieldInput(page, 'Имя метрики').fill('uptime_pretty')
    await fieldInput(page, 'Источник').selectOption('ssh')
    // Not fieldInput('Команда') — the "Источник" <select> above always renders both
    // <option>s in the DOM (including "ssh (команда)"), so a plain substring/first-match
    // on "Команда" resolves to that select, not the real textarea. .last() is the actual
    // "Команда" field since nothing after it also matches.
    const commandField = page.locator('.field', { hasText: 'Команда' }).last().locator('textarea')
    await commandField.fill('show uptime')
    // Table/derive controls are snmp-only — never rendered for an ssh-source metric.
    await expect(page.getByText('Производная метрика')).toHaveCount(0)

    await page.getByRole('button', { name: 'Сохранить профиль' }).click()
    await page.locator('input[placeholder="Имя, метрика…"]').fill('e2e-ssh-metric-profile')
    const card = page.locator('.card', { hasText: 'e2e-ssh-metric-profile' })
    await expect(card).toBeVisible()
    await expect(card).toContainText('метрик: 1')

    await card.getByRole('button', { name: 'Изменить' }).click()
    await page.locator('.tabs button', { hasText: 'Метрики' }).click()
    await expect(fieldInput(page, 'Имя метрики')).toHaveValue('uptime_pretty')
    await expect(fieldInput(page, 'Источник')).toHaveValue('ssh')
    await expect(page.locator('.field', { hasText: 'Команда' }).last().locator('textarea')).toHaveValue('show uptime')

    await page.locator('.modal-footer').getByRole('button', { name: 'Отмена' }).click()
  })
})
