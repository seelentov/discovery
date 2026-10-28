import { test, expect, fieldInput } from './fixtures'
import { DEVICE_DELETE_IP, DEVICE_KEEP_IP, DEVICE_MANUAL_CREATE_IP, E2E_PROFILE_NAME } from './shared'

test.describe('Устройства', () => {
  test.beforeEach(async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Устройства' }).click()
  })

  test('поиск, сортировка, раскрытие строки с метриками', async ({ adminPage: page }) => {
    // Direct user request 2026-08-28: configurable auto-refresh (same pattern as Alerts).
    // Default changed from 1s to off (pre-release audit finding 9, 2026-09-20, direct
    // user request) -- auto-refresh anywhere should be opt-in.
    await expect(page.getByRole('button', { name: 'Обновить' })).toBeVisible()
    await expect(page.locator('.filter-bar select[title="Период автообновления"]')).toHaveValue('0')

    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).first()
    await expect(row).toBeVisible()
    // Matched the always-true profile from `05` — profile column shows it, not "без профиля".
    await expect(row).toContainText('e2e-test-profile')

    // Sort indicator toggles asc -> desc -> back to default (ip/asc) on a 3rd click —
    // just exercising the control here, not the resulting order (search already narrows
    // this to a single real row, not enough to observe reordering meaningfully).
    const ipHeader = page.locator('.th-sortable', { hasText: 'IP' })
    await ipHeader.click()
    await expect(ipHeader.locator('.sort-ind')).toBeVisible()
    await ipHeader.click()
    await ipHeader.click()

    await row.locator('.expand-btn').click()
    const metricsTable = row.locator('xpath=following-sibling::tr[1]').locator('.metrics-table')
    await expect(metricsTable).toBeVisible()
    await expect(metricsTable).toContainText('dummy')
  })

  test('безопасное действие показывает job и итог проверки', async ({ adminPage: page }) => {
    const ip = '198.51.100.236'
    await page.getByRole('button', { name: 'Создать' }).click()
    await page.locator('.modal-body .field', { hasText: 'IP' }).locator('input').fill(ip)
    await page.locator('.modal-footer').getByRole('button', { name: 'Создать' }).click()
    await expect(page.locator('.toast-stack')).toContainText('создано')
    await page.locator('.input-icon input').fill(ip)
    const row = page.locator('.data-table tbody tr', { hasText: ip }).first()
    await expect(row).toBeVisible()
    await row.locator('.expand-btn').click()
    const actions = page.locator(`section[aria-label="Действия устройства ${ip}"]`)
    await expect(actions.getByRole('button', { name: 'Проверить' })).toBeVisible()
    await actions.getByRole('button', { name: 'Проверить' }).click()
    await expect(actions.getByRole('status')).toContainText('Задача #')
    await expect(actions.getByRole('status')).toContainText('done', { timeout: 30_000 })
    await expect(actions.getByRole('status')).toContainText('ping:')
    // This scenario owns its device; later CIDR tests use the suite's shared devices.
    const deleted = await page.evaluate(async (ip) => {
      const response = await fetch(`/api/devices?search=${ip}`)
      const body = await response.json()
      const device = body.items.find((d: { facts: { ip: string } }) => d.facts.ip === ip)
      return device ? (await fetch(`/api/devices/${device.id}`, { method: 'DELETE' })).status : 404
    }, ip)
    expect(deleted).toBe(204)
  })

  // 2026-09-17 audit finding #6: at ~1280px the "Действия" column ran off the edge of
  // `.table-wrap`'s `overflow-x: auto` with no visual hint there was anything to scroll
  // to. Fixed with a pure-CSS scroll-shadow (see `global.css`'s `.table-wrap` docs) —
  // checked here via computed style rather than a pixel screenshot: the fix's actual
  // mechanism is a `background-attachment: local, local, scroll, scroll` 4-layer
  // gradient, which a plain visual diff couldn't attribute to *this* fix as opposed to
  // any other border/shadow-shaped change.
  test('таблица показывает CSS-тень для скролла на узком экране (нет пиксель-скриншота — проверяется сам механизм)', async ({ adminPage: page }) => {
    await page.setViewportSize({ width: 1280, height: 800 })
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    const wrap = page.locator('.table-wrap').first()
    await expect(wrap).toBeVisible()
    const attachment = await wrap.evaluate((el) => getComputedStyle(el).backgroundAttachment)
    const layers = attachment.split(',').map((s) => s.trim())
    expect(layers).toEqual(['local', 'local', 'scroll', 'scroll'])
    const image = await wrap.evaluate((el) => getComputedStyle(el).backgroundImage)
    expect(image.split('linear-gradient').length - 1).toBe(4) // four gradient layers, not a plain flat background
  })

  test('таблица метрик устройства — свой "Обновить"/период, override метрики переживает собственный refresh', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).first()
    await row.locator('.expand-btn').click()
    const detail = row.locator('xpath=following-sibling::tr[1]')

    // Direct user request 2026-08-28: this sub-table has its own independent "Обновить" +
    // period select, separate from the page-level ones in `.filter-bar`.
    await expect(detail.getByRole('button', { name: 'Обновить' })).toBeVisible()
    // Positional, not `select[title*=...]` — the only `<select>` in this scope, and a
    // title-substring attribute selector was flaky here in practice.
    const refreshSelect = detail.locator('select')
    await expect(refreshSelect).toBeEnabled()

    const dummyRow = detail.locator('.metrics-table tbody tr', { hasText: 'dummy' })
    await dummyRow.locator('.switch-labeled').click()
    // The toggle round-trips through `onToggleMetric` then this component's own `load()`
    // (not the page-level `load()`, which is paused while a row is expanded) — the
    // manual-override reset icon appearing proves that self-refresh actually happened.
    // Icon-only (2026-08-29, direct user request — was a visible "ручной override" text
    // button, replaced with an icon centered next to the switch; accessible name now
    // comes from its `title`, which still contains the word "override").
    const overrideResetBtn = dummyRow.getByRole('button', { name: /override/i })
    await expect(overrideResetBtn).toBeVisible()

    await overrideResetBtn.click()
    await expect(dummyRow.getByRole('button', { name: /override/i })).toHaveCount(0)
  })

  test('trap/syslog-таблица явно показывает свёрнутое состояние и раскрывает те же строки', async ({ adminPage: page }) => {
    // Push listeners are disabled in the isolated E2E agent. Inject the exact MetricView
    // shape produced by trap/syslog ingestion while keeping the real device response.
    await page.route('**/api/devices**', async (route) => {
      if (route.request().method() !== 'GET') {
        await route.continue()
        return
      }
      const response = await route.fetch()
      const url = new URL(route.request().url())
      if (!url.pathname.match(/\/api\/devices(?:\/[^/]+)?$/)) {
        await route.fulfill({ response })
        return
      }

      const body = await response.json()
      const pushMetrics = (metrics: Record<string, unknown>[]) => [
        ...metrics.filter((metric) => !String(metric.name).startsWith('trap_') && !String(metric.name).startsWith('syslog_')),
        {
          name: 'syslog_iface_down',
          value: [{ index: 'xe-0/0/1', fields: { ifName: 'xe-0/0/1', message: 'is down' } }],
          error: null,
          polled_at: new Date().toISOString(),
          last_attempt_at: new Date().toISOString(),
          enabled_override: null,
          effective_enabled: true,
        },
        {
          name: 'trap_link_down_empty',
          value: [],
          error: null,
          polled_at: new Date().toISOString(),
          last_attempt_at: new Date().toISOString(),
          enabled_override: null,
          effective_enabled: true,
        },
        {
          name: 'trap_link_down_error',
          value: null,
          error: 'synthetic trap ingest error',
          polled_at: null,
          last_attempt_at: new Date().toISOString(),
          enabled_override: null,
          effective_enabled: true,
        },
      ]

      if (Array.isArray(body.items)) {
        body.items = body.items.map((item: { metrics?: Record<string, unknown>[] }) => ({
          ...item,
          metrics: pushMetrics(Array.isArray(item.metrics) ? item.metrics : []),
        }))
      } else if (Array.isArray(body.metrics)) {
        body.metrics = pushMetrics(body.metrics)
      }
      await route.fulfill({ response, json: body })
    })

    // The beforeEach hook opened this page before the route was installed; reload so the
    // initial device-list response is the deterministic injected fixture.
    await page.reload()
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).first()
    await row.locator('.expand-btn').click()
    const detail = row.locator('xpath=following-sibling::tr[1]')
    const syslogRow = detail.locator('.metrics-table tbody tr', { hasText: 'syslog_iface_down' })
    const collapsedToggle = syslogRow.locator('button[aria-expanded]')

    await expect(collapsedToggle).toBeVisible()
    await expect(collapsedToggle).toHaveAttribute('aria-expanded', 'false')
    await expect(syslogRow).not.toContainText('xe-0/0/1')

    await collapsedToggle.click()
    await expect(syslogRow.locator('button[aria-expanded="true"]')).toHaveCount(1)
    await expect(syslogRow).toContainText('xe-0/0/1')
    await expect(syslogRow).toContainText('таблица раскрыта')

    const emptyTrapRow = detail.locator('.metrics-table tbody tr', { hasText: 'trap_link_down_empty' })
    await expect(emptyTrapRow).toContainText('Таблица пуста')
    await expect(emptyTrapRow.locator('button[aria-expanded]')).toHaveCount(0)

    const errorTrapRow = detail.locator('.metrics-table tbody tr', { hasText: 'trap_link_down_error' })
    await expect(errorTrapRow).toContainText('synthetic trap ingest error')
    await expect(errorTrapRow).not.toContainText('Таблица пуста')
  })

  test('фильтр "с ошибками" находит устройство (SNMP против TEST-NET-3 не отвечает)', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    await page.locator('.segmented button', { hasText: 'С ошибками' }).click()
    await expect(page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP })).toBeVisible()
  })

  test('включить/выключить устройство', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).first()
    const toggle = row.locator('.switch-labeled')
    await expect(toggle).toContainText('вкл')
    await toggle.click()
    await expect(toggle).toContainText('выкл')
    await expect(page.locator('.toast-stack')).toContainText('выключено')
    await toggle.click()
    await expect(toggle).toContainText('вкл')
  })

  test('синхронизация с профилем', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).first()
    // Icon-only (2026-08-29, direct user request — was icon+"Синхр." text); accessible
    // name now comes from the title, which says "Синхронизировать", not "Синхр.".
    await row.getByRole('button', { name: /Синхронизировать с профилем/ }).click()
    await expect(page.locator('.toast-stack')).toContainText('синхронизировано с профилем')
  })

  test('удаление устройства — отмена, затем подтверждение', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill(DEVICE_DELETE_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_DELETE_IP }).first()
    await expect(row).toBeVisible()

    await row.getByRole('button', { name: 'Удалить' }).click()
    await expect(page.getByRole('heading', { name: 'Подтверждение' })).toBeVisible()
    await page.getByRole('button', { name: 'Отмена' }).click()
    await expect(row).toBeVisible() // cancel didn't delete it

    await row.getByRole('button', { name: 'Удалить' }).click()
    await page.locator('.modal-footer').getByRole('button', { name: 'Удалить' }).click()
    await expect(page.locator('.toast-stack')).toContainText('удалено')
    await expect(page.locator('.data-table tbody tr', { hasText: DEVICE_DELETE_IP })).toHaveCount(0)
  })

  test('пагинация: контрол виден при непустом результате', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill('')
    await page.locator('.segmented button', { hasText: 'Все' }).click()
    await expect(page.locator('.pagination')).toBeVisible()
    await expect(page.locator('.pagination')).toContainText('Показаны')
  })

  test('фильтр по профилю', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill('')
    // `E2E_PROFILE_NAME` (`05`) matches every device unconditionally — every row should
    // still show it, so this proves the dropdown actually narrows the request, not that
    // it happens to match everything by coincidence.
    // `.first()` — the filter bar now also has the auto-refresh period `<select>` (task
    // #28), so a bare `.filter-bar select` matches two elements; the profile filter is
    // the first one in DOM order.
    const profileSelect = page.locator('.filter-bar select').first()
    await profileSelect.selectOption({ label: 'e2e-test-profile' })
    // Wait past the loading placeholder itself (also a real `<tr>`, so a plain "first row
    // visible" check can pass against *it*, not real data) before reading rows.
    await expect(page.locator('.data-table tbody')).not.toContainText('Загрузка')
    await expect(page.locator('.data-table tbody tr').first()).toBeVisible()
    const rows = await page.locator('.data-table tbody tr').allTextContents()
    expect(rows.length).toBeGreaterThan(0)
    for (const text of rows) expect(text).toContain('e2e-test-profile')
    await profileSelect.selectOption('')
  })

  test('фильтр по подсети (CIDR)', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill('')
    // Every seeded device this suite creates lives under 203.0.113.0/24 (TEST-NET-3,
    // `06-discovery.spec.ts`'s docs) — a narrower /30 inside it should still show our
    // known keeper, a sibling /24 outside it should show nothing.
    await page.locator('input[placeholder="Подсеть (CIDR)…"]').fill('203.0.113.0/24')
    await expect(page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP })).toBeVisible()

    await page.locator('input[placeholder="Подсеть (CIDR)…"]').fill('198.51.100.0/24')
    await expect(page.locator('.data-table tbody')).toContainText('Измените фильтры')
    await page.locator('input[placeholder="Подсеть (CIDR)…"]').fill('')
  })

  test('массовое включение показывает scope текущей выборки', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    await expect(page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP })).toBeVisible()
    await page.waitForTimeout(400)
    await page.getByRole('button', { name: 'Включить все' }).click()
    await expect(page.getByRole('heading', { name: 'Подтверждение' })).toBeVisible()
    await expect(page.locator('.modal-body')).toContainText(`текущую выборку (поиск «${DEVICE_KEEP_IP}»)`)
    await expect(page.locator('.modal-body')).toContainText('Затронуто устройств: 1')
    await page.getByRole('button', { name: 'Отмена' }).click()
  })

  test('клик по профилю открывает профиль устройства', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).first()
    await row.locator('.metric-name-btn', { hasText: E2E_PROFILE_NAME }).click()

    await expect(page.getByRole('heading', { name: `Редактировать профиль: ${E2E_PROFILE_NAME}` })).toBeVisible()
    // Direct user request 2026-08-28: unlike Alerts' own "правило: X →" link (which opens
    // the "Тревоги" tab — see 09-alerts.spec.ts), this one must land on "Основное".
    await expect(page.locator('.tabs button.active')).toContainText('Основное')
    await page.locator('.modal-header button[title="Закрыть"]').click()
  })

  test('клик по количеству активных тревог открывает тревоги устройства', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).first()
    // `06`'s discovery run creates a real активная alert for this device — see that
    // spec's "устройства и тревога появляются" test — so this column is non-zero by the
    // time `07` runs.
    await row.getByRole('button', { name: /^\d+$/ }).click()

    await expect(page.locator('.topbar__title')).toHaveText('Тревоги')
    await expect(page.locator('.filter-bar__row .input-icon input')).toHaveValue(DEVICE_KEEP_IP)
    await expect(page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).filter({ hasText: 'e2e-alert' })).toBeVisible()
  })

  test('история метрики открывается по клику на её имя', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).first()
    await row.locator('.expand-btn').click()
    const metricsTable = row.locator('xpath=following-sibling::tr[1]').locator('.metrics-table')
    await metricsTable.locator('.metric-name-btn', { hasText: 'dummy' }).click()

    await expect(page.getByRole('heading', { name: 'История метрики: dummy' })).toBeVisible()
    // `dummy` polls a real OID against an unreachable TEST-NET-3 host, so every recorded
    // run is an error — never a numeric success — which renders as the plain table
    // branch, not the SVG chart; either way, the modal must show *something* other than
    // a stuck "Загрузка…", proving the fetch actually completed.
    const modalBody = page.locator('.modal-body')
    await expect(modalBody).not.toContainText('Загрузка…')
    await page.locator('.modal-header button[title="Закрыть"]').click()
    await expect(page.getByRole('heading', { name: 'История метрики: dummy' })).toHaveCount(0)
  })

  test('история метрики — фильтр по периоду', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).first()
    await row.locator('.expand-btn').click()
    const metricsTable = row.locator('xpath=following-sibling::tr[1]').locator('.metrics-table')
    await metricsTable.locator('.metric-name-btn', { hasText: 'dummy' }).click()

    const modalBody = page.locator('.modal-body')
    await expect(modalBody).not.toContainText('Загрузка…')

    // Direct user request 2026-08-28: auto-refresh here is only meaningful while the
    // window includes "now" — enabled by default (both bounds blank).
    // Positional, not `select[title*=...]` — the only `<select>` in this scope, and a
    // title-substring attribute selector was flaky here in practice.
    const refreshSelect = modalBody.locator('select')
    await expect(refreshSelect).toBeEnabled()

    // A window that couldn't possibly contain any real run (year 2000) narrows to nothing
    // — also strictly in the past, so auto-refresh must disable itself.
    const dateInputs = page.locator('.modal-body input[type="datetime-local"]')
    await dateInputs.nth(0).fill('2000-01-01T00:00')
    await dateInputs.nth(1).fill('2000-01-02T00:00')
    await expect(modalBody).toContainText('За выбранный период записей нет.')
    await expect(refreshSelect).toBeDisabled()

    await page.getByRole('button', { name: /Сбросить период/ }).click()
    await expect(modalBody).not.toContainText('За выбранный период записей нет.')
    await expect(refreshSelect).toBeEnabled()
    await page.locator('.modal-header button[title="Закрыть"]').click()
  })

  test('ручное создание устройства — ip, профиль, начальная метрика', async ({ adminPage: page }) => {
    await page.getByRole('button', { name: 'Создать' }).click()
    await expect(page.getByRole('heading', { name: 'Создать устройство' })).toBeVisible()

    const modalBody = page.locator('.modal-body')
    await modalBody.locator('.field', { hasText: 'IP' }).locator('input').fill(DEVICE_MANUAL_CREATE_IP)
    await modalBody.locator('.field', { hasText: 'Профиль' }).locator('select').selectOption(E2E_PROFILE_NAME)
    await page.getByRole('button', { name: 'Добавить' }).click()
    const kvRow = modalBody.locator('.filter-bar__row').last()
    await kvRow.locator('input').nth(0).fill('area_name')
    await kvRow.locator('input').nth(1).fill('Воронеж')

    await page.locator('.modal-footer').getByRole('button', { name: 'Создать' }).click()
    await expect(page.locator('.toast-stack')).toContainText('создано')

    await page.locator('.input-icon input').fill(DEVICE_MANUAL_CREATE_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_MANUAL_CREATE_IP }).first()
    await expect(row).toBeVisible()
    await expect(row).toContainText(E2E_PROFILE_NAME)

    await row.locator('.expand-btn').click()
    const metricsTable = row.locator('xpath=following-sibling::tr[1]').locator('.metrics-table')
    await expect(metricsTable).toContainText('area_name')
    await expect(metricsTable).toContainText('Воронеж')
  })

  test('экспорт устройств в CSV/XLSX/JSON скачивает файл', async ({ adminPage: page }) => {
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    for (const [label, ext] of [
      ['CSV', 'csv'],
      ['XLSX', 'xlsx'],
      ['JSON', 'json'],
    ] as const) {
      await page.locator('.dropdown', { hasText: 'Экспорт' }).getByRole('button', { name: /Экспорт/ }).click()
      const [download] = await Promise.all([page.waitForEvent('download'), page.locator('.dropdown-menu button', { hasText: label }).click()])
      expect(download.suggestedFilename()).toBe(`devices.${ext}`)
    }
  })

  test('SSH-креды устройства — гейтинг формы (пароль/приватный ключ), запрос реально доходит до backend', async ({ adminPage: page }) => {
    // This isolated e2e stand has no DISCOVERY_SECRET_KEY configured (same constraint the
    // Notifications suite documents for webhook/email secrets) — and unlike
    // SnmpAuth::Community, SSH credentials have no plaintext-ok fallback (see
    // discovery_core::secret::encrypt_ssh_auth_secrets's docs: "these credentials require
    // DISCOVERY_SECRET_KEY to be configured"), so a real save can never succeed here.
    // What *is* provable without that env var: the modal's disabled-until-valid gating for
    // both auth kinds, and that clicking Save genuinely reaches the real backend and
    // surfaces its real, specific error — not a silent no-op, not a hang, not a generic
    // "something went wrong". Backend-side proof of the actual persisting round trip
    // (with a key configured) already exists —
    // put_ssh_credentials_with_a_secret_key_configured_round_trips_onto_an_existing_device
    // in crates/web/src/lib.rs — this test proves the UI wiring on top of that.
    await page.locator('.input-icon input').fill(DEVICE_KEEP_IP)
    const row = page.locator('.data-table tbody tr', { hasText: DEVICE_KEEP_IP }).first()
    await row.locator('button[title^="SSH-креды"]').click()

    await expect(page.getByRole('heading', { name: `SSH-креды: ${DEVICE_KEEP_IP}` })).toBeVisible()
    // CWE-295 fix (2026-09-17): this device has no `ssh_credentials` at all yet, so there
    // is nothing pinned — the modal must say so plainly rather than showing nothing/blank.
    await expect(page.locator('.modal', { hasText: 'Host key:' })).toContainText('не закреплён')
    const saveBtn = page.locator('.modal-footer').getByRole('button', { name: 'Сохранить' })
    // No username yet — save must be disabled, not just "nobody happened to click it".
    await expect(saveBtn).toBeDisabled()

    await fieldInput(page, 'Username').fill('e2e-ssh-user')
    await expect(saveBtn).toBeDisabled() // password auth (default) still needs a password
    // Not fieldInput('Пароль') — "Тип аутентификации" above is a <select> whose <option>
    // "пароль" is always in the DOM, so a plain substring/first-match on "Пароль" resolves
    // to that select, not the real password input. .last() is the actual field.
    await page.locator('.field', { hasText: 'Пароль' }).last().locator('input').fill('e2e-ssh-password')
    await expect(saveBtn).toBeEnabled()

    await saveBtn.click()
    await expect(page.locator('.toast-stack')).toContainText(/DISCOVERY_SECRET_KEY|internal server error \(correlation id:/)
    // A failed save must not silently close the modal — the error needs to stay next to
    // the form that produced it, not just flash by in a toast.
    await expect(page.getByRole('heading', { name: `SSH-креды: ${DEVICE_KEEP_IP}` })).toBeVisible()

    // --- Same gating for the private-key branch — different pair of fields, same
    // disabled-until-filled contract; passphrase is optional so isn't part of it. ---
    await fieldInput(page, 'Тип аутентификации').selectOption('private_key')
    await expect(saveBtn).toBeDisabled()
    // Same "select's own option text" trap as "Пароль" above ("приватный ключ" is also an
    // <option> of "Тип аутентификации") — .last() for the same reason.
    await page.locator('.field', { hasText: 'Приватный ключ' }).last().locator('textarea').fill('-----BEGIN OPENSSH PRIVATE KEY-----\ne2e-fake-key\n-----END OPENSSH PRIVATE KEY-----')
    await expect(saveBtn).toBeEnabled()

    // 2026-09-17 audit finding #7: every modal in the app shares this one `<Modal>` shell
    // (see its own docs) — before this fix, only an explicit click on «Закрыть»/the X
    // icon closed anything, Escape did nothing. Proven here rather than a dedicated test
    // specifically *because* this modal is already open with real unsaved input in it —
    // the more realistic case Escape needs to handle.
    await page.keyboard.press('Escape')
    await expect(page.getByRole('heading', { name: `SSH-креды: ${DEVICE_KEEP_IP}` })).toHaveCount(0)
  })
})
