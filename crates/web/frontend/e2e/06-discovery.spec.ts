/**
 * Seeds real devices (and, via the profile from `05`, real alerts) for `07`/`08`/`09`
 * without any SNMP simulator: `create_dead_devices: true` on a subnet bypasses the ping
 * gate entirely (`DiscoveryHandler`), and `SnmpPollHandler` unconditionally hands a
 * candidate IP to `Dedup` regardless of whether real SNMP negotiation succeeded (a failed
 * OID fetch is recorded as an error metric, not a reason to skip the device) — so a
 * `TEST-NET-3` address (`203.0.113.0/24`, RFC 5737 — reserved for documentation, never
 * routable, safe to "discover" without hitting anything real) reliably produces a `Device`
 * row and, through `05`'s always-true profile/alert, a real `Alert` row too. Three
 * distinct single-host targets, kept alive for different later specs — see each inline
 * comment for which.
 */
import { test, expect, fieldInput } from './fixtures'
import { DEVICE_ALERT_DELETE_IP, DEVICE_DELETE_IP, DEVICE_KEEP_IP, DISCOVERY_CONFIG_NAME, E2E_PROFILE_NAME } from './shared'

async function addSubnet(page: import('@playwright/test').Page, ip: string) {
  await page.getByRole('button', { name: /^Подсеть$/ }).click()
  const blocks = page.locator('.card', { hasText: 'IP сети' })
  const block = blocks.last()
  await block.locator('input[placeholder="10.0.0.0"]').fill(ip)
  await block.locator('input[placeholder="255.255.255.0"]').fill('255.255.255.255')
  await block.locator('.checkbox-row', { hasText: 'Создавать устройства' }).locator('input').check()
}

async function getJson(page: import('@playwright/test').Page, path: string) {
  return page.evaluate(async (requestPath) => {
    const response = await fetch(requestPath)
    const text = await response.text()
    if (!response.ok) throw new Error(`GET ${requestPath} failed with ${response.status}: ${text}`)
    return JSON.parse(text) as { total: number }
  }, path)
}

test.describe('Дискаверинг', () => {
  test('создание конфига с тремя подсетями, запуск, устройства и тревога появляются', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Дискаверинг' }).click()

    await page.getByRole('button', { name: /Создать/ }).click()
    await expect(page.getByRole('heading', { name: 'Новая конфигурация дискаверинга' })).toBeVisible()
    await fieldInput(page, 'Имя конфигурации').fill(DISCOVERY_CONFIG_NAME)

    // Periodic mode is simpler to fill than calendar (no month/day/time parsing) and
    // doesn't matter for a manual "run now" anyway — the schedule itself is never
    // consulted by that path (`run_discovery_config_now` bypasses it deliberately).
    await fieldInput(page, 'Режим расписания').selectOption('periodic')
    await fieldInput(page, 'Период, сек').fill('3600')

    await addSubnet(page, DEVICE_KEEP_IP)
    await addSubnet(page, DEVICE_DELETE_IP)
    await addSubnet(page, DEVICE_ALERT_DELETE_IP)

    await page.getByRole('button', { name: 'Сохранить конфигурацию' }).click()
    const card = page.locator('.card', { hasText: DISCOVERY_CONFIG_NAME })
    await expect(card).toBeVisible()
    await expect(card).toContainText('подсетей: 3')

    await card.getByRole('button', { name: 'Запустить' }).click()
    await expect(card).toContainText(/поставлено в очередь: 3/)

    // Pipeline: Discovery -> SnmpPoll -> Dedup -> ProfileApply -> MetricPoll -> AlertEval,
    // all in-process queue workers, no manual polling interval to wait out for the first
    // tick — just real (if slow, since SNMP against a dead TEST-NET-3 host times out
    // before falling back) I/O. Polling the real API (not the UI) here for a tight,
    // reliable wait — the UI specs that actually exercise these rows are `07`/`08`/`09`.
    await expect
      .poll(
        async () => {
          const body = await getJson(page, '/api/devices?search=203.0.113')
          return body.total
        },
        { timeout: 30_000, message: 'expected all 3 seeded devices to appear via the pipeline' },
      )
      .toBe(3)

    await expect
      .poll(
        async () => {
          const body = await getJson(page, '/api/alerts?search=e2e-alert')
          return body.total
        },
        { timeout: 30_000, message: 'expected the e2e-alert profile rule to have fired for all 3 devices' },
      )
      .toBe(3)

    // Sanity: the profile from `05` really is what matched — its "sync devices" button
    // now has real work to report, closing the loop on that spec's "0 devices" assertion.
    await page.locator('.nav-item', { hasText: 'Профили' }).click()
    const profileCard = page.locator('.card', { hasText: E2E_PROFILE_NAME })
    await profileCard.getByRole('button', { name: /Синхр. устройства/ }).click()
    await expect(profileCard).toContainText('синхронизировано устройств: 3')
  })

  test('поиск читает подсети и название', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Дискаверинг' }).click()
    const searchInput = page.locator('.filter-bar__row .input-icon input')
    const card = page.locator('.card', { hasText: DISCOVERY_CONFIG_NAME })

    await searchInput.fill(DISCOVERY_CONFIG_NAME)
    await expect(card).toBeVisible()

    // Matches by a subnet's IP too, not just the config's own name — see
    // `list_discovery_configs`'s Rust docs.
    await searchInput.fill(DEVICE_KEEP_IP)
    await expect(card).toBeVisible()

    await searchInput.fill('no-such-config-or-subnet-anywhere')
    await expect(page.locator('.empty-state')).toContainText('Конфигураций не найдено')

    await searchInput.fill('')
    await expect(card).toBeVisible()
  })

  test('клонирование конфигурации дискаверинга', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Дискаверинг' }).click()
    // Exact match — the clone below is named `${DISCOVERY_CONFIG_NAME}-clone`, which a
    // plain substring `hasText` would also match once it exists.
    const sourceTitle = page.locator('.config-card__title', { hasText: new RegExp(`^${DISCOVERY_CONFIG_NAME}$`) })
    const sourceCard = sourceTitle.locator('xpath=ancestor::div[contains(@class,"card-pad")][1]')
    await sourceCard.getByRole('button', { name: /Клонировать/ }).click()

    await expect(page.getByRole('heading', { name: `Новая конфигурация (копия «${DISCOVERY_CONFIG_NAME}»)` })).toBeVisible()
    // Subnets carried over, name blank — not run here, so no need to defang the subnets
    // the way the profile-clone test does (discovery only fires on its own schedule or an
    // explicit "Запустить" click, neither of which this test does to the clone).
    await expect(fieldInput(page, 'Имя конфигурации')).toHaveValue('')
    // Deliberately does NOT contain `DISCOVERY_CONFIG_NAME` as a substring — same
    // "persists for the rest of the suite, other specs' substring locators would
    // otherwise match it too" reasoning as `05-profiles.spec.ts`'s own clone test.
    const cloneName = 'e2e-cloned-scan'
    await fieldInput(page, 'Имя конфигурации').fill(cloneName)
    await page.getByRole('button', { name: 'Сохранить конфигурацию' }).click()

    const cloneCard = page.locator('.card', { hasText: cloneName })
    await expect(cloneCard).toBeVisible()
    await expect(cloneCard).toContainText('подсетей: 3')
    await expect(sourceCard).toBeVisible()
  })

  test('экспорт/импорт подсетей дискаверинга', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Дискаверинг' }).click()
    const sourceTitle = page.locator('.config-card__title', { hasText: new RegExp(`^${DISCOVERY_CONFIG_NAME}$`) })
    const sourceCard = sourceTitle.locator('xpath=ancestor::div[contains(@class,"card-pad")][1]')
    await sourceCard.getByRole('button', { name: 'Изменить' }).click()

    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Экспорт' }).click()])
    const filePath = await download.path()
    expect(filePath).toBeTruthy()
    await page.locator('.modal-footer').getByRole('button', { name: 'Отмена' }).click()

    // Import into a brand-new (unsaved) config — proves this transfers between configs,
    // not just a no-op round trip back into the same one.
    await page.getByRole('button', { name: /Создать/ }).click()
    await expect(page.locator('input[placeholder="10.0.0.0"]')).toHaveCount(0)

    await page.setInputFiles('input[type="file"]', filePath!)
    await expect(page.locator('.toast-stack')).toContainText('Импортировано подсетей: 3')
    await expect(page.locator('input[placeholder="10.0.0.0"]')).toHaveCount(3)

    await page.locator('.modal-footer').getByRole('button', { name: 'Отмена' }).click()
  })

  // Audit finding 10 (2026-09-20): `DiscoveryOidsEditor` used to recompute `columnsMode`
  // from the raw `DiscoveryOidSpec` on every render -- indistinguishable from "auto" until
  // at least one column pair existed, so selecting "курируемые" reverted itself to
  // "собрать всё" before the KvEditor for typing column pairs ever appeared. Isolated to a
  // brand-new, never-saved config (cancelled at the end) so it doesn't depend on or
  // mutate the shared `e2e-scan` config's subnet state.
  test('доп. OID: выбор "курируемые" столбцы у табличного OID не откатывается сам собой', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Дискаверинг' }).click()
    await page.getByRole('button', { name: /Создать/ }).click()
    await expect(page.getByRole('heading', { name: 'Новая конфигурация дискаверинга' })).toBeVisible()

    await addSubnet(page, '203.0.113.201')
    await page.getByTitle('Добавить ещё один OID').click()

    // Not `fieldInput(page, 'Тип'/'Столбцы')` — both `<Field>`s nest *inside* the outer
    // "Доп. OID для обогащения" field, whose own aggregated text also contains "Тип"/
    // "Столбцы" as substrings, so `.first()` there resolves to the wrong (outer) element.
    // `getByTitle` targets each field's hint tooltip directly and unambiguously instead.
    await page.getByTitle(/скаляр — один OID/).getByRole('combobox').selectOption('table')
    const columnsMode = page.getByTitle(/курируемые — опрашивается/).getByRole('combobox')
    await columnsMode.selectOption('manual')
    await expect(columnsMode).toHaveValue('manual')
    // The concrete symptom: before the fix, this button never even appeared -- the select
    // had already reverted to 'auto' by the time of this assertion.
    await expect(page.getByTitle('Добавить ещё одну пару для «Столбцы таблицы»')).toBeVisible()

    await page.locator('.modal-footer').getByRole('button', { name: 'Отмена' }).click()
  })
})
