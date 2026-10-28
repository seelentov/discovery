import { test, expect, fieldInput } from './fixtures'

/**
 * The AI assistant chat itself is self-service — any logged-in user, no domain gate (see
 * `docs/Architecture/AI Assistant.md`) — so the `adminPage` fixture exercises that path
 * fine (admin is also just "a logged-in user" here); a separate non-admin account would
 * only add value for proving the *absence* of an accidental admin-gate, which isn't worth
 * the extra user-management setup in this suite. The provider settings tab genuinely is
 * admin-only, so it needs `adminPage` regardless.
 *
 * No real (or fake) `LlmProvider` is wired into the e2e backend — `POST .../messages`
 * always builds a real `GigaChatProvider` from whatever's configured in
 * `/api/settings/ai-assistant`, and this suite's isolated `discovery-agent` starts with
 * nothing configured there. So this spec proves the parts that don't need a real model
 * reply: navigation, conversation creation, the "provider not configured" 503 path, and
 * the settings round trip (including that the secret never comes back).
 */
test.describe('ИИ-ассистент', () => {
  test('нав-пункт «Ассистент» открывает страницу чата', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Ассистент' }).click()
    await expect(page.locator('.topbar__title')).toHaveText('Ассистент')
    await expect(page.locator('.assistant-layout')).toBeVisible()
  })

  test('можно создать чат; отправка сообщения без настроенного провайдера даёт понятную ошибку', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Ассистент' }).click()

    await page.getByRole('button', { name: 'Новый чат', exact: true }).click()
    await expect(page.locator('.assistant-conv-item.active')).toBeVisible()

    const input = page.locator('.assistant-input')
    await input.fill('Покажи активные тревоги')
    await page.getByRole('button', { name: 'Отправить' }).click()

    await expect(page.locator('.assistant-banner')).toContainText('не настроен')
  })

  test('admin: настройки провайдера — round trip (без секрета — стенд без DISCOVERY_SECRET_KEY)', async ({ adminPage: page }) => {
    // Audit finding 4 (2026-09-20) replaced separate Client ID/Client Secret fields with
    // one Authorization key (decoded+split client-side, see `SettingsPage.tsx`'s docs) --
    // there's no longer a way to set client_id without also setting client_secret, so a
    // "round trip without touching the secret path" now has to exercise a genuinely
    // different non-secret field: `client_scope` (audit finding 3), a plain select, never
    // encrypted. Same constraint `07-devices.spec.ts`/`13-notifications.spec.ts` document
    // otherwise: this isolated e2e stand has no `DISCOVERY_SECRET_KEY` configured, so an
    // actual Authorization key would correctly fail to save -- see the next test.
    await page.locator('.nav-item', { hasText: 'Настройки' }).click()
    await page.locator('.settings-nav button', { hasText: 'ИИ-ассистент' }).click()

    await fieldInput(page, 'Тариф (scope)').selectOption('GIGACHAT_API_B2B')
    await page.locator('.form-actions').getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/сохранен/i)

    // Persistence proof: leave and come back, same as 04-settings.spec.ts's round-trip
    // pattern (SPA navigation, not a full reload — SettingsPage refetches on every mount
    // either way). Authorization key is asserted blank too — trivially true here since
    // none was ever set, but it's also exactly what redact-on-read looks like from the UI.
    await page.locator('.nav-item', { hasText: 'Обзор' }).click()
    await page.locator('.nav-item', { hasText: 'Настройки' }).click()
    await page.locator('.settings-nav button', { hasText: 'ИИ-ассистент' }).click()

    await expect(fieldInput(page, 'Тариф (scope)')).toHaveValue('GIGACHAT_API_B2B')
    await expect(fieldInput(page, 'Authorization key')).toHaveValue('')

    // restore the default tariff — this suite shares one backend/state test-by-test.
    await fieldInput(page, 'Тариф (scope)').selectOption('GIGACHAT_API_PERS')
    await page.locator('.form-actions').getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/сохранен/i)
  })

  test('admin: переключение провайдера на OpenRouter показывает свои поля и сохраняет модель (round trip)', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Настройки' }).click()
    await page.locator('.settings-nav button', { hasText: 'ИИ-ассистент' }).click()

    await fieldInput(page, 'Провайдер').selectOption('openrouter')
    await expect(fieldInput(page, 'Authorization key')).toHaveCount(0)
    await fieldInput(page, 'Model').fill('openai/gpt-4o-mini')
    await page.locator('.form-actions').getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/сохранен/i)

    await page.locator('.nav-item', { hasText: 'Обзор' }).click()
    await page.locator('.nav-item', { hasText: 'Настройки' }).click()
    await page.locator('.settings-nav button', { hasText: 'ИИ-ассистент' }).click()

    await expect(fieldInput(page, 'Провайдер')).toHaveValue('openrouter')
    await expect(fieldInput(page, 'Model')).toHaveValue('openai/gpt-4o-mini')
    await expect(fieldInput(page, 'API Key')).toHaveValue('')

    // Switch back to gigachat and save — this suite shares one backend/state
    // test-by-test (see this file's own docs), and the next test below needs the
    // GigaChat fields visible again.
    await fieldInput(page, 'Провайдер').selectOption('gigachat')
    await page.locator('.form-actions').getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/сохранен/i)
  })

  test('admin: переключение провайдера на self-hosted показывает свои поля и сохраняет base URL/модель (round trip)', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Настройки' }).click()
    await page.locator('.settings-nav button', { hasText: 'ИИ-ассистент' }).click()

    await fieldInput(page, 'Провайдер').selectOption('self_hosted')
    await expect(fieldInput(page, 'Authorization key')).toHaveCount(0)
    await fieldInput(page, 'Base URL').fill('http://localhost:11434/v1/chat/completions')
    await fieldInput(page, 'Model').fill('llama3')
    await page.locator('.form-actions').getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/сохранен/i)

    await page.locator('.nav-item', { hasText: 'Обзор' }).click()
    await page.locator('.nav-item', { hasText: 'Настройки' }).click()
    await page.locator('.settings-nav button', { hasText: 'ИИ-ассистент' }).click()

    await expect(fieldInput(page, 'Провайдер')).toHaveValue('self_hosted')
    await expect(fieldInput(page, 'Base URL')).toHaveValue('http://localhost:11434/v1/chat/completions')
    await expect(fieldInput(page, 'Model')).toHaveValue('llama3')
    await expect(fieldInput(page, 'API Key')).toHaveValue('')

    // Switch back to gigachat and save — this suite shares one backend/state
    // test-by-test (see this file's own docs), and the next test below needs the
    // GigaChat fields visible again.
    await fieldInput(page, 'Провайдер').selectOption('gigachat')
    await page.locator('.form-actions').getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/сохранен/i)
  })

  test('admin: сохранение секрета без DISCOVERY_SECRET_KEY даёт понятную ошибку, не тихий сбой', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Настройки' }).click()
    await page.locator('.settings-nav button', { hasText: 'ИИ-ассистент' }).click()

    // A validly-formatted base64(client_id:client_secret) Authorization key (audit
    // finding 4) -- decodes fine client-side, so this actually reaches the backend's
    // encrypted-secret save path, same as a real Client Secret would have before.
    await fieldInput(page, 'Authorization key').fill(Buffer.from('test-client-id:test-client-secret').toString('base64'))
    await page.locator('.form-actions').getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText(/DISCOVERY_SECRET_KEY|internal server error \(correlation id:/)
  })

  /**
   * The bypass toggle itself (`auto_approve_writes`, 2026-09-18) — a plain REST-backed
   * round trip, same constraint as the rest of this file applies: no real/fake
   * `LlmProvider` is wired into this stand, so this only proves the toggle persists across
   * navigation, not that a bypassed write actually skips confirmation mid-conversation —
   * that behavior is covered by `discovery-web`'s Rust integration tests
   * (`assistant_auto_approve_writes_executes_immediately_without_confirmation`), which can
   * inject `FakeLlmProvider` and drive the real orchestration loop.
   */
  test('тумблер «без подтверждения» переживает переход между страницами', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Ассистент' }).click()
    await page.getByRole('button', { name: 'Новый чат', exact: true }).click()
    await expect(page.locator('.assistant-conv-item.active')).toBeVisible()

    const toggle = page.locator('.assistant-mode-row .switch-labeled')
    await expect(toggle).toContainText('с подтверждением')
    await expect(page.locator('.assistant-mode-row__warning')).toHaveCount(0)

    await toggle.click()
    await expect(toggle).toContainText('без подтверждения')
    await expect(page.locator('.assistant-mode-row__warning')).toBeVisible()

    await page.locator('.nav-item', { hasText: 'Обзор' }).click()
    await page.locator('.nav-item', { hasText: 'Ассистент' }).click()
    // Remounting the page resets `activeId` (local component state, not URL-backed) — no
    // conversation is auto-selected, so re-click the (only) one in the list.
    await page.locator('.assistant-conv-item').first().click()
    await expect(page.locator('.assistant-mode-row .switch-labeled')).toContainText('без подтверждения')

    await page.locator('.assistant-mode-row .switch-labeled').click()
    await expect(page.locator('.assistant-mode-row .switch-labeled')).toContainText('с подтверждением')
  })
})
