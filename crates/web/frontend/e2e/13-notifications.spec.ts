import { test, expect, fieldInput, login } from './fixtures'

const RECIPIENT_USER = 'e2e-notify-recipient'
const RECIPIENT_PASSWORD = 'e2e-password-notify'
const RULE_NAME = 'e2e-notify-rule'
const RULE_RENAMED = 'e2e-notify-rule-renamed'
const WEBHOOK_URL = 'https://example.com/e2e-hook'
const WEBHOOK_URL_EDITED = 'https://example.com/e2e-hook-edited'
const EMAIL_TARGET = 'e2e@example.com'

test.describe('Уведомления', () => {
  test.beforeEach(async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Уведомления' }).click()
    await expect(page.locator('.topbar__title')).toHaveText('Уведомления')
  })

  test('Мои каналы — создание, редактирование, удаление', async ({ adminPage: page }) => {
    // Tab is the default, but assert it explicitly — this is the self-service surface
    // every logged-in user sees, not just admins.
    await expect(page.locator('.tabs button', { hasText: 'Мои каналы' })).toHaveClass(/active/)

    // --- Create a webhook channel ---
    await page.getByRole('button', { name: 'Добавить канал' }).click()
    await expect(page.getByRole('heading', { name: 'Новый канал' })).toBeVisible()
    await fieldInput(page, 'Тип канала').selectOption('webhook')
    await fieldInput(page, 'Webhook URL').fill(WEBHOOK_URL)
    // No secret filled in — this isolated e2e stand has no DISCOVERY_SECRET_KEY
    // configured, and a non-empty secret with no key is a deliberate loud failure (500),
    // same "no passthrough" contract SSH credentials already have — see
    // `encrypt_optional_secret`'s Rust docs. Covered directly by
    // `discovery-config-store`'s own `webhook_secret_requires_a_key_to_persist` test and
    // `discovery-web`'s `notification_provider_settings_secrets_require_a_key_configured_to_persist`,
    // not re-proven here.
    await page.getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText('добавлен')
    const webhookRow = page.locator('.data-table tbody tr', { hasText: WEBHOOK_URL })
    await expect(webhookRow).toBeVisible()
    await expect(webhookRow).toContainText('Webhook')
    await expect(webhookRow).toContainText('включён')

    // --- Create an email channel too ---
    await page.getByRole('button', { name: 'Добавить канал' }).click()
    await fieldInput(page, 'Тип канала').selectOption('email')
    await fieldInput(page, 'Email-адрес').fill(EMAIL_TARGET)
    await page.getByRole('button', { name: 'Сохранить' }).click()
    const emailRow = page.locator('.data-table tbody tr', { hasText: EMAIL_TARGET })
    await expect(emailRow).toBeVisible()
    await expect(emailRow).toContainText('Email')

    // --- Edit the webhook channel: change its URL and disable it ---
    await webhookRow.getByRole('button', { name: 'Редактировать' }).click()
    await expect(page.getByRole('heading', { name: 'Редактировать канал' })).toBeVisible()
    await fieldInput(page, 'Webhook URL').fill(WEBHOOK_URL_EDITED)
    await page.locator('.switch').click()
    await page.getByRole('button', { name: 'Сохранить' }).click()
    const editedRow = page.locator('.data-table tbody tr', { hasText: WEBHOOK_URL_EDITED })
    await expect(editedRow).toBeVisible()
    await expect(editedRow).toContainText('выключен')

    // --- Delete both ---
    await editedRow.getByRole('button', { name: 'Удалить' }).click()
    await page.locator('.modal-footer').getByRole('button', { name: 'Удалить' }).click()
    await expect(editedRow).toHaveCount(0)
    await emailRow.getByRole('button', { name: 'Удалить' }).click()
    await page.locator('.modal-footer').getByRole('button', { name: 'Удалить' }).click()
    await expect(emailRow).toHaveCount(0)
  })

  test('Матрица — создание правила с получателем, редактирование, удаление', async ({ adminPage: page }) => {
    // A throwaway recipient — created fresh in this spec (not reused from 03-users,
    // which deletes its own accounts at the end of its own tests).
    await page.locator('.nav-item', { hasText: 'Пользователи' }).click()
    await page.getByRole('button', { name: /Добавить пользователя/ }).click()
    await fieldInput(page, 'Имя пользователя').fill(RECIPIENT_USER)
    await fieldInput(page, 'Пароль').fill(RECIPIENT_PASSWORD)
    await page.getByRole('button', { name: 'Создать' }).click()
    await expect(page.locator('.data-table tbody tr', { hasText: RECIPIENT_USER })).toBeVisible()

    await page.locator('.nav-item', { hasText: 'Уведомления' }).click()
    await page.locator('.tabs button', { hasText: 'Матрица' }).click()

    await page.getByRole('button', { name: 'Создать правило' }).click()
    await expect(page.getByRole('heading', { name: 'Новое правило' })).toBeVisible()
    await fieldInput(page, 'Название').fill(RULE_NAME)
    await fieldInput(page, 'Минимальный уровень').selectOption('Critical')
    await fieldInput(page, 'Профили').fill('e2e-test-profile')
    await page.locator('.checkbox-row', { hasText: RECIPIENT_USER }).locator('input').check()
    await page.getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText('создано')

    const ruleRow = page.locator('.data-table tbody tr', { hasText: RULE_NAME })
    await expect(ruleRow).toBeVisible()
    await expect(ruleRow).toContainText('Критично+')
    await expect(ruleRow).toContainText('профилей: 1')
    await expect(ruleRow).toContainText(RECIPIENT_USER)

    // --- Edit: rename ---
    await ruleRow.getByRole('button', { name: 'Редактировать' }).click()
    await expect(page.getByRole('heading', { name: 'Редактировать правило' })).toBeVisible()
    await fieldInput(page, 'Название').fill(RULE_RENAMED)
    await page.getByRole('button', { name: 'Сохранить' }).click()
    const renamedRow = page.locator('.data-table tbody tr', { hasText: RULE_RENAMED })
    await expect(renamedRow).toBeVisible()

    // --- Empty-selector hint: a brand-new rule with no subnet/profile/device selected
    // must say it matches every device (the opposite default from Maintenance windows). ---
    await page.getByRole('button', { name: 'Создать правило' }).click()
    await expect(page.getByText(/сработает для всех устройств/)).toBeVisible()
    await page.getByRole('button', { name: 'Отмена' }).click()

    // --- Cleanup: delete the rule, then the throwaway recipient ---
    await renamedRow.getByRole('button', { name: 'Удалить' }).click()
    await page.locator('.modal-footer').getByRole('button', { name: 'Удалить' }).click()
    await expect(renamedRow).toHaveCount(0)

    await page.locator('.nav-item', { hasText: 'Пользователи' }).click()
    const recipientRow = page.locator('.data-table tbody tr', { hasText: RECIPIENT_USER })
    await recipientRow.getByRole('button', { name: 'Удалить' }).click()
    await page.locator('.modal-footer').getByRole('button', { name: 'Удалить' }).click()
    await expect(recipientRow).toHaveCount(0)
  })

  test('Провайдер — round trip (без секретов — стенд без DISCOVERY_SECRET_KEY)', async ({ adminPage: page }) => {
    await page.locator('.tabs button', { hasText: 'Провайдер' }).click()
    await fieldInput(page, 'SMTP-хост').fill('smtp.e2e-example.com')
    await fieldInput(page, 'SMTP-порт').fill('2525')
    await fieldInput(page, 'Адрес отправителя').fill('alerts@e2e-example.com')
    await page.locator('.form-actions').getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.toast-stack')).toContainText('сохранены')

    await page.locator('.nav-item', { hasText: 'Обзор' }).click()
    await page.locator('.nav-item', { hasText: 'Уведомления' }).click()
    await page.locator('.tabs button', { hasText: 'Провайдер' }).click()
    await expect(fieldInput(page, 'SMTP-хост')).toHaveValue('smtp.e2e-example.com')
    await expect(fieldInput(page, 'SMTP-порт')).toHaveValue('2525')
    await expect(fieldInput(page, 'Адрес отправителя')).toHaveValue('alerts@e2e-example.com')
  })

  test('право видно любому пользователю, не только админу (self-service)', async ({ browser }) => {
    const admin = await browser.newContext()
    const adminPage = await admin.newPage()
    await login(adminPage)
    await adminPage.locator('.nav-item', { hasText: 'Пользователи' }).click()
    await adminPage.getByRole('button', { name: /Добавить пользователя/ }).click()
    await fieldInput(adminPage, 'Имя пользователя').fill('e2e-notify-selfservice')
    await fieldInput(adminPage, 'Пароль').fill('e2e-password-self')
    await adminPage.getByRole('button', { name: 'Создать' }).click()
    await expect(adminPage.locator('.data-table tbody tr', { hasText: 'e2e-notify-selfservice' })).toBeVisible()
    await admin.close()

    const nonAdmin = await browser.newContext()
    const nonAdminPage = await nonAdmin.newPage()
    await login(nonAdminPage, { username: 'e2e-notify-selfservice', password: 'e2e-password-self' })
    await expect(nonAdminPage.locator('.nav-item', { hasText: 'Уведомления' })).toBeVisible()
    await nonAdminPage.locator('.nav-item', { hasText: 'Уведомления' }).click()
    await expect(nonAdminPage.locator('.tabs button', { hasText: 'Мои каналы' })).toHaveClass(/active/)
    // No domain grant at all — can manage own channels regardless.
    await nonAdminPage.getByRole('button', { name: 'Добавить канал' }).click()
    await fieldInput(nonAdminPage, 'Тип канала').selectOption('telegram')
    await fieldInput(nonAdminPage, 'Telegram chat_id').fill('987654321')
    await nonAdminPage.getByRole('button', { name: 'Сохранить' }).click()
    await expect(nonAdminPage.locator('.data-table tbody tr', { hasText: '987654321' })).toBeVisible()
    await nonAdmin.close()

    // Cleanup via a fresh admin context.
    const cleanup = await browser.newContext()
    const cleanupPage = await cleanup.newPage()
    await login(cleanupPage)
    await cleanupPage.locator('.nav-item', { hasText: 'Пользователи' }).click()
    const row = cleanupPage.locator('.data-table tbody tr', { hasText: 'e2e-notify-selfservice' })
    await row.getByRole('button', { name: 'Удалить' }).click()
    await cleanupPage.locator('.modal-footer').getByRole('button', { name: 'Удалить' }).click()
    await expect(row).toHaveCount(0)
    await cleanup.close()
  })
})
