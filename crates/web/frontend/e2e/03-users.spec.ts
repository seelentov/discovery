import { test, expect, fieldInput, login } from './fixtures'

const NEW_USER = 'e2e-nonadmin'
const NEW_PASSWORD = 'e2e-password-123'

const ROLE_NAME = 'e2e-role'

test.describe('Пользователи', () => {
  test('создание, роли, смена пароля, toggle admin, удаление', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Пользователи' }).click()

    // Own bootstrap admin row is present with no role (is_admin bypasses per-domain
    // permissions entirely — see `UserView`'s docs).
    await expect(page.locator('.data-table tbody tr', { hasText: 'admin' })).toBeVisible()

    // --- Create a role first, so it's assignable below ---
    // Scoped to `.tabs` — the sidebar's own nav button has the same accessible name.
    await page.locator('.tabs button', { hasText: /^Роли/ }).click()
    await page.getByRole('button', { name: /Добавить роль/ }).click()
    await expect(page.getByRole('heading', { name: 'Новая роль' })).toBeVisible()
    await fieldInput(page, 'Имя роли').fill(ROLE_NAME)
    const roleDevicesRow = page.locator('.perm-table__row', { hasText: 'Устройства' })
    await roleDevicesRow.locator('select').selectOption('write')
    await page.getByRole('button', { name: 'Сохранить' }).click()
    await expect(page.locator('.grid-cards .card', { hasText: ROLE_NAME })).toBeVisible()

    // --- Create the user ---
    await page.locator('.tabs button', { hasText: 'Пользователи' }).click()
    await page.getByRole('button', { name: /Добавить пользователя/ }).click()
    await expect(page.getByRole('heading', { name: 'Новый пользователь' })).toBeVisible()
    await fieldInput(page, 'Имя пользователя').fill(NEW_USER)
    await fieldInput(page, 'Пароль').fill(NEW_PASSWORD)
    await page.getByRole('button', { name: 'Создать' }).click()
    const row = page.locator('.data-table tbody tr', { hasText: NEW_USER })
    await expect(row).toBeVisible()
    const adminCell = row.locator('td').nth(1) // Имя | Админ | Роль | Создан | Действия
    await expect(adminCell).toHaveText('нет')

    // --- Assign the role ---
    // Icon-only buttons (direct user request 2026-08-28 — no visible text label, see
    // `Button`'s `iconOnly`) resolve their accessible name from `title`, not on-screen
    // text — these locators match the actual `title` strings, not the old button labels.
    await row.getByRole('button', { name: 'Назначить роль' }).click()
    await expect(page.getByRole('heading', { name: `Роль пользователя: ${NEW_USER}` })).toBeVisible()
    await page.locator('.modal-body select').selectOption({ label: ROLE_NAME })
    await page.getByRole('button', { name: 'Сохранить' }).click()
    await expect(row.locator('.perm-tag')).toHaveText(ROLE_NAME)

    // --- Reset password (native window.prompt) ---
    page.once('dialog', (dialog) => dialog.accept('another-new-password'))
    await row.getByRole('button', { name: 'Сбросить пароль' }).click()

    // --- Toggle admin on, then back off ---
    await row.getByRole('button', { name: 'Сделать администратором' }).click()
    await expect(adminCell).toHaveText('да')
    await row.getByRole('button', { name: 'Снять администратора' }).click()
    await expect(adminCell).toHaveText('нет')

    // --- Delete (app's own confirm Modal, not a native window.confirm) ---
    await row.getByRole('button', { name: 'Удалить' }).click()
    await expect(page.getByRole('heading', { name: 'Подтверждение' })).toBeVisible()
    await page.locator('.modal-footer').getByRole('button', { name: 'Удалить' }).click()
    await expect(row).toHaveCount(0)
  })

  test('редактирование роли и удаление роли с предупреждением о пользователях', async ({ adminPage: page }) => {
    await page.locator('.nav-item', { hasText: 'Пользователи' }).click()
    await page.locator('.tabs button', { hasText: /^Роли/ }).click()

    // --- Create a fresh role for this test (the previous test's own role/user were
    // both cleaned up already) ---
    const roleName = 'e2e-role-edit'
    await page.getByRole('button', { name: /Добавить роль/ }).click()
    await fieldInput(page, 'Имя роли').fill(roleName)
    // Not `.perm-table__row', { hasText: 'Тревоги' }` — a plain substring match also
    // resolves the "Групповые тревоги" domain's row (pre-existing footgun, unrelated to
    // this session's audit fixes, surfaced by a real run: strict-mode violation). The
    // guillemet-wrapped `title` text is unambiguous between the two.
    await page.locator('select[title*="«Тревоги»"]').selectOption('read')
    await page.getByRole('button', { name: 'Сохранить' }).click()
    const card = page.locator('.grid-cards .card', { hasText: roleName })
    await expect(card).toBeVisible()
    await expect(card).toContainText('пользователей: 0')
    await expect(card).toContainText('Тревоги: чтение')

    // --- Edit: rename + full-replace the permission set (Devices:write instead of
    // Alerts:read — the old grant must be gone, not merged, matching `update_role`'s
    // real contract). ---
    const renamedRoleName = 'e2e-role-edited'
    await card.getByRole('button', { name: 'Изменить' }).click()
    await expect(page.getByRole('heading', { name: `Редактировать роль: ${roleName}` })).toBeVisible()
    await fieldInput(page, 'Имя роли').fill(renamedRoleName)
    await page.locator('select[title*="«Тревоги»"]').selectOption('')
    await page.locator('.perm-table__row', { hasText: 'Устройства' }).locator('select').selectOption('write')
    await page.getByRole('button', { name: 'Сохранить' }).click()
    const renamedCard = page.locator('.grid-cards .card', { hasText: renamedRoleName })
    await expect(renamedCard).toBeVisible()
    await expect(renamedCard).toContainText('Устройства: запись')
    await expect(renamedCard).not.toContainText('Тревоги')

    // --- Assign it to a throwaway user, then delete the role and confirm the warning
    // mentions the member count, and that the user survives, unassigned. ---
    await page.locator('.tabs button', { hasText: 'Пользователи' }).click()
    await page.getByRole('button', { name: /Добавить пользователя/ }).click()
    await fieldInput(page, 'Имя пользователя').fill('e2e-role-member')
    await fieldInput(page, 'Пароль').fill('e2e-password-789')
    // Not `fieldInput(page, 'Роль')` — Playwright's `hasText` substring match is
    // case-insensitive, and "Пароль" (rendered earlier in the same modal) itself
    // contains "роль" as a substring, so that would grab the password field instead.
    await page.locator('.modal-body select').selectOption({ label: renamedRoleName })
    await page.getByRole('button', { name: 'Создать' }).click()
    const memberRow = page.locator('.data-table tbody tr', { hasText: 'e2e-role-member' })
    await expect(memberRow.locator('.perm-tag')).toHaveText(renamedRoleName)

    await page.locator('.tabs button', { hasText: /^Роли/ }).click()
    await expect(renamedCard).toContainText('пользователей: 1')
    await renamedCard.getByRole('button', { name: 'Удалить' }).click()
    await expect(page.getByText(/У неё сейчас 1 пользователь\(ей\)/)).toBeVisible()
    await page.locator('.modal-footer').getByRole('button', { name: 'Удалить' }).click()
    await expect(renamedCard).toHaveCount(0)

    await page.locator('.tabs button', { hasText: 'Пользователи' }).click()
    await expect(memberRow).toContainText('без роли')

    // --- Cleanup ---
    await memberRow.getByRole('button', { name: 'Удалить' }).click()
    await page.locator('.modal-footer').getByRole('button', { name: 'Удалить' }).click()
    await expect(memberRow).toHaveCount(0)
  })

  test('право "Пользователи" в сайдбаре скрыто для не-админа', async ({ browser }) => {
    // A throwaway non-admin account, separate from the one created/deleted above —
    // this test only needs it to exist for its own lifetime, in its own browser context
    // (so it doesn't disturb the shared `adminPage` session other specs still rely on).
    const admin = await browser.newContext()
    const adminPage = await admin.newPage()
    await login(adminPage)
    await adminPage.locator('.nav-item', { hasText: 'Пользователи' }).click()
    await adminPage.getByRole('button', { name: /Добавить пользователя/ }).click()
    await fieldInput(adminPage, 'Имя пользователя').fill('e2e-nav-check')
    await fieldInput(adminPage, 'Пароль').fill('e2e-password-456')
    await adminPage.getByRole('button', { name: 'Создать' }).click()
    await expect(adminPage.locator('.data-table tbody tr', { hasText: 'e2e-nav-check' })).toBeVisible()
    await admin.close()

    const nonAdmin = await browser.newContext()
    const nonAdminPage = await nonAdmin.newPage()
    await login(nonAdminPage, { username: 'e2e-nav-check', password: 'e2e-password-456' })
    await expect(nonAdminPage.locator('.nav-item', { hasText: 'Обзор' })).toBeVisible()
    await expect(nonAdminPage.locator('.nav-item', { hasText: 'Пользователи' })).toHaveCount(0)
    await nonAdmin.close()
  })
})
