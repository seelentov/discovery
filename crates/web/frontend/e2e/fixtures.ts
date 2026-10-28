/**
 * Shared login helper + the bootstrap admin credentials `global-setup.ts` captured.
 *
 * Locators here deliberately avoid `getByLabel()` for text inputs: this app's `Field`
 * component (`src/components/Field.tsx`) renders `<label>{text}</label>{children}` as
 * *siblings*, not `<label>...<input/></label>` nesting or `htmlFor`/`id` pairing — so
 * there is no accessible-name association a screen reader (or Playwright's `getByLabel`)
 * could pick up. That's a real, worth-fixing accessibility gap (flagged separately, not
 * silently patched here to keep this E2E pass testing the app as it actually ships) —
 * `fieldInput()` below works around it the same way an external tester would have to:
 * scope to the `.field`/`.checkbox-row` container by its visible label text, then grab
 * the control inside it.
 *
 * **Gotcha found 2026-09-12 (Trap/Service Check/SSH/SSH-creds specs):** `fieldByLabel`'s
 * substring match runs against the *whole* container's text content, which includes a
 * `<select>`'s `<option>` text even when a different option is selected — a sibling
 * `<select>` field whose options happen to spell out a *later* field's label (e.g. "Тип
 * аутентификации" containing options "пароль"/"приватный ключ", right before real
 * "Пароль"/"Приватный ключ" fields) will match first and win under `.first()`. When a
 * label collides with another field's option text, use `page.locator('.field', {
 * hasText: label }).last()` instead of `fieldInput()` — the real field is reliably the
 * *last* match, not the first, as long as nothing after it also collides.
 */
import { test as base, expect, type Locator, type Page } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const AUTH_FILE = path.join(__dirname, '.auth', 'bootstrap.json')

export interface Credentials {
  username: string
  password: string
}

export function bootstrapCredentials(): Credentials {
  return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf-8'))
}

/** The `.field`/`.checkbox-row` wrapper whose visible label text contains `label` —
 * scope further with `.locator('input')` etc. Substring match on purpose (hints are
 * often appended after the label text in the same element). */
export function fieldByLabel(scope: Page | Locator, label: string): Locator {
  return scope.locator('.field, .checkbox-row', { hasText: label }).first()
}

export function fieldInput(scope: Page | Locator, label: string): Locator {
  return fieldByLabel(scope, label).locator('input, select, textarea')
}

export async function login(page: Page, creds: Credentials = bootstrapCredentials()) {
  await page.goto('/')
  await page.locator('input[autocomplete="username"]').fill(creds.username)
  await page.locator('input[autocomplete="current-password"]').fill(creds.password)
  await page.getByRole('button', { name: /Войти/ }).click()
  await expect(page.locator('.sidebar')).toBeVisible()
}

export const test = base.extend<{ adminPage: Page }>({
  adminPage: async ({ page }, use) => {
    await login(page)
    await use(page)
  },
})

export { expect }
