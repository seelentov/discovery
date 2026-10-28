import { test, expect } from './fixtures'

test.describe('Мобильная навигация', () => {
  test.use({ viewport: { width: 390, height: 844 } })

  test('открывает все разрешённые пункты, закрывается по Escape и клику вне меню', async ({ adminPage: page }) => {
    const menuButton = page.getByRole('button', { name: 'Открыть меню' })
    const sidebar = page.locator('.sidebar')

    await expect(menuButton).toBeVisible()
    await menuButton.click()
    await expect(sidebar).toBeVisible()
    await expect(sidebar.locator('.nav-item')).toHaveCount(15)
    await expect(sidebar.locator('.sidebar__search-btn')).toBeVisible()
    await expect(sidebar.locator('button[title="Выйти"]')).toBeVisible()

    await page.keyboard.press('Escape')
    await expect(sidebar).not.toHaveClass(/open/)

    await menuButton.click()
    await page.locator('.sidebar-backdrop').click({ position: { x: 380, y: 400 } })
    await expect(sidebar).not.toHaveClass(/open/)

    await menuButton.click()
    await sidebar.locator('.sidebar__search-btn').click()
    await expect(page.locator('.command-palette')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.locator('.command-palette')).toHaveCount(0)
  })
})
