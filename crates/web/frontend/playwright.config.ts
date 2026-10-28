import { defineConfig, devices } from '@playwright/test'

/**
 * Drives the real embedded production build (`GET /` on the actual `discovery-agent`
 * binary — same `dist/` a real deployment serves), not the Vite dev server. `npm run
 * build` must be run (and the Rust binary rebuilt) before this reflects frontend
 * changes — see `e2e/global-setup.ts`'s docs and `frontend/README.md`'s build order.
 *
 * `workers: 1` / `fullyParallel: false` is deliberate, not a leftover default: every
 * spec shares one live backend instance and several specs depend on state earlier specs
 * created through the UI (a profile + discovery config in `05`/`06` are what gives `07`
 * (Devices)/`08` (Queues)/`09` (Alerts) something real to click on) — numeric filename
 * prefixes fix the run order. This mirrors the project's own live-testing philosophy
 * (one shared instance, sequential concrete proof) rather than the fully-isolated-test
 * ideal, which would need per-test backend instances this suite doesn't attempt.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'e2e-report' }]],
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  use: {
    baseURL: `http://127.0.0.1:${process.env.E2E_PORT ?? '8088'}`,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
