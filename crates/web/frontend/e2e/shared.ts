/** Constants shared between spec files that depend on data an earlier spec seeded —
 * Playwright forbids importing one `*.spec.ts` from another, so this is the shared home
 * for them instead. See `06-discovery.spec.ts`'s docs for the full seeding story. */
export const E2E_PROFILE_NAME = 'e2e-test-profile'

export const DEVICE_KEEP_IP = '203.0.113.77' // 07 (devices) / 09 (alerts) general read/interaction tests
export const DEVICE_DELETE_IP = '203.0.113.88' // 07's delete-confirm flow target
export const DEVICE_ALERT_DELETE_IP = '203.0.113.99' // 09's alert-delete-confirm flow target
export const DEVICE_MANUAL_CREATE_IP = '203.0.113.150' // 07's manual device-creation test target
export const DISCOVERY_CONFIG_NAME = 'e2e-scan'
