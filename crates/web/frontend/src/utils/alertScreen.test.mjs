import test from 'node:test'
import assert from 'node:assert/strict'
import { screenNoticeVisible } from './alertScreen.ts'
const now = Date.now()
const alert = (policy = {}, fields = {}) => ({ id: 'a', state: 'Active', first_seen: new Date(now - 1000).toISOString(), details: { policy: { screen_notification: true, ...policy } }, ...fields })
test('optional notices expire, dismiss and never show recovered incidents', () => {
  assert.equal(screenNoticeVisible(alert(), now, new Set()), true)
  assert.equal(screenNoticeVisible(alert(), now, new Set(['a'])), false)
  assert.equal(screenNoticeVisible(alert({ notification_lifetime_seconds: 1 }), now, new Set()), false)
  assert.equal(screenNoticeVisible(alert({}, { state: 'Cleared' }), now, new Set()), false)
})
test('required acknowledgment survives recovery, lifetime and dismissal', () => {
  const a = alert({ acknowledge_required: true, notification_lifetime_seconds: 1 }, { state: 'Cleared' })
  assert.equal(screenNoticeVisible(a, now, new Set(['a'])), true)
  assert.equal(screenNoticeVisible({ ...a, acknowledged_at: new Date(now).toISOString() }, now, new Set()), false)
})
test('snooze, flapping, correlation and opt-out suppress notices', () => {
  for (const fields of [{ flapping: true }, { suppressed_by_alert_id: 'root' }, { snoozed_until: new Date(now + 100).toISOString() }]) assert.equal(screenNoticeVisible(alert({ acknowledge_required: true }, fields), now, new Set()), false)
  assert.equal(screenNoticeVisible(alert({ screen_notification: false }), now, new Set()), false)
  assert.equal(screenNoticeVisible(alert({}, { snoozed_until: new Date(now).toISOString() }), now, new Set()), true)
})
