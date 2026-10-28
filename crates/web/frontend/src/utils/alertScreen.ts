import type { Alert } from '../api/types'

export function screenNoticeVisible(alert: Alert, now: number, dismissed: ReadonlySet<string>): boolean {
  const policy = alert.details?.policy
  if (!policy?.screen_notification || alert.acknowledged_at || alert.flapping || alert.suppressed_by_alert_id) return false
  if (alert.snoozed_until && Date.parse(alert.snoozed_until) > now) return false
  if (policy.acknowledge_required) return true
  if (alert.state !== 'Active' || dismissed.has(alert.id)) return false
  return !policy.notification_lifetime_seconds || now - Date.parse(alert.first_seen) < policy.notification_lifetime_seconds * 1000
}
