import { Icon, type IconName } from './Icon'

export type Severity = 'ok' | 'warning' | 'critical' | 'info' | 'neutral'

const SEVERITY_ICON: Record<Severity, IconName> = {
  ok: 'check-circle',
  warning: 'triangle',
  critical: 'x-circle',
  info: 'dot',
  neutral: 'dot',
}

const SEVERITY_LABEL: Record<Severity, string> = {
  ok: 'ок',
  warning: 'warning',
  critical: 'critical',
  info: 'info',
  neutral: 'н/д',
}

/** A status pill — icon + label, never color alone (see global.css comment on
 * `.badge`/severity stripes). `label` overrides the default Russian text for `severity`. */
export function Badge({ severity, label }: { severity: Severity; label?: string }) {
  return (
    <span className={`badge badge-${severity}`}>
      <Icon name={SEVERITY_ICON[severity]} />
      {label ?? SEVERITY_LABEL[severity]}
    </span>
  )
}
