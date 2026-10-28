/**
 * Labeled toggle — round-8/round-11 design fixes made every on/off switch in the app
 * carry a visible "вкл"/"выкл" text next to it after users repeatedly mistook the bare
 * switch thumb for a decorative status dot. Always render through this component (not a
 * raw `.switch` span) so that discoverability fix can't quietly regress per-page.
 */
export function Switch({
  checked,
  onChange,
  title,
  label,
}: {
  checked: boolean
  onChange: (next: boolean) => void
  title: string
  /** Defaults to "вкл"/"выкл" — override for a different pair (e.g. custom copy is
   * rarely needed, but the enable-all-devices case in the mockup used verbs instead). */
  label?: [onLabel: string, offLabel: string]
}) {
  const [onLabel, offLabel] = label ?? ['вкл', 'выкл']
  return (
    <label className="switch-labeled" title={title}>
      <span className="switch">
        <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
        <span className="track" />
        <span className="thumb" />
      </span>
      <span className="switch-labeled__text">{checked ? onLabel : offLabel}</span>
    </label>
  )
}
