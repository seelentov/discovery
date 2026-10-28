import type { ReactNode } from 'react'

/** A labeled form field wrapper — `.field` provides the label + gap styling, the actual
 * control (input/select/textarea) is passed as children so this stays control-agnostic.
 *
 * `hint` (2026-08-29, direct user request: "убери лишние текстовые подсказки в статичном
 * тексте, они будут встроены в тултип") is a hover tooltip on the control itself, not
 * always-visible text next to the label the way it used to render — same "don't take up
 * space, surface on demand" reasoning every icon-only button's `title` already uses. */
export function Field({ label, hint, wide, children }: { label: string; hint?: string; wide?: boolean; children: ReactNode }) {
  return (
    <div className={wide ? 'field field-wide' : 'field'}>
      <label>{label}</label>
      <div className="field-control" title={hint}>
        {children}
      </div>
    </div>
  )
}
