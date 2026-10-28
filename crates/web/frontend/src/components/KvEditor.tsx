import { Button } from './Button'
import { Field } from './Field'
import { Icon } from './Icon'

/** A repeater for editing a `Record<string, string>`-shaped field as a list of key/value
 * rows — originally local to `DiscoveryPage` (subnet `oids`/`labels`), extracted
 * 2026-08-29 for reuse by `ProfilesPage`'s table-metric `columns` editor (column name →
 * SNMP subid) — same shape, same "name maps to a string" editing need, no reason to
 * duplicate the row-add/update/remove logic a second time. */
export function KvEditor({
  label,
  hint,
  keyPlaceholder,
  valuePlaceholder,
  entries,
  onChange,
}: {
  label: string
  hint: string
  keyPlaceholder: string
  valuePlaceholder: string
  entries: [string, string][]
  onChange: (entries: [string, string][]) => void
}) {
  function update(idx: number, key: string, value: string) {
    const next = entries.slice()
    next[idx] = [key, value]
    onChange(next)
  }
  function remove(idx: number) {
    onChange(entries.filter((_, i) => i !== idx))
  }
  function add() {
    onChange([...entries, ['', '']])
  }
  return (
    <div style={{ marginTop: '.75rem' }}>
      <Field label={label} hint={hint}>
        <div className="util-col gap-2">
          {entries.map(([k, v], idx) => (
            <div className="filter-bar__row" key={idx}>
              <input className="input" placeholder={keyPlaceholder} value={k} onChange={(e) => update(idx, e.target.value, v)} />
              <input className="input mono" placeholder={valuePlaceholder} value={v} onChange={(e) => update(idx, k, e.target.value)} />
              <Button variant="ghost" iconOnly small title="Удалить" onClick={() => remove(idx)}>
                <Icon name="x" />
              </Button>
            </div>
          ))}
          <Button variant="ghost" small title={`Добавить ещё одну пару для «${label}»`} onClick={add} style={{ alignSelf: 'flex-start' }}>
            <Icon name="plus" />
            Добавить
          </Button>
        </div>
      </Field>
    </div>
  )
}
