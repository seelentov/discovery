import { Field } from './Field'
import { KvEditor } from './KvEditor'

/** Shared "is this OID a scalar or a table, and if a table, which columns" editing
 * widget — extracted 2026-08-29 so `ProfilesPage`'s metric editor and `DiscoveryPage`'s
 * subnet-OID editor use exactly the same UI/logic instead of two near-identical copies
 * (direct user request: "используй один код что в дискаверинг для оидов что для
 * профилей"). Mirrors the three-state `columns` encoding both `discovery_dsl::MetricSpec`
 * and `discovery_config_store::DiscoveryOidSpec` share on the Rust side: `kind: 'scalar'`
 * -> `columns` omitted entirely on save; `kind: 'table'` + `columnsMode: 'auto'` ->
 * `columns: {}`; `kind: 'table'` + `columnsMode: 'manual'` -> `columns: {name: subid, ...}`.
 *
 * Split into two components, not one, because callers place them in different layout
 * contexts: the type+OID fields are two more `<Field>`s inside an existing `.form-grid`
 * (`OidTypeAndValueFields` returns a `Fragment`, transparent to CSS Grid child placement),
 * while the columns editor is its own block below the grid (`TableColumnsFields`).
 */
export type OidKind = 'scalar' | 'table'
export type ColumnsMode = 'auto' | 'manual'

/** `onChange` always reports the *complete* next `{oid, kind}` pair, never a partial
 * patch with possibly-missing keys — deliberately, so the caller can always forward it
 * to its own state update unconditionally (`onChange({oid: next.oid, kind: next.kind})`)
 * without needing to know or guess which field this particular interaction touched. A
 * "partial patch, some keys may be `undefined`" design was tried here first and had a
 * real bug: naively spreading such a patch into existing state (`{...prev, ...patch}`)
 * overwrites the untouched field with `undefined`, because the key is still *present* in
 * the spread object even when its value isn't — object spread doesn't skip `undefined`
 * values. Always-complete values sidestep that trap entirely. */
export function OidTypeAndValueFields({
  oid,
  kind,
  onChange,
}: {
  oid: string
  kind: OidKind
  onChange: (next: { oid: string; kind: OidKind }) => void
}) {
  return (
    <>
      <Field label="Тип" hint="скаляр — один OID, одно значение; таблица — OID узла таблицы (entry), опрашивается по столбцам через SNMP walk">
        <select className="select" value={kind} onChange={(e) => onChange({ oid, kind: e.target.value as OidKind })}>
          <option value="scalar">скаляр</option>
          <option value="table">таблица</option>
        </select>
      </Field>
      <Field
        label={kind === 'table' ? 'OID таблицы (entry)' : 'OID'}
        hint={kind === 'table' ? 'OID узла таблицы (напр. ifEntry = 1.3.6.1.2.1.2.2.1) — столбцы задаются ниже как subid относительно него' : 'SNMP OID'}
      >
        <input className="input mono" value={oid} onChange={(e) => onChange({ oid: e.target.value, kind })} />
      </Field>
    </>
  )
}

/** Same "always the complete next value" contract as `OidTypeAndValueFields` above, and
 * for the same reason. */
export function TableColumnsFields({
  columnsMode,
  columns,
  onChange,
}: {
  columnsMode: ColumnsMode
  columns: [string, string][]
  onChange: (next: { columnsMode: ColumnsMode; columns: [string, string][] }) => void
}) {
  return (
    <div className="util-col gap-2" style={{ marginTop: '.5rem' }}>
      <Field label="Столбцы" hint="курируемые — опрашивается только заданный список столбцов (меньше трафика); собрать всё — один walk по всей таблице, столбцы называются по сырому SNMP subid (для разведки по незнакомой таблице)">
        <select className="select" value={columnsMode} onChange={(e) => onChange({ columnsMode: e.target.value as ColumnsMode, columns })}>
          <option value="manual">курируемые</option>
          <option value="auto">собрать всё</option>
        </select>
      </Field>
      {columnsMode === 'manual' && (
        <KvEditor
          label="Столбцы таблицы"
          hint="имя столбца → subid относительно OID таблицы (напр. ifDescr → 2 под ifEntry)"
          keyPlaceholder="имя столбца, напр. ifDescr"
          valuePlaceholder="subid, напр. 2"
          entries={columns}
          onChange={(entries) => onChange({ columnsMode, columns: entries })}
        />
      )}
    </div>
  )
}

/** `true` if a manual-columns table has nothing actually filled in — a dead-end config
 * (would poll and always produce an empty table, indistinguishable from "there just
 * happen to be zero rows right now"). Shared save-time validation for both pages'
 * OID/metric editors — same rule, same message, one place to get it right. */
export function validManualColumns(columns: [string, string][]): [string, string][] {
  return columns.map(([k, v]) => [k.trim(), v.trim()] as [string, string]).filter(([k, v]) => k && v)
}
