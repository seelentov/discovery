import { Icon, type IconName } from './Icon'

function EmptyStateInner({ icon, text }: { icon: IconName; text: string }) {
  return (
    <div className="empty-state">
      <Icon name={icon} />
      <strong>Ничего не найдено</strong>
      <span>{text}</span>
    </div>
  )
}

/** For a `<tbody>` — renders as a single row spanning every column. */
export function EmptyStateRow({ colSpan, icon, text }: { colSpan: number; icon: IconName; text: string }) {
  return (
    <tr>
      <td colSpan={colSpan}>
        <EmptyStateInner icon={icon} text={text} />
      </td>
    </tr>
  )
}

/** For a card grid or any non-table container. */
export function EmptyStateBlock({ icon, text }: { icon: IconName; text: string }) {
  return <EmptyStateInner icon={icon} text={text} />
}
