import { useCallback, useEffect, useState } from 'react'
import { rolesApi } from '../api/roles'
import { usersApi } from '../api/users'
import { ApiHttpError } from '../api/http'
import { DOMAIN_LABELS, DOMAINS, type Role, type UserListItem } from '../api/types'
import { Button } from '../components/Button'
import { EmptyStateBlock, EmptyStateRow } from '../components/EmptyState'
import { Field } from '../components/Field'
import { Icon } from '../components/Icon'
import { Modal } from '../components/Modal'
import { useConfirm } from '../hooks/useConfirm'
import { useToast } from '../hooks/useToast'

function fmtDate(iso: string): string {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}`
}

export function UsersPage() {
  const toast = useToast()
  const confirm = useConfirm()
  const [tab, setTab] = useState<'users' | 'roles'>('users')
  const [users, setUsers] = useState<UserListItem[] | null>(null)
  const [roles, setRoles] = useState<Role[] | null>(null)

  const [createOpen, setCreateOpen] = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newIsAdmin, setNewIsAdmin] = useState(false)
  const [newMustChangePassword, setNewMustChangePassword] = useState(false)
  const [newRoleId, setNewRoleId] = useState('')
  const [createError, setCreateError] = useState('')

  const [roleTarget, setRoleTarget] = useState<UserListItem | null>(null)
  const [roleDraft, setRoleDraft] = useState('')

  const [editingRole, setEditingRole] = useState<{ id: string | null; name: string; permissions: Record<string, string> } | null>(null)
  const [roleError, setRoleError] = useState('')

  const load = useCallback(async () => {
    try {
      const [u, r] = await Promise.all([usersApi.list(), rolesApi.list()])
      setUsers(u)
      setRoles(r)
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось загрузить пользователей', true)
    }
  }, [toast])

  useEffect(() => {
    load()
  }, [load])

  async function handleCreate() {
    setCreateError('')
    try {
      await usersApi.create({
        username: newUsername.trim(),
        password: newPassword,
        is_admin: newIsAdmin,
        must_change_password: newMustChangePassword,
        role_id: newRoleId || null,
      })
      setCreateOpen(false)
      setNewUsername('')
      setNewPassword('')
      setNewIsAdmin(false)
      setNewMustChangePassword(false)
      setNewRoleId('')
      toast(`Пользователь «${newUsername.trim()}» создан`)
      load()
    } catch (e) {
      setCreateError(e instanceof ApiHttpError ? e.message : 'Не удалось создать пользователя')
    }
  }

  async function handleDelete(u: UserListItem) {
    const ok = await confirm(`Удалить пользователя «${u.username}»? Действие необратимо.`, { label: 'Удалить', icon: 'trash' })
    if (!ok) return
    try {
      await usersApi.delete(u.id)
      toast('Пользователь удалён')
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось удалить пользователя', true)
    }
  }

  async function handleToggleAdmin(u: UserListItem) {
    try {
      await usersApi.setAdmin(u.id, !u.is_admin)
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось изменить права', true)
    }
  }

  async function handleResetPassword(u: UserListItem) {
    const password = window.prompt(`Новый пароль для «${u.username}»:`)
    if (!password) return
    try {
      await usersApi.setPassword(u.id, password)
      toast('Пароль изменён')
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось сменить пароль', true)
    }
  }

  function openRolePicker(u: UserListItem) {
    setRoleTarget(u)
    setRoleDraft(u.role_id ?? '')
  }

  async function saveRolePick() {
    if (!roleTarget) return
    try {
      await usersApi.setRole(roleTarget.id, roleDraft || null)
      setRoleTarget(null)
      toast('Роль обновлена')
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось назначить роль', true)
    }
  }

  function openCreateRole() {
    setRoleError('')
    setEditingRole({ id: null, name: '', permissions: {} })
  }

  function openEditRole(r: Role) {
    setRoleError('')
    setEditingRole({ id: r.id, name: r.name, permissions: { ...r.permissions } })
  }

  async function saveRole() {
    if (!editingRole) return
    setRoleError('')
    // "нет доступа" is stored as an empty string in the draft (so the <select> has a
    // value to show) — the backend only understands "read"/"write", so drop those
    // entries entirely before sending, same "absence = no access" convention every
    // other permission map in this app already uses.
    const permissions = Object.fromEntries(Object.entries(editingRole.permissions).filter(([, level]) => level))
    const body = { name: editingRole.name.trim(), permissions }
    try {
      if (editingRole.id) {
        await rolesApi.update(editingRole.id, body)
      } else {
        await rolesApi.create(body)
      }
      setEditingRole(null)
      toast(`Роль «${body.name}» сохранена`)
      load()
    } catch (e) {
      setRoleError(e instanceof ApiHttpError ? e.message : 'Не удалось сохранить роль')
    }
  }

  async function handleDeleteRole(r: Role) {
    const usersWithRole = (users ?? []).filter((u) => u.role_id === r.id).length
    const ok = await confirm(
      usersWithRole > 0
        ? `Удалить роль «${r.name}»? У неё сейчас ${usersWithRole} пользователь(ей) — они не будут удалены, но потеряют доступ по этой роли.`
        : `Удалить роль «${r.name}»?`,
      { label: 'Удалить', icon: 'trash' },
    )
    if (!ok) return
    try {
      await rolesApi.delete(r.id)
      toast('Роль удалена')
      load()
    } catch (e) {
      toast(e instanceof ApiHttpError ? e.message : 'Не удалось удалить роль', true)
    }
  }

  const userRows = users ?? []
  const roleRows = roles ?? []

  return (
    <div className="util-col gap-4">
      <p className="stamp">
        Локальные учётные записи. Права доступа (чтение/запись) по доменам назначаются через роли — пользователю просто выбирается роль, а не отдельные права. Внешние
        провайдеры (LDAP/Kerberos/OAuth) не реализованы.
      </p>

      <div className="tabs">
        <button className={tab === 'users' ? 'active' : ''} title="Учётные записи и их роли" onClick={() => setTab('users')}>
          Пользователи
        </button>
        <button className={tab === 'roles' ? 'active' : ''} title="Именованные наборы прав доступа по доменам" onClick={() => setTab('roles')}>
          Роли ({roleRows.length})
        </button>
      </div>

      {tab === 'users' && (
        <>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Имя</th>
                  <th>Админ</th>
                  <th>Роль</th>
                  <th>Создан</th>
                  <th>Действия</th>
                </tr>
              </thead>
              <tbody>
                {users === null ? (
                  <EmptyStateRow colSpan={5} icon="users" text="Загрузка…" />
                ) : userRows.length === 0 ? (
                  <EmptyStateRow colSpan={5} icon="users" text="Пользователей нет" />
                ) : (
                  userRows.map((u) => (
                    <tr key={u.id}>
                      <td>
                        {u.username}
                        {u.must_change_password && (
                          <span
                            className="badge badge-warning"
                            style={{ marginLeft: '.4rem' }}
                            title="Учётная запись ещё не сменила пароль по умолчанию/временный — при следующем входе будет предложено сменить"
                          >
                            <Icon name="lock" />
                            смена пароля
                          </span>
                        )}
                      </td>
                      <td>{u.is_admin ? <span className="badge badge-ok">да</span> : <span className="row-sub">нет</span>}</td>
                      <td>{u.role_name ? <span className="perm-tag">{u.role_name}</span> : <span className="row-sub">без роли</span>}</td>
                      <td className="row-sub">{fmtDate(u.created_at)}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <Button variant="ghost" iconOnly small title="Назначить роль" onClick={() => openRolePicker(u)}>
                          <Icon name="sliders" />
                        </Button>
                        <Button variant="ghost" iconOnly small title="Сбросить пароль" onClick={() => handleResetPassword(u)}>
                          <Icon name="key" />
                        </Button>
                        <Button variant="ghost" iconOnly small title={u.is_admin ? 'Снять администратора' : 'Сделать администратором'} onClick={() => handleToggleAdmin(u)}>
                          <Icon name={u.is_admin ? 'x-circle' : 'check-circle'} />
                        </Button>
                        <Button variant="ghost" iconOnly small title="Удалить" onClick={() => handleDelete(u)}>
                          <Icon name="trash" />
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="form-actions">
            <Button variant="primary" title="Создать новую учётную запись" onClick={() => setCreateOpen(true)}>
              <Icon name="plus" />
              Добавить пользователя
            </Button>
          </div>
        </>
      )}

      {tab === 'roles' && (
        <>
          {roles === null ? (
            <p className="stamp">Загрузка…</p>
          ) : roleRows.length === 0 ? (
            <EmptyStateBlock icon="sliders" text="Ролей нет — создайте первую, чтобы можно было выдавать доступ пользователям" />
          ) : (
            <div className="grid-cards">
              {roleRows.map((r) => {
                const memberCount = userRows.filter((u) => u.role_id === r.id).length
                const grantedDomains = DOMAINS.filter((d) => r.permissions[d])
                return (
                  <div className="card card-pad" key={r.id}>
                    <div className="config-card__title">{r.name}</div>
                    <div className="config-card__sub">
                      пользователей: {memberCount} · доменов с доступом: {grantedDomains.length}
                    </div>
                    <div className="wrap-row" style={{ marginTop: '.4rem' }}>
                      {grantedDomains.length === 0 ? (
                        <span className="row-sub">нет прав ни по одному домену</span>
                      ) : (
                        grantedDomains.map((d) => (
                          <span className="perm-tag" key={d}>
                            {DOMAIN_LABELS[d]}: {r.permissions[d] === 'write' ? 'запись' : 'чтение'}
                          </span>
                        ))
                      )}
                    </div>
                    <div className="config-card__actions">
                      <Button variant="ghost" iconOnly small title={`Изменить права роли «${r.name}»`} onClick={() => openEditRole(r)}>
                        <Icon name="pencil" />
                      </Button>
                      <Button variant="danger" iconOnly small title={`Удалить роль «${r.name}» — пользователи с этой ролью останутся без роли`} onClick={() => handleDeleteRole(r)}>
                        <Icon name="trash" />
                      </Button>
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          <div className="form-actions">
            <Button variant="primary" title="Создать новую роль с нуля" onClick={openCreateRole}>
              <Icon name="plus" />
              Добавить роль
            </Button>
          </div>
        </>
      )}

      <Modal
        open={createOpen}
        title="Новый пользователь"
        onClose={() => setCreateOpen(false)}
        footer={
          <>
            <Button variant="ghost" title="Закрыть без создания пользователя" onClick={() => setCreateOpen(false)}>
              Отмена
            </Button>
            <Button variant="primary" title="Создать пользователя с указанными данными" onClick={handleCreate}>
              Создать
            </Button>
          </>
        }
      >
        <div className="util-col gap-2">
          {createError && <div className="form-error">{createError}</div>}
          <Field label="Имя пользователя" hint="используется для входа, должно быть уникальным">
            <input className="input" value={newUsername} onChange={(e) => setNewUsername(e.target.value)} autoComplete="off" />
          </Field>
          <Field label="Пароль" hint="можно сменить позже кнопкой «Сбросить пароль»">
            <input className="input" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} autoComplete="new-password" />
          </Field>
          <Field label="Роль" hint="определяет доступ по доменам; можно назначить позже">
            <select className="select" value={newRoleId} onChange={(e) => setNewRoleId(e.target.value)}>
              <option value="">без роли</option>
              {roleRows.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
          </Field>
          <label className="checkbox-row" title="Администратор видит и может менять всё независимо от роли — назначенная роль в этом случае игнорируется">
            <input type="checkbox" checked={newIsAdmin} onChange={(e) => setNewIsAdmin(e.target.checked)} />
            Администратор (полный доступ, минуя роль)
          </label>
          <label className="checkbox-row" title="При следующем входе пользователь увидит блокирующий экран смены пароля вместо дашборда">
            <input type="checkbox" checked={newMustChangePassword} onChange={(e) => setNewMustChangePassword(e.target.checked)} />
            Потребовать смену пароля при первом входе
          </label>
        </div>
      </Modal>

      <Modal
        open={roleTarget !== null}
        title={`Роль пользователя: ${roleTarget?.username ?? ''}`}
        onClose={() => setRoleTarget(null)}
        footer={
          <>
            <Button variant="ghost" title="Закрыть без изменения роли" onClick={() => setRoleTarget(null)}>
              Отмена
            </Button>
            <Button variant="primary" title="Сохранить назначенную роль" onClick={saveRolePick}>
              Сохранить
            </Button>
          </>
        }
      >
        <Field label="Роль" hint="меняет доступ этого пользователя по доменам немедленно">
          <select className="select" value={roleDraft} onChange={(e) => setRoleDraft(e.target.value)}>
            <option value="">без роли (нет доступа по доменам)</option>
            {roleRows.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </select>
        </Field>
      </Modal>

      <Modal
        open={editingRole !== null}
        title={editingRole?.id ? `Редактировать роль: ${editingRole.name}` : 'Новая роль'}
        onClose={() => setEditingRole(null)}
        footer={
          <>
            <Button variant="ghost" title="Закрыть без сохранения изменений" onClick={() => setEditingRole(null)}>
              Отмена
            </Button>
            <Button variant="primary" title="Сохранить роль — изменения сразу действуют на всех пользователей с этой ролью" onClick={saveRole}>
              Сохранить
            </Button>
          </>
        }
      >
        {editingRole && (
          <div className="util-col gap-2">
            {roleError && <div className="form-error">{roleError}</div>}
            <Field label="Имя роли" hint="уникальное имя роли, отображается в списке пользователей">
              <input className="input" value={editingRole.name} onChange={(e) => setEditingRole({ ...editingRole, name: e.target.value })} autoComplete="off" />
            </Field>
            <div className="perm-table">
              <div className="perm-table__head">
                <span>Домен</span>
                <span>Доступ</span>
              </div>
              {DOMAINS.map((domain) => (
                <div className="perm-table__row" key={domain}>
                  <span>{DOMAIN_LABELS[domain]}</span>
                  <select
                    className="select"
                    title={`Доступ роли к домену «${DOMAIN_LABELS[domain]}»: нет доступа — раздел скрыт; чтение — только просмотр; запись — просмотр и изменение`}
                    value={editingRole.permissions[domain] ?? ''}
                    onChange={(e) =>
                      setEditingRole({
                        ...editingRole,
                        permissions: { ...editingRole.permissions, [domain]: e.target.value },
                      })
                    }
                  >
                    <option value="">нет доступа</option>
                    <option value="read">чтение</option>
                    <option value="write">запись</option>
                  </select>
                </div>
              ))}
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}
