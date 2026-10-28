import { useState, type FormEvent } from 'react'
import { authApi } from '../api/auth'
import { ApiHttpError } from '../api/http'
import { Icon } from '../components/Icon'
import { useAuth } from '../hooks/useAuth'

/**
 * Blocking gate shown instead of the real dashboard whenever `user.must_change_password`
 * is set (see `App.tsx`'s `Root`) — no sidebar, no way to navigate around it. This is a
 * UX convenience, not the actual security boundary: the server independently rejects
 * every domain/admin-gated route for such an account regardless of what this page does
 * (see `require_domain_permission`/`require_admin` in `crates/web/src/lib.rs`) — so even
 * a user who somehow bypassed this screen (or hit the API directly) couldn't do anything
 * else until the password is actually changed.
 *
 * Exists specifically for the fixed `admin`/`admin` first-run bootstrap login (direct
 * user request 2026-08-26) — a real end customer needs a known, documentable login on
 * day one, and this is what makes handing one out safe instead of a standing default.
 */
export function ChangePasswordPage() {
  const { logout, refreshUser } = useAuth()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (newPassword !== confirmPassword) {
      setError('Новый пароль и подтверждение не совпадают')
      return
    }
    if (newPassword === currentPassword) {
      setError('Новый пароль должен отличаться от текущего')
      return
    }
    setSubmitting(true)
    try {
      await authApi.changePassword({ current_password: currentPassword, new_password: newPassword })
      await refreshUser() // clears must_change_password on this same session — no re-login needed
    } catch (e) {
      setError(e instanceof ApiHttpError ? e.message : 'Не удалось сменить пароль')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="login-screen">
      <div className="login-radar">
        <svg viewBox="0 0 400 400">
          <g fill="none" stroke="var(--accent)" strokeWidth={1}>
            <circle cx={200} cy={200} r={60} opacity={0.5} />
            <circle cx={200} cy={200} r={120} opacity={0.3} />
            <circle cx={200} cy={200} r={180} opacity={0.15} />
          </g>
        </svg>
      </div>
      <div className="login-card">
        <div className="login-brand">
          <Icon name="lock" className="brand-icon" />
          <div className="wordmark">Смена пароля</div>
          <div className="tagline">Обязательна перед первым входом</div>
        </div>
        <p className="stamp" style={{ maxWidth: 'none', marginBottom: '.6rem' }}>
          Учётная запись создана с паролем по умолчанию — прежде чем продолжить, задайте собственный пароль.
        </p>
        <form className="login-form" onSubmit={handleSubmit}>
          <div className="field">
            <label>Текущий пароль</label>
            <input
              className="input"
              type="password"
              autoComplete="current-password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
            />
          </div>
          <div className="field">
            <label>Новый пароль</label>
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              minLength={4}
            />
          </div>
          <div className="field">
            <label>Повторите новый пароль</label>
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              minLength={4}
            />
          </div>
          {error && (
            <p className="stamp" style={{ maxWidth: 'none', color: 'var(--status-critical)' }}>
              {error}
            </p>
          )}
          <button className="btn btn-primary" style={{ height: '2.4rem', marginTop: '.4rem' }} disabled={submitting}>
            {submitting ? 'Сохраняем…' : 'Сменить пароль'}
          </button>
          <button type="button" className="btn btn-ghost" style={{ height: '2.2rem' }} onClick={() => logout()}>
            Выйти
          </button>
        </form>
      </div>
    </div>
  )
}
