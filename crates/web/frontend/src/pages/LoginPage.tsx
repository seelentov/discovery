import { useState, type FormEvent } from 'react'
import { Icon } from '../components/Icon'
import { useAuth } from '../hooks/useAuth'

export function LoginPage() {
  const { login, loginError } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    try {
      await login({ username, password })
    } catch {
      // loginError already carries the message; nothing else to do here.
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
          <Icon name="radar" className="brand-icon" />
          <div className="wordmark">Discovery</div>
          <div className="tagline">Система мониторинга сети</div>
        </div>
        <form className="login-form" onSubmit={handleSubmit}>
          <div className="field">
            <label>Логин</label>
            <input
              className="input"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
          <div className="field">
            <label>Пароль</label>
            <input
              className="input"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          {loginError && (
            <p className="stamp" style={{ maxWidth: 'none', color: 'var(--status-critical)' }}>
              {loginError}
            </p>
          )}
          <button className="btn btn-primary" style={{ height: '2.4rem', marginTop: '.4rem' }} disabled={submitting}>
            {submitting ? 'Входим…' : 'Войти'}
          </button>
        </form>
      </div>
    </div>
  )
}
