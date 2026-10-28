/**
 * Spawns a real, isolated `discovery-agent` binary for the whole E2E run — same
 * isolated scratch config pattern the project's own live-testing documentation uses. The
 * config lives under a per-run temporary directory, so the E2E instance never reads the
 * repository config or touches `discovery_dev`; the bootstrap admin credentials are
 * generated in-process instead of read from logs.
 *
 * Binary must already be built (`cargo build -p discovery-agent`, or the whole
 * workspace) — this does not build it, to keep the E2E run itself fast and to avoid a
 * surprise multi-minute compile the first time someone runs `npm run test:e2e`.
 */
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = path.resolve(__dirname, '../../../..')
const BINARY = path.join(REPO_ROOT, 'target/debug/discovery-agent')
const AUTH_DIR = path.join(__dirname, '.auth')
const AUTH_FILE = path.join(AUTH_DIR, 'bootstrap.json')
const PID_FILE = path.join(AUTH_DIR, 'agent.pid')
const SCRATCH_DIR = path.join(os.tmpdir(), `discovery-e2e-${Date.now()}`)
const BOOTSTRAP_PASSWORD = process.env.DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD ?? `e2e-bootstrap-${randomBytes(24).toString('hex')}`
const E2E_PORT = process.env.E2E_PORT ?? '8088'

// A config in the per-run scratch directory keeps storage and the HTTP port isolated from
// the repository and from another E2E run. The setup below writes only the selected port;
// all other settings use the agent defaults.
const CONFIG_FILE = path.join(SCRATCH_DIR, 'e2e-config.toml')

const ANSI_RE = /\x1b\[[0-9;]*m/g

function safeOutput(output: string) {
  return output.replaceAll(BOOTSTRAP_PASSWORD, '[REDACTED]')
}

function removeRunArtifacts() {
  for (const file of [AUTH_FILE, PID_FILE, path.join(AUTH_DIR, 'scratch-dir.txt')]) {
    fs.rmSync(file, { force: true })
  }
  fs.rmSync(SCRATCH_DIR, { recursive: true, force: true })
}

export default async function globalSetup() {
  if (!fs.existsSync(BINARY)) {
    throw new Error(`discovery-agent binary not found at ${BINARY} — run "cargo build -p discovery-agent" (or the whole workspace) before the E2E suite.`)
  }

  removeRunArtifacts()
  fs.mkdirSync(AUTH_DIR, { recursive: true })
  fs.mkdirSync(SCRATCH_DIR, { recursive: true })
  fs.writeFileSync(
    CONFIG_FILE,
    `[server]\naddr = "127.0.0.1:${E2E_PORT}"\n\n[login_rate_limit]\nburst_capacity = 100\nrefill_per_sec = 100.0\n`,
  )
  fs.writeFileSync(path.join(AUTH_DIR, 'scratch-dir.txt'), SCRATCH_DIR)

  fs.appendFileSync(CONFIG_FILE, `\n[syslog]\nenabled = true\nbind_addr = "127.0.0.1:${Number(E2E_PORT) + 1}"\nallowed_sources = ["127.0.0.1"]\n`)

  const child = spawn(BINARY, [], {
    cwd: SCRATCH_DIR, // so the default `logs/discovery.log` file sink lands outside the repo
    env: { ...process.env, CONFIG_FILE, DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD: BOOTSTRAP_PASSWORD, RUST_LOG: 'info' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  fs.writeFileSync(PID_FILE, String(child.pid))

  let buffer = ''
  let listening = false

  try {
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`discovery-agent did not finish starting within 20s. Output so far:\n${safeOutput(buffer)}`))
      }, 20_000)

      function onData(chunk: Buffer) {
        buffer += chunk.toString('utf-8')
        const clean = buffer.replace(ANSI_RE, '')
        if (clean.includes('dashboard listening')) listening = true
        if (listening) {
          clearTimeout(timeout)
          resolve()
        }
      }

      child.stdout.on('data', onData)
      child.stderr.on('data', onData)
      child.on('exit', (code) => {
        clearTimeout(timeout)
        if (!listening) reject(new Error(`discovery-agent exited early (code ${code}) before startup completed. Output:\n${safeOutput(buffer)}`))
      })
      child.on('error', (err) => {
        clearTimeout(timeout)
        reject(err)
      })
    })

    // The bootstrap account is created with `must_change_password: true` (2026-08-26,
    // direct user request — the fixed `admin`/`admin` login must be forced through a real
  // change before it can do anything else, see `discovery-agent::main`'s docs). Every
  // other domain/admin route 403s until that happens (`require_domain_permission`/
  // `require_admin` in `crates/web/src/lib.rs`), which would break all 32 specs' shared
  // `adminPage` fixture if left as-is — so this does the one-time change here, via the
  // real API, and hands specs the already-changed password. `01-auth.spec.ts` is what
  // actually exercises the forced-change *UI* flow itself, against a throwaway account
  // created for that one test — this is just unblocking the shared session.
    const baseUrl = `http://127.0.0.1:${E2E_PORT}`
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: BOOTSTRAP_PASSWORD }),
    })
    if (!loginRes.ok) throw new Error(`global-setup: bootstrap login failed (${loginRes.status})`)
    const { token } = (await loginRes.json()) as { token: string }
    const realPassword = `e2e-real-admin-${randomBytes(24).toString('hex')}`
    const changeRes = await fetch(`${baseUrl}/api/auth/password`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ current_password: BOOTSTRAP_PASSWORD, new_password: realPassword }),
    })
    if (!changeRes.ok) throw new Error(`global-setup: forced password change failed (${changeRes.status})`)

    const verifyRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: realPassword }),
    })
    if (!verifyRes.ok) throw new Error(`global-setup: changed-password login failed (${verifyRes.status})`)

    fs.writeFileSync(AUTH_FILE, JSON.stringify({ username: 'admin', password: realPassword }, null, 2))
    // eslint-disable-next-line no-console
    console.log(`[global-setup] discovery-agent (pid ${child.pid}) up, bootstrap admin ready (password changed), scratch dir ${SCRATCH_DIR}`)
  } catch (error) {
    child.kill('SIGTERM')
    removeRunArtifacts()
    throw error
  }
}
