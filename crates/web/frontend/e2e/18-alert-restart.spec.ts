import { test, expect } from './fixtures'
import { request, type APIRequestContext } from '@playwright/test'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer } from 'node:net'
import { createSocket } from 'node:dgram'
import { DatabaseSync } from 'node:sqlite'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

async function port() {
  const server = createServer()
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const p = (server.address() as { port: number }).port
  await new Promise<void>(resolve => server.close(() => resolve()))
  return p
}
async function stop(child: ChildProcess) {
  if (child.exitCode !== null) return
  const exited = new Promise<void>(resolve => child.once('exit', () => resolve()))
  child.kill('SIGTERM')
  const timer = setTimeout(() => child.kill('SIGKILL'), 5000)
  await exited; clearTimeout(timer)
}

test('real process restart preserves activation, recovery, event window and previous value', async () => {
  test.setTimeout(90_000)
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'discovery-alert-restart-'))
  const httpPort = await port(), syslogPort = await port()
  const config = path.join(scratch, 'config.toml'), database = path.join(scratch, 'state.db')
  const binary = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../target/debug/discovery-agent')
  const password = 'restart-test-bootstrap-123', changed = 'restart-test-admin-456'
  fs.writeFileSync(config, `[server]\naddr = "127.0.0.1:${httpPort}"\n[storage]\ndefault_database = "persistent"\n[[storage.databases]]\nname = "persistent"\nkind = "sqlite"\nfile_path = "${database}"\n[syslog]\nenabled = true\nbind_addr = "127.0.0.1:${syslogPort}"\nallowed_sources = ["127.0.0.1"]\n`)
  let output = '', child: ChildProcess | undefined, client: APIRequestContext | undefined
  const start = async () => {
    child = spawn(binary, [], { cwd: scratch, env: { ...process.env, CONFIG_FILE: config, DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD: password }, stdio: ['ignore', 'pipe', 'pipe'] })
    child.stdout?.on('data', b => { output += b.toString() }); child.stderr?.on('data', b => { output += b.toString() })
    await expect.poll(async () => { try { return (await fetch(`http://127.0.0.1:${httpPort}/`)).status } catch { return 0 } }, { timeout: 20_000 }).toBe(200)
  }
  const send = async (status: string) => {
    const socket = createSocket('udp4')
    try { await new Promise<void>((resolve, reject) => socket.send(Buffer.from(`<30>Oct  3 12:00:00 router status=${status}`), syslogPort, '127.0.0.1', e => e ? reject(e) : resolve())) } finally { socket.close() }
  }
  const saved = (id: string) => {
    const db = new DatabaseSync(database, { readOnly: true })
    try { const row = db.prepare('SELECT snapshot FROM alert_runtime WHERE device_id = ? OR device_id = ?').get(id, Buffer.from(id.replaceAll('-', ''), 'hex')) as { snapshot: string } | undefined; return row ? JSON.parse(row.snapshot) : null } finally { db.close() }
  }
  try {
    await start()
    client = await request.newContext({ baseURL: `http://127.0.0.1:${httpPort}` })
    const login = await client.post('/api/auth/login', { data: { username: 'admin', password } }); expect(login.status()).toBe(200)
    const token = (await login.json()).token
    expect((await client.put('/api/auth/password', { headers: { Authorization: `Bearer ${token}` }, data: { current_password: password, new_password: changed } })).status()).toBe(204)
    const authenticated = await client.post('/api/auth/login', { data: { username: 'admin', password: changed } }); expect(authenticated.status()).toBe(200)
    const stableToken = (await authenticated.json()).token
    await client.dispose()
    client = await request.newContext({ baseURL: `http://127.0.0.1:${httpPort}`, extraHTTPHeaders: { Authorization: `Bearer ${stableToken}` } })
    const base = (name: string, expression: string, policy = {}) => ({ name, expression, level: 'warning', enabled: true, message: name, policy: { period_seconds: 1, ...policy } })
    const profile = { profile: { name: 'restart-alerts', priority: 0 }, match: { expression: 'false' }, metrics: { poll: {} }, syslog: { bindings: { link: { variants: [{ pattern: '^status=(?P<status>\\w+)$' }] } } }, alerts: [
      { ...base('restart-activation', 'true'), activate_after_seconds: 20 },
      { ...base('restart-recovery', 'metrics.syslog_link[0].status == "down"'), clear_after_seconds: 15 },
      base('restart-change', 'metrics.syslog_link[0].status', { mode: 'change' }),
      base('restart-events', 'true', { mode: 'event', event: { metric: 'syslog_link', count: 2, window_seconds: 60 } }),
    ] }
    expect((await client.post('/api/profiles', { data: profile })).status()).toBe(204)
    const creation = await client.post('/api/devices', { data: { ip: '127.0.0.1', profile: 'restart-alerts' } }); expect(creation.status()).toBe(200)
    const id = (await creation.json()).id
    await send('down')
    await expect.poll(() => Math.max(0, ...(saved(id)?.statuses.filter((s: { name: string }) => s.name === 'restart-events').map((s: { event_count: number }) => s.event_count) ?? [])), { timeout: 10_000 }).toBe(1)
    await expect.poll(async () => (await (await client!.get(`/api/alerts?device_id=${id}&search=restart-recovery`)).json()).items[0]?.state, { timeout: 10_000 }).toBe('Active')
    await expect.poll(() => saved(id)?.statuses.find((s: { name: string }) => s.name === 'restart-change')?.value, { timeout: 10_000 }).toBe('down')
    const activationSince = saved(id).states.find((s: { name: string }) => s.name === 'restart-activation').activation_since
    expect(activationSince).toBeTruthy()
    await stop(child!); await start()
    const statuses = (await (await client.get(`/api/devices/${id}/alert-rules`)).json())
    expect(statuses.find((s: { name: string }) => s.name === 'restart-activation').activation_since).toBe(activationSince)
    expect(statuses.find((s: { name: string }) => s.name === 'restart-change').value).toBe('down')
    await send('up')
    await expect.poll(async () => (await (await client!.get(`/api/alerts?device_id=${id}&search=restart-events`)).json()).total, { timeout: 10_000 }).toBe(1)
    await expect.poll(async () => (await (await client!.get(`/api/alerts?device_id=${id}&search=restart-change`)).json()).total, { timeout: 10_000 }).toBe(1)
    const change = (await (await client.get(`/api/alerts?device_id=${id}&search=restart-change`)).json()).items[0]
    expect(change.details.previous_value).toBe('down'); expect(change.details.observed_value).toBe('up')
    await expect.poll(() => saved(id)?.states.find((s: { name: string }) => s.name === 'restart-recovery')?.recovery_since, { timeout: 10_000 }).toBeTruthy()
    const recoverySince = saved(id).states.find((s: { name: string }) => s.name === 'restart-recovery').recovery_since
    await stop(child!); await start()
    expect((await (await client.get(`/api/devices/${id}/alert-rules`)).json()).find((s: { name: string }) => s.name === 'restart-recovery').recovery_since).toBe(recoverySince)
    await expect.poll(async () => (await (await client!.get(`/api/alerts?device_id=${id}&search=restart-recovery`)).json()).items[0]?.state, { timeout: 25_000 }).toBe('Cleared')
    await expect.poll(async () => (await (await client!.get(`/api/alerts?device_id=${id}&search=restart-activation`)).json()).total, { timeout: 15_000 }).toBe(1)
    expect((await (await client.get(`/api/alerts?device_id=${id}&search=restart-events`)).json()).total).toBe(1)
  } finally {
    if (child) await stop(child)
    await client?.dispose()
    fs.writeFileSync('/tmp/discovery-alert-capabilities-restart.log', output.replaceAll(password, '[REDACTED]').replaceAll(changed, '[REDACTED]'))
    fs.rmSync(scratch, { recursive: true, force: true })
  }
})
