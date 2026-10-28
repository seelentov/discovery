import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const AUTH_DIR = path.join(__dirname, '.auth')
const PID_FILE = path.join(AUTH_DIR, 'agent.pid')
const SCRATCH_DIR_FILE = path.join(AUTH_DIR, 'scratch-dir.txt')
const AUTH_FILE = path.join(AUTH_DIR, 'bootstrap.json')

export default async function globalTeardown() {
  try {
    const pid = Number(fs.readFileSync(PID_FILE, 'utf-8'))
    process.kill(pid, 'SIGTERM')
    // eslint-disable-next-line no-console
    console.log(`[global-teardown] sent SIGTERM to discovery-agent (pid ${pid})`)
  } catch {
    // Already gone, or never started — nothing to clean up.
  }

  try {
    const scratchDir = fs.readFileSync(SCRATCH_DIR_FILE, 'utf-8').trim()
    if (scratchDir) fs.rmSync(scratchDir, { recursive: true, force: true })
  } catch {
    // Best-effort — a leftover /tmp dir from a scratch run is harmless either way.
  }

  for (const file of [PID_FILE, SCRATCH_DIR_FILE, AUTH_FILE]) {
    fs.rmSync(file, { force: true })
  }
}
