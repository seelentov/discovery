# E2E tests (Playwright)

Full click-through coverage of the React dashboard — every page, every button, every
modal — driven against a **real, isolated `discovery-agent` binary** (not a mock backend,
not the Vite dev server) via real HTTP/DOM, the same way an actual user would. No SNMP
simulator is used or needed: `create_dead_devices: true` on a discovery subnet bypasses
the ping gate entirely, so `TEST-NET-3` addresses (`203.0.113.0/24`, RFC 5737 — reserved
for documentation, never routable) reliably become real `Device`/`Alert` rows through the
genuine pipeline (Discovery → SnmpPoll → Dedup → ProfileApply → MetricPoll → AlertEval),
SNMP timeouts and all. See `06-discovery.spec.ts`'s docs for the exact mechanism.

## Running

```bash
# 1. Backend must be built first — the suite spawns the real binary, it doesn't build it
#    (keeps every run fast; a stale binary here is a "did you build?" mistake, not this
#    suite's job to catch).
cd ../../..              # repo root
cargo build -p discovery-agent

# 2. Frontend must be built too — the backend serves the embedded `dist/`, and (thanks to
#    crates/web/build.rs) a `cargo build` after this WILL pick up a fresh dist/ even
#    without touching any .rs file.
cd crates/web/frontend
npm run build
cd ../../..
cargo build -p discovery-agent   # only needed if you skipped step 1 after this

# 3. Run the suite
cd crates/web/frontend
npm run test:e2e            # headless
npm run test:e2e:headed     # watch it click through the browser
npm run test:e2e:report     # open the last HTML report
```

## How it's isolated

`e2e/global-setup.ts` spawns `target/debug/discovery-agent` once for the whole run with
`CONFIG_FILE` pointing at a path that's guaranteed not to exist — the exact zero-config
pattern `docs/Architecture/Testing и Live-проверка.md` documents for manual live checks:
storage defaults to `sqlite::memory:`, nothing persists, the real `discovery_dev` Postgres
dev stand is never touched. The bootstrap admin password is generated in setup and passed
to the child only through `DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD`; it is never read from
process output. After the forced password change, only the resulting credentials are
written to the ignored `e2e/.auth/bootstrap.json` for specs to read via `fixtures.ts`'s
`bootstrapCredentials()`. Setup failure and `global-teardown.ts` both terminate the agent
and remove the scratch directory and credential artifacts.

## Why the specs run in a fixed, numbered order (not parallel, not isolated per-test)

`playwright.config.ts` sets `workers: 1` / `fullyParallel: false` deliberately. This
suite optimizes for **one shared, realistic backend building up real state test-by-test**
(mirroring the project's own "one shared live instance, sequential concrete proof"
testing philosophy — see `.claude/rules/testing-and-verification.md`), not for
fully-isolated unit-style tests. Concretely:

- `05-profiles` creates a profile whose match expression is `true` (matches every device)
  and whose one alert rule's activation expression is also `true` (fires on any device's
  first `MetricPoll` tick, no real metric value needed).
- `06-discovery` creates a discovery config with three `/32` TEST-NET-3 subnets and runs
  it — the real pipeline turns those into three real devices, which the `05` profile
  matches, which fires three real alerts. This is what gives `07`/`08`/`09` (Devices/
  Queues/Alerts) real rows to click on instead of empty-state screens.
- `08` and `09` each also generate their own fresh, disposable discovery activity (new
  `/28`/`/32` subnets) rather than reusing `06`'s already-settled devices, specifically to
  have something genuinely *mid-flight* to interact with (pending jobs, an active alert
  that hasn't been closed yet).
- `11-overview` is last on purpose — it asserts non-zero counts that only exist because
  everything before it ran.

Numeric filename prefixes (`01`-`11`) encode this dependency chain; shared constants
(seeded IPs/names) live in `e2e/shared.ts`, not per-spec (Playwright forbids importing one
`*.spec.ts` file from another).

## Real bugs this suite caught (not written to match existing behavior)

Two genuine app bugs were found and fixed while building this suite, not introduced
by it — see `docs/Changelog/2026-08-25 - E2E тесты (Playwright).md` for the full writeup:

1. **Sticky topbar overlapped the first ~49px of every page's content**, making anything
   in that band unclickable (first caught as an unrelated-looking `Settings` page test
   timeout). Root cause: `49px` throughout `app-shell`/`sidebar`/`topbar` CSS was a
   leftover offset for `.mode-bar` — a design-artifact-only element (the "UI Kit vs
   Прототип" switcher) this real app never renders. Fixed by zeroing those offsets.
2. **`crates/web` had no `build.rs`** — `cargo build` had no way to know `frontend/dist/`
   even existed, so a `cargo build` run after `npm run build` (touching no `.rs` file) was
   a silent no-op that kept embedding whatever `dist/` happened to be baked in from a
   previous, unrelated recompile. Fixed with a one-line `build.rs` declaring
   `cargo:rerun-if-changed=frontend/dist`.
3. **`SettingsPage`'s three checkbox-backed retention sections could get clobbered by
   their own initial fetch** — `alertForever`/`logForever`/`deadNever` default to `true`
   in local state before `loadAll()`'s response arrives; a fast interaction in that window
   (unchecking one right after navigating in) got silently overwritten back to the
   optimistic default the instant the real fetch resolved. Fixed with an explicit
   `loaded` gate mirroring the `!= null` gate the object-shaped sections already had.
4. **Runaway `sqlx::query` ↔ `logs` feedback loop** (2026-08-26, found from a direct user
   report of ~100GB in minutes on a brief run, not by this suite) — persisting a captured
   log entry is itself a SQL `INSERT`, which sqlx traces as its own loggable event; with
   no exclusion, persisting *any* event re-entered the pipeline forever. Fixed by
   hardcoding `sqlx=off` on the persisting/dashboard-buffer layers — see
   `crates/agent/src/logging_setup.rs` and `docs/Changelog/2026-08-26 - Runaway
   лог-фидбек-луп (sqlx x logs).md`. `10-logs.spec.ts`'s target-filter test used to search
   for `sqlx` as a "guaranteed present" target — that assumption flipped after this fix
   (its correct absence *is* the proof the fix works), so the test now searches
   `discovery_agent` instead.

Separately, repeated full-suite (not single-file) runs also caught **test-fragility**, not
app bugs — worth knowing before adding new specs: `LogsQuery.search` only matches
`message`/`target`, never structured `fields` (a `sqlx::query` line's actual SQL text
lives in `fields`, not `message` — search for a real log *message*, not field content);
`OverviewPage`'s alerts panel only ever shows its 10 most recent entries, so don't assert
a specific seeded device stays in that top-10 once other specs have created more than 10
matching alerts.

**2026-09-12:** full-suite runs are noticeably sensitive to concurrent load on the machine
running them (other `cargo build`s, other browsers, general memory pressure) — under heavy
contention, a run can degenerate into a long cascade of unrelated `.sidebar`/element-not-
found timeouts starting partway through and never recovering, purely because every
subsequent login/render blows past Playwright's fixed timeouts, not because anything in
the app or the new spec actually broke. Confirmed by re-running the identical suite
back-to-back on an otherwise-idle machine and getting a clean pass. If a run shows a long
tail of failures with no code change to explain them, check system load before trusting
the result — rerun once uncontended before concluding a spec (new or existing) is broken.

## Files

- `global-setup.ts` / `global-teardown.ts` — spawn/kill the real backend for the whole run.
- `fixtures.ts` — `login()`, the `adminPage` fixture, `fieldByLabel`/`fieldInput` (see its
  own docs for why `getByLabel()` doesn't work against this app's `Field` component).
- `shared.ts` — cross-spec constants (seeded IPs, profile/config names).
- `01`-`11` — one file per concern, in dependency order (see above).
