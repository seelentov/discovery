# discovery dashboard — frontend

React 19 + TypeScript, built with Vite, styled with plain CSS (design tokens ported from
the signed-off design artifact — see `src/styles/global.css`'s header comment). No
component library, no CSS framework: this repo is otherwise pure Rust, so the frontend
stays as close to "just a few well-organized files" as a real dashboard reasonably allows.

## Build order — read this before `cargo build`

`crates/web` embeds this project's **built output** (`dist/`) directly into the
`discovery-web` binary via `rust-embed` (see `Assets`/`serve_embedded` in
`crates/web/src/lib.rs`). `dist/` is gitignored (a build artifact, not source) — so:

```bash
cd crates/web/frontend
npm install       # first time, or after package.json changes
npm run build     # produces dist/ — required before `cargo build` picks up this crate
cd ../../..
cargo build
```

Forgetting this step doesn't fail the Rust build (rust-embed just embeds an empty/stale
`dist/`, or whatever was last built) — the binary boots fine but `serve_embedded` returns
a 500 with an explanatory message telling you to run the steps above.

CI must run the `npm` steps before `cargo build`/`cargo test` for the same reason.

## Local development

Two processes, same as any Vite + separate-backend setup:

```bash
# terminal 1 — the real backend, whatever port config.toml's [server].addr says (8088 by default)
cargo run -p discovery-agent

# terminal 2 — Vite dev server with hot reload, proxying /api to the backend above
cd crates/web/frontend && npm run dev
```

Open the Vite dev server's own URL (not the Rust binary's) — `vite.config.ts` proxies
`/api/*` to `http://127.0.0.1:8088`, so it talks to real data without a build step, and
without axum needing to know Vite exists.

## E2E tests

`e2e/` — full Playwright click-through of every page against a real, isolated
`discovery-agent`. See `e2e/README.md` for how to run it and what it's found so far.

## Where things live

- `src/api/` — typed REST client (`http.ts` for the low-level fetch wrapper, `types.ts`
  mirroring the real Rust `#[derive(Serialize)]`/`Deserialize` structs 1:1 — see that
  file's header comment for the "backend changes first" rule).
- `src/components/` — generic, page-agnostic pieces (`Button`, `Badge`, `Switch`,
  `Modal`, `Icon`, ...).
- `src/hooks/` — cross-cutting app state as React context + hook pairs (`useAuth`,
  `useToast`, `useConfirm`).
- `src/layout/` — the app shell (sidebar + topbar), and `pages.ts`, the single source of
  truth for the 9-page navigation structure (`implemented: false` pages render a
  placeholder instead of a route until they're ported).
- `src/pages/` — one file per page.

## Status (2026-08-25)

All 9 pages in `layout/pages.ts` are ported. The old `crates/web/static/index.html` and
its `GET /legacy` route were deleted the same day, once that was true — see
`docs/Changelog/2026-08-25 - React Frontend — все страницы.md`.

**2026-08-27 design-artifact parity pass** — see `docs/Changelog/2026-08-27 - Design-
artifact parity pass (фильтры, экспорт, Roles).md` for the full write-up. Closed most of
the gaps a page-by-page audit found against the signed-off artifact: Devices gained a
profile dropdown + CIDR filter + metric-value search + a real metric-history chart,
Profiles gained real server-side search/sort/pagination, Alerts gained header-click sort +
rule traceability + bulk-close + date-range, Logs gained a bounded-24h date-range, Settings
exposes ClickHouse/Cassandra (a real UI gap, not a design one — the backend already
supported both), Overview's tiles/lists are now clickable, Devices/Alerts got CSV/XLSX/JSON
export, and Users gained a full Roles model (`roles`/`role_permissions`, replacing the old
per-user permission grid entirely — this one *was* a backend feature, not a frontend port,
see that changelog entry).

One remaining known, deliberate difference from the design artifact (caught while wiring
real data originally, still accurate):

- Metric values render with no unit suffix (no "%", "дБм", ...) — `MetricSpec`/
  `MetricRecord` have no unit field in the real schema, so there's nothing to render;
  the artifact's units were a display-only invention worth flagging if it resurfaces.
