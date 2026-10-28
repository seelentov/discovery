//! Without this, `cargo build` has no reason to know `frontend/dist/` even exists —
//! `rust-embed`'s derive macro reads the folder at compile time but registers no
//! `rerun-if-changed` of its own, so a `cargo build` run after `npm run build` (with no
//! *Rust* source file touched) is a silent no-op: the binary keeps whatever `dist/` was
//! embedded the *previous* time this crate happened to recompile, with no error, no
//! warning, nothing — found live 2026-08-25 while re-verifying an E2E-caught CSS fix,
//! where the freshly built `dist/` kept not showing up in test runs. Cargo's own docs
//! confirm a `rerun-if-changed` pointing at a directory is scanned recursively for any
//! file change inside it, which is exactly the granularity `frontend/dist/`'s variable,
//! hashed-filename Vite output needs.
fn main() {
    println!("cargo:rerun-if-changed=frontend/dist");
}
