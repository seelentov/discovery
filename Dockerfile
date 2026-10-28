# Builds a single discovery-agent image: React dashboard + Rust binary, no external
# services required by default (SQLite storage, see deploy/config.example.toml).
#
# Live-verified 2026-09-12 (Colima on macOS/arm64): `docker compose up -d --build` built
# clean and the full QUICKSTART.md flow (login -> forced password change -> profile ->
# discovery config -> real device appearing in `GET /api/devices`) passed end-to-end
# against the real container. See docs/Changelog for that entry.

# ---- Stage 1: build the React dashboard -----------------------------------------------
FROM node:20-bookworm-slim AS frontend-builder
WORKDIR /app/crates/web/frontend
COPY crates/web/frontend/package.json crates/web/frontend/package-lock.json ./
RUN npm ci
COPY crates/web/frontend/ ./
RUN npm run build

# ---- Stage 2: build the discovery-agent binary -----------------------------------------
FROM rust:1-bookworm AS rust-builder
# pkg-config/libssl-dev: TLS-using deps (notifications talk HTTPS/SMTP+STARTTLS).
# cmake/perl/clang: several transitive -sys crates in this workspace (evidence: aws-lc-sys
# build objects, likely pulled in via russh/rustls) need these for their native build step.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev cmake perl clang \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
# crates/web/build.rs embeds whatever is in crates/web/frontend/dist/ into the binary at
# compile time (see crates/web/frontend/README.md, "Build order") -- it must exist before
# `cargo build` runs, so the frontend stage's output is copied in first.
COPY --from=frontend-builder /app/crates/web/frontend/dist/ ./crates/web/frontend/dist/
RUN cargo build --release -p discovery-agent
# Future optimization, not a correctness issue: this rebuilds all dependencies on every
# source change since there's no separate dependency-only layer (e.g. via cargo-chef).
# Fine for a first working image; worth revisiting if iteration speed matters later.

# ---- Stage 3: runtime --------------------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /app --shell /usr/sbin/nologin discovery

WORKDIR /app
COPY --from=rust-builder /app/target/release/discovery-agent /usr/local/bin/discovery-agent
COPY deploy/config.example.toml /app/config.toml

RUN mkdir -p /data && chown -R discovery:discovery /app /data

USER discovery
ENV CONFIG_FILE=/app/config.toml
EXPOSE 8088
VOLUME ["/data"]

ENTRYPOINT ["discovery-agent"]
