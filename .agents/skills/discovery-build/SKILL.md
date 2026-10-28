---
name: discovery-build
description: Собрать релизные бинарники Discovery для Windows, macOS и Linux на x86_64 и ARM64, упаковать и проверить артефакты.
---

# Релизная сборка Discovery

Перед сборкой проверь `Cargo.toml`, `Cargo.lock`, `crates/agent/Cargo.toml`, `Dockerfile` и доступные toolchains. Новые протокольные зависимости могут менять поддержку целей.

## Матрица

| ОС | x86_64 | ARM64 | Предпочтительная среда |
|---|---|---|---|
| Linux | `x86_64-unknown-linux-gnu` | `aarch64-unknown-linux-gnu` | Linux runner нужной архитектуры или проверенный cross toolchain |
| macOS | `x86_64-apple-darwin` | `aarch64-apple-darwin` | macOS с Apple SDK и linker |
| Windows | `x86_64-pc-windows-msvc` | `aarch64-pc-windows-msvc` | Windows с соответствующими MSVC tools и SDK |

Это целевая матрица, не утверждение о шести успешных сборках. `rustup target add <target>` устанавливает Rust std, но не SDK, C/C++ cross compiler и linker. Проверяй native dependencies, например crypto `*-sys`, по фактическому build log. Не обещай универсальную сборку всех целей на одном Mac.

## Процедура

1. В frontend: `npm ci`, `npm run build`. UI должен быть свежим до каждой Rust release-сборки.
2. Для каждой цели: `cargo build --release --locked -p discovery-agent --target <target>` в подходящем окружении. При native запуске без `--target` бинарник лежит в `target/release`, с флагом — в `target/<target>/release`.
3. Сохрани binary (`discovery-agent.exe` для Windows), `LICENSE`, `QUICKSTART.md` и portable config с SQLite `data/discovery.sqlite3`, loopback HTTP и без чужих секретов. Версию возьми из manifest; зафиксируй commit, target, toolchain, способ сборки и динамические зависимости.
4. Упакуй каждый target отдельно (zip для Windows, tar.gz для Unix). Сгенерируй SHA-256 по готовым архивам средствами доступного хоста: `shasum -a 256`, `sha256sum` или PowerShell `Get-FileHash -Algorithm SHA256`.
5. На соответствующей ОС/архитектуре проверь чистый запуск, первый вход/смену пароля, UI, запись данных и перезапуск. Эмуляцию отметь отдельно. Статусы «собран», «проверен запуск», «E2E пройден» не объединяй.

Готовые бинарники публикуются в GitHub Releases репозитория Discovery (архивы и SHA-256 прикладываются к релизу с тегом версии).

Не публикуй и не загружай артефакты без запроса. Подпись/нотаризация не следуют из успешной компиляции.

## Linux-пакеты

Metadata в `crates/agent/Cargo.toml` использует `QUICKSTART.md` и `LICENSE` из корня, конфиги и scripts из `deploy/linux-packages/`.

- deb: из корня `cargo deb -p discovery-agent` при установленном cargo-deb.
- rpm: сначала native release-сборка, затем из `crates/agent` — `cargo generate-rpm` при установленном cargo-generate-rpm.
- Перед cross packaging проверь пути metadata: native `target/release` не совпадает с `target/<target>/release`. Не переименовывай чужой бинарник ради совпадения пути.
- Проверь состав пакета и установку в отдельной Linux VM/container с подходящей init-средой. Сверь package architecture, права, config, systemd и первый запуск. Локальный macOS-прогон не подтверждает установку deb/rpm.
