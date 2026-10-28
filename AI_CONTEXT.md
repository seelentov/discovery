# Карта Discovery

Пути относительно корня репозитория. Перед изменением проверяй текущий код: параллельно развивается поддержка протоколов.

| Область | Точки входа |
|---|---|
| Запуск, связывание зависимостей, HTTP listener | `crates/agent/src/main.rs` |
| Конфигурация и проверка настроек | `crates/bootstrap/src/lib.rs`, `config.toml`, `deploy/config.example.toml` |
| Общие типы и контракты | `crates/core/src/` |
| Очереди и обработчики заданий | `crates/queue/src/`, `crates/agent/src/handlers.rs` |
| Устройства, метрики, профили и их применение | `crates/devices/src/`, `crates/config-store/src/`, `crates/dsl/src/`, `crates/agent/src/profile_reload.rs` |
| Протоколы | `crates/snmp/`, `crates/ping/`, `crates/ssh/`, `crates/servicecheck/` |
| Входящие события | `crates/agent/src/trap_listener.rs`, `trap_ingest.rs`, `syslog_listener.rs`, `syslog_ingest.rs` |
| Тревоги, уведомления, топология | `crates/alerts/`, `crates/notify/`, `crates/topology/`, обработчики в `crates/agent/src/` |
| Хранение | `crates/db/` — подключения и маршрутизация доменов; `crates/entities/` — сущности; `crates/migration/` — создание схемы |
| Доступ, журнал, логи | `crates/auth/`, `crates/journal/`, `crates/logging/` |
| ИИ-ассистент | `crates/assistant/`, `crates/llm/` |
| REST и встроенный UI | `crates/web/src/lib.rs`, `crates/web/build.rs` |
| React | `crates/web/frontend/src/{pages,components,api,hooks,layout,styles,utils}` |
| Проверки | Rust `#[cfg(test)]` и `crates/*/tests/`; Playwright в `crates/web/frontend/e2e/` |
| Доставка | `Dockerfile`, `docker-compose.yml`, `deploy/linux-packages/`, metadata в `crates/agent/Cargo.toml` |
| Документация и релизы | `docs/` (пользовательская документация), GitHub Releases (готовые бинарники) |

Основная цепочка: обнаружение → SNMP/идентификация → дедупликация → применение профиля → периодический опрос → метрики/тревоги → уведомления. Конкретные переходы и очереди проверяй по обработчикам, не переноси эту схему буквально на каждый протокол.

`Config::load` читает путь из `CONFIG_FILE` (по умолчанию `config.toml` относительно cwd). Без настроенного storage используется память: данные пропадают после остановки. Для сохраняемого состояния явно настрой SQLite или другой поддерживаемый backend. Разные домены могут использовать разные подключения.

Первый запуск с пустым хранилищем пользователей требует `DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD`; пользователь `admin` обязан сменить его при входе. Для сохраняемых зашифрованных секретов нужен стабильный `DISCOVERY_SECRET_KEY` (32 случайных байта, Base64).

Playwright запускает собственный backend из `target/debug/discovery-agent`, создаёт временный конфиг и общий для прогона набор данных. `E2E_PORT` задаётся отдельно для каждого worktree. Новый многопротокольный стенд реализуется в отдельной задаче; старые ссылки на `devicefarm` не подтверждают его наличие.

## Связанные места изменений

Это ориентиры для проверки затронутого контракта, а не требование менять все перечисленные файлы в каждой задаче.

| Изменение | Что проверить вместе |
|---|---|
| REST: поля, ответы, ошибки, новый endpoint | Роуты и обработчики в `crates/web/src/lib.rs` (либо подключённом модуле), клиент в `crates/web/frontend/src/api/`, типы в `crates/web/frontend/src/api/types.ts`, вызывающие страницы и компоненты |
| Формат и применение профиля | `crates/dsl/src/`, `crates/config-store/src/profile_store.rs`, REST и `reload_matcher_and_nudge_devices` в `crates/web/src/lib.rs`, периодический вызов в `crates/agent/src/profile_reload.rs`: сохранение должно доходить до активного matcher и известных устройств |
| Сохраняемые данные | Сущности в `crates/entities`, соответствующий store, создание схемы в `crates/migration`; при добавлении файла миграции — его `mod` и регистрация в `Migrator::migrations` в `crates/migration/src/lib.rs`. Проверяй чистую установку, перенос старых данных не требуется |
| UI в работающем сервере | `crates/web/frontend/src` → `npm run build` → `frontend/dist` → `crates/web/build.rs` и RustEmbed в `crates/web/src/lib.rs` → сборка `discovery-agent` → перезапуск своего процесса. Подробности проверки сборки — в `discovery-run` |

При изменении контракта ищи его потребителей по символам и путям API. Навигацию по определениям и ссылкам используй, если доступен подходящий инструмент; для текстового поиска достаточно `rg`.
