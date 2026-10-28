# Справочник конфигурации

Основные настройки хранятся в `config.toml`. Для `.deb`/`.rpm` это
`/etc/discovery-agent/config.toml`. В текущем Docker Compose образ получает файл
`/app/config.toml` из `deploy/config.example.toml` во время сборки; соседний файл на хосте
сам по себе контейнер не читает. Для собственной конфигурации либо измените источник и
пересоберите образ, либо добавьте в Compose bind mount:

```yaml
volumes:
  - ./config.toml:/app/config.toml:ro
```

После правки секций, читаемых при старте, перезапустите сервис
(`sudo systemctl restart discovery-agent` или `docker compose restart`). Для изменения
исходного `deploy/config.example.toml` нужен `docker compose up -d --build`.

Большинство повседневных настроек (профили, конфигурации дискаверинга, уведомления, окна
обслуживания) удобнее менять через веб-дашборд, не редактируя файл вручную — они
сохраняются в базу данных, а не в `config.toml`. Ниже — то, что настраивается именно
через файл.

Важно: `[storage]`, `[server]`, `[logging]`, `[concurrency]`, `[worker_poll_interval]` и
`[reclaim]` читаются при старте и требуют перезапуска. `[poll_intervals]` используется
только как начальное заполнение настроек в пустой базе; после первого запуска актуальные
значения живут в базе данных и меняются в «Настройки» или через REST API.

## `[storage]` — базы данных и маршрутизация

```toml
[storage]
default_database = "main"

[[storage.databases]]
name = "main"
kind = "sqlite"                 # postgres | mysql | sqlite | memory
file_path = "/var/lib/discovery-agent/discovery.sqlite3"
# host, port, database, username, password — для postgres/mysql
# pool_max_connections = 64
# sqlite_busy_timeout_secs = 5

[storage.routing]
# jobs = "main"
# devices = "main"
```

`default_database` указывает подключение для доменов без отдельного маршрута. Пустой
список подключений включает временное `sqlite::memory:`-хранилище, которое не переживает
перезапуск. Поддерживаются `postgres`, `mysql`, `sqlite` и `memory`. Размер пула должен
учитывать сумму воркеров из `[concurrency]` и запас под REST/дашборд.

## `[server]` — сетевые настройки дашборда

```toml
[server]
addr = "0.0.0.0:8088"
enable_rest = true
enable_webui = true
```

Адрес и порт, на котором слушает веб-интерфейс. См.
[раздел про безопасность](installation.md#безопасность-и-сеть) — держите этот порт за
firewall/VPN. `enable_rest = false` отключает весь `/api/*`, поэтому встроенный webui при
этом работать не сможет. `enable_webui = false` оставляет REST API без встроенной статики.
Оба значения `false` делают HTTP-интерфейс недоступным; после изменения нужен перезапуск.

## `[logging]` — журналирование

```toml
[logging]
level = "info"
level_console = ""       # пусто = использовать level
level_file = ""
level_dashboard = ""
file = "logs/discovery.log"  # пусто = отключить файловый sink
file_rotation = "daily"      # daily | hourly | never
buffer_size = 1000            # размер журнала в дашборде
```

Пустые уровни наследуют общий `level`. Файл и буфер дашборда — независимые приёмники;
изменения применяются после перезапуска.

## `[concurrency]` и `[worker_poll_interval]` — очереди

`[concurrency]` задаёт число одновременно работающих обработчиков каждой очереди:

```toml
[concurrency]
discovery = 4
snmp_poll = 8
dedup = 4
profile_apply = 4
metric_poll = 8
alert_eval = 4
reachability_poll = 8
service_check_poll = 8
notification_dispatch = 8
topology_recompute = 8
```

`[worker_poll_interval]` задаёт задержку между попытками claim новых заданий в миллисекундах
для тех же очередей (`discovery_ms`, `snmp_poll_ms`, `dedup_ms`, `profile_apply_ms`,
`metric_poll_ms`, `alert_eval_ms`, `reachability_poll_ms`, `service_check_poll_ms`,
`notification_dispatch_ms`, `topology_recompute_ms`). Это не период опроса устройств.
При увеличении concurrency увеличьте пул подключений к БД и учитывайте нагрузку на сеть.

## `[reclaim]` — возврат зависших заданий

```toml
[reclaim]
check_interval_secs = 30
stale_after_secs = 300
```

Цикл с указанным интервалом возвращает в `pending` задания, оставшиеся в `in_progress`
после падения воркера. `stale_after_secs` должен быть больше нормальной длительности самого
долгого задания, иначе живое медленное задание может быть запущено повторно.

## `[poll_intervals]` — начальные интервалы опроса

```toml
[poll_intervals]
identity_secs = 300
metric_secs = 15
profiles_reload_secs = 5
discovery_schedule_check_secs = 30
reachability_secs = 60
metric_history_cleanup_secs = 3600
alert_cleanup_secs = 3600
dead_device_cleanup_secs = 3600
logs_cleanup_secs = 3600
trap_ttl_sweep_secs = 60
```

При пустом хранилище настроек эти значения один раз записываются в базу. На последующих
запусках изменение секции в файле не меняет работающую систему: используйте «Настройки»
или `PUT /api/settings/poll-intervals`.

## `[login_rate_limit]` — защита входа от подбора пароля

```toml
[login_rate_limit]
burst_capacity = 5       # столько попыток подряд разрешено без задержки
refill_per_sec = 0.0167  # ~1 попытка в минуту после исчерпания burst_capacity
```

Значения по умолчанию редко нужно менять — рассчитаны на то, что реальный пользователь,
пару раз ошибившийся паролем, ничего не заметит, а автоматический перебор паролей
сводится к ~60 попыткам в час на пару (логин, IP). См. [Аутентификация](api-reference.md#аутентификация)
за тем, как выглядит ответ при срабатывании лимита.

## Секретный ключ шифрования (`DISCOVERY_SECRET_KEY`)

Не в `config.toml`, а в отдельном файле (`/etc/discovery-agent/discovery.env` для
`.deb`/`.rpm`, `.env` для Docker) — генерируется автоматически при установке. Нужен для
хранения секретов (SNMPv3-пароли, SSH-учётные данные, пароли SMTP/webhook-секреты) в
зашифрованном виде. Обычный SNMP v1/v2c-опрос и сам дашборд без него работают нормально.
Без ключа `PUT`/`POST`-запрос, сохраняющий любой из перечисленных выше секретов, завершается
ошибкой `HTTP 500` с текстом, требующим настроить `DISCOVERY_SECRET_KEY` — секрет не
записывается ни в открытом виде, ни в повреждённом.

## `[snmp_trap]` и `[syslog]` — приём SNMP Trap и Syslog

**Обязательно включить здесь, если используете вкладки «Trap»/«Syslog» в профиле** (см.
[Профили](features/profiles.md#вкладка-trap-5)) — сами по себе биндинги в профиле ничего
не примут, пока соответствующий слушатель не включён и не перезапущен через этот файл:
профильные настройки живут в БД и применяются на лету, а вот сам приём push-сообщений
управляется только здесь и требует перезапуска процесса после изменения.

```toml
[snmp_trap]
enabled = false          # по умолчанию выключено
bind_addr = "0.0.0.0:1162"   # не стандартный 162 — тот требует root/CAP_NET_BIND_SERVICE
ingest_concurrency = 8
rate_limit_per_source_per_sec = 20
allowed_sources = []          # IP или CIDR; пусто = принимать от любого источника

[syslog]
enabled = false
bind_addr = "0.0.0.0:1514"   # не стандартный 514, та же причина
ingest_concurrency = 8
rate_limit_per_source_per_sec = 20
allowed_sources = []          # IP или CIDR; пусто = принимать от любого источника
```

Если ваши устройства настроены слать trap/syslog на стандартный порт (162/514) —
либо укажите его явно в `bind_addr` и дайте процессу нужную привилегию
(`CAP_NET_BIND_SERVICE` на Linux), либо перенастройте устройства слать на порт из примера
выше. `rate_limit_per_source_per_sec` — защита от одного слишком болтливого источника, не
общий лимит на всю систему; `ingest_concurrency` — сколько сообщений обрабатывается
параллельно.

## Уведомления и окна обслуживания

В `config.toml` для них нет секции — оба ресурса, как профили и конфигурации дискаверинга
выше, хранятся не в файле, а в базе данных агента и управляются через REST API/дашборд:
`PUT/POST/DELETE /api/notifications/channels`, `/api/notifications/rules` и
`/api/maintenance-windows`. Поля и семантика каждого — [Уведомления](features/notifications.md),
[Окна обслуживания](features/maintenance-windows.md).
