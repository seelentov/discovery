# REST API

Всё, что делает дашборд, доступно и напрямую через REST — дашборд сам является лишь одним
из клиентов этого API, привилегий у него никаких особенных нет. Это описание годится и
для написания собственной интеграции (например, синк устройств из вашей системы учёта, или
получение тревог в свою систему мониторинга инцидентов).

## Базовые соглашения

- Все пути — `/api/...`, на том же хосте и порту, что и сам дашборд.
- Тело запроса и ответа — JSON, кроме двух исключений: вложения к комментариям тревог
  передаются как base64-строка *внутри* JSON (не `multipart/form-data`), а скачивание
  вложения отдаёт сырые байты с заголовками `Content-Type`/`Content-Disposition`, как
  обычная отдача файла.
- **Ошибки — не JSON.** Тело ошибки — обычный текст (`Content-Type: text/plain`), не
  `{"error": "..."}`. Разбирайте по HTTP-статусу, текст — для человека, не для парсинга по
  структуре.
- Списочные эндпоинты (устройства, тревоги, профили, дискаверинг, задачи очередей, логи,
  журнал) принимают `page`/`page_size` (по умолчанию `page=1`, `page_size=50`, максимум
  `500`) и возвращают `{"items": [...], "total": N}` — `total` до пагинации, чтобы клиент
  мог посчитать число страниц.
- **Регистр строковых enum-значений различается между query-параметром фильтра и полем
  JSON-тела для одного и того же понятия** — не опечатка, а следствие того, что фильтры в
  query-строке разбираются вручную (нижний регистр: `?level=critical`, `?state=active`),
  а поля тела — обычным `serde`-выводом по имени варианта Rust as is (с большой буквы:
  `"level": "Critical"`, `"state": "Active"`). Уровень тревоги/статус тревоги/уровень
  матрицы уведомлений — везде так; проверяйте регистр под конкретное место, не
  переносите его между query и телом по аналогии.

## Аутентификация

```
POST /api/auth/login
{"username": "admin", "password": "..."}
→ 200 {"token": "...", "user": {"id", "username", "is_admin", "must_change_password", "role_id", "role_name"}}
```

Ответ также ставит `Set-Cookie: discovery_session=...; HttpOnly; SameSite=Lax` — сам
дашборд работает через эту куку. Для прямых вызовов (curl, скрипты, интеграции) удобнее
`token` из тела: передавайте его в каждом следующем запросе как
`Authorization: Bearer <token>`. Оба способа равнозначны — сервер сначала смотрит на
заголовок `Authorization`, и только если его нет — на куку.

**Лимит попыток входа**: burst + плавное восполнение (настройка — см.
[`[login_rate_limit]`](configuration.md#login_rate_limit--защита-входа-от-подбора-пароля)),
ключ — пара (имя пользователя, IP). При
превышении — тот же ответ, что и на неверный пароль (`401 invalid username or password`)
— специально нет отдельного «вы заблокированы», чтобы не подсказывать атакующему, сработал
троттлинг или пароль просто неверный.

| Метод | Путь | Доступ | Тело / ответ |
|---|---|---|---|
| POST | `/api/auth/login` | публичный | см. выше |
| POST | `/api/auth/logout` | любая сессия (no-op без неё) | `204`, снимает куку |
| GET | `/api/auth/me` | требует сессию | `200` с тем же `user`, что и login, либо `401` |
| PUT | `/api/auth/password` | требует сессию | `{"current_password", "new_password"}` → `204` |

`PUT /api/auth/password` работает независимо от `must_change_password` — единственный
путь выйти из состояния «обязательна смена пароля».

## Права доступа — как читать коды ошибок

Каждый маршрут ниже помечен одним из четырёх уровней доступа:

- **публичный** — без сессии вообще (только `/api/auth/login`).
- **требует сессию** — валидный токен/кука, без требований к роли.
- **домен: X (чтение/запись)** — GET/HEAD требует уровня «чтение» на домене X, любой
  другой метод — уровня «запись» (см. [Пользователи → Роли](features/users.md#вкладка-роли)
  за полным списком из 12 доменов и их русских названий).
- **администратор** — `is_admin = true` на аккаунте; роль в этом случае не участвует.

Типичные коды ошибок, в порядке проверки:

| Код | Тело | Когда |
|---|---|---|
| `401` | `not logged in` | нет ни заголовка `Authorization`, ни куки |
| `401` | `invalid or expired session` | токен есть, но не найден/истёк |
| `403` | `password change required — PUT /api/auth/password` | у аккаунта `must_change_password = true` — блокирует вообще все доменные/админские маршруты, кроме самой смены пароля |
| `403` | `requires <read\|write> access to <domain>` | сессия валидна, но роль не даёт нужного уровня на этом домене |
| `403` | `requires admin` | маршрут админский, а аккаунт не администратор |
| `404` | текст с именем ресурса | ресурс с таким id/именем не найден |
| `400` | текст с описанием проблемы | тело запроса не прошло валидацию (например, пустое имя, `ends_at` раньше `starts_at`) |
| `500` | текст ошибки | внутренняя ошибка — например, сохранение секрета без настроенного `DISCOVERY_SECRET_KEY` (см. [Справочник конфигурации](configuration.md)) |

**Побочный эффект каждого успешного изменяющего запроса**: любой не-GET/HEAD запрос к
доменному или админскому маршруту, завершившийся `2xx`, дописывает одну строку в
[Журнал](features/journal.md) — это происходит одинаково что через дашборд, что через
прямой вызов API, разницы для журнала нет.

---

## Устройства (домен `devices`)

| Метод | Путь | Доступ | Описание |
|---|---|---|---|
| GET | `/api/devices` | domain: devices (чтение) | список, фильтры `search`/`profile`/`has_error`/`cidr`, сортировка `sort_by=ip\|profile\|discovered_at`, `sort_dir` |
| POST | `/api/devices` | domain: devices (запись) | создать вручную (см. ниже) |
| PUT | `/api/devices/enabled` | domain: devices (запись) | массовое вкл/выкл — `{"enabled": bool}` → `{"touched": N}` |
| GET | `/api/devices/:id` | domain: devices (чтение) | одно устройство |
| DELETE | `/api/devices/:id` | domain: devices (запись) | удалить (каскадно — метрики, тревоги) |
| PUT | `/api/devices/:id/enabled` | domain: devices (запись) | `{"enabled": bool}` |
| PUT | `/api/devices/:id/ssh_credentials` | domain: devices (запись) | `{"username", "auth": {...}, "port"}` — см. ниже |
| POST | `/api/devices/:id/sync-profile` | domain: devices (запись) | сбросить ручные override метрик обратно на профиль |
| GET | `/api/devices/:id/metrics/:name/history` | domain: device_metrics (чтение) | пагинация `page`/`page_size`, `since`/`until` |
| PUT | `/api/devices/:id/metrics/:name/enabled` | domain: device_metrics (запись) | включить/выключить конкретную метрику на устройстве (override) |
| DELETE | `/api/devices/:id/metrics/:name/enabled` | domain: device_metrics (запись) | сбросить override обратно на настройку профиля |

```
POST /api/devices
{
  "ip": "10.0.0.5",
  "profile": "switch-access",       // необязательно
  "metrics": {"area_name": "Воронеж"},  // необязательно, только строки
  "snmp_auth": {...},               // необязательно, см. ниже
  "snmp_port": 161                  // необязательно, по умолчанию 161
}
```

`snmp_auth` — тот же формат, что и `credentials` внутри подсети дискаверинга (раздел
«Дискаверинг» ниже): `{"kind": "community", "version": "v1"|"v2c", "community": "..."}`
либо `{"kind": "usm_v3", "user": "...", "auth": {"protocol": "...", "passphrase": "..."} | null, "priv_": {"protocol": "...", "passphrase": "..."} | null}`
— значения `protocol` (`md5`/`sha1`/`sha224`/`sha256`/`sha384`/`sha512` для `auth`,
`des`/`des3`/AES-варианты для `priv`) перечислены в форме дискаверинга — см.
[Дискаверинг](features/discovery-configs.md#snmp-доступ).

```
PUT /api/devices/:id/ssh_credentials
{"username": "admin", "auth": {"Password": "..."} | {"PrivateKey": "..."}, "port": 22}
```

`GET`-ответ по устройству дополнительно содержит `ssh_credentials.known_host_key` —
отпечаток SSH-ключа устройства, запомненный при первом подключении (`null`, пока
подключения ещё не было); задать его через этот `PUT` нельзя, только через реальное
подключение к устройству — см. [Устройства](features/devices.md).

Полную семантику полей — см. [Устройства](features/devices.md).

## Тревоги (домен `alerts`)

| Метод | Путь | Доступ | Описание |
|---|---|---|---|
| GET | `/api/incidents` | domain: alerts (чтение) | только сейчас активные, без пагинации/истории — лёгкий снимок без похода в БД |
| GET | `/api/alerts` | domain: alerts (чтение) | полная история, фильтры `search`/`level=info\|warning\|critical`/`state=active\|cleared`/`device_id`/`since`/`until`, `sort_by=first_seen\|last_seen\|level\|name\|device_ip` |
| GET | `/api/alerts/:id` | domain: alerts (чтение) | одна тревога |
| DELETE | `/api/alerts/:id` | domain: alerts (запись) | удалить запись насовсем |
| POST | `/api/alerts/:id/close` | domain: alerts (запись) | закрыть вручную — идемпотентно, `closed_by` = вызвавший пользователь |
| GET/POST | `/api/alerts/:id/comments` | domain: alerts (чтение/запись) | тред обсуждения — см. ниже |
| GET | `/api/alerts/:id/comments/:comment_id/attachments/:attachment_id` | domain: alerts (чтение) | скачать вложение — сырые байты, не JSON |

```
POST /api/alerts/:id/comments
{
  "text": "...",
  "attachments": [{"filename": "screenshot.png", "content_type": "image/png", "data_base64": "..."}]
}
```

Полную семантику (гистерезис, статус «Утеряна») — см.
[Тревоги](features/alerts.md).

## Очереди (домен `jobs`)

| Метод | Путь | Доступ | Описание |
|---|---|---|---|
| GET | `/api/queues` | domain: jobs (чтение) | агрегаты по всем 10 очередям — `[{"queue": "discovery", "stats": {...}}, ...]` |
| GET | `/api/workers` | domain: jobs (чтение) | что сейчас выполняет каждый воркер |
| PUT | `/api/queues/:kind/paused` | domain: jobs (запись) | `{"paused": bool}` — пауза всей очереди |
| GET | `/api/queues/:kind/jobs` | domain: jobs (чтение) | задачи очереди, фильтр `state=pending\|in_progress\|failed`, `search`, `sort_by=id\|created_at\|updated_at\|attempts` |
| DELETE | `/api/queues/:kind/jobs` | domain: jobs (запись) | очистить очередь целиком, опционально `?state=failed` — только этот статус |
| DELETE | `/api/queues/:kind/jobs/:id` | domain: jobs (запись) | удалить одну задачу |
| POST | `/api/queues/:kind/jobs/:id/pause` | domain: jobs (запись) | приостановить одну задачу |
| POST | `/api/queues/:kind/jobs/:id/resume` | domain: jobs (запись) | возобновить |

`:kind` — одно из `discovery`, `snmp_poll`, `dedup`, `profile_apply`, `metric_poll`,
`alert_eval`, `reachability_poll`, `service_check_poll`, `notification_dispatch`,
`topology_recompute`. Что делает каждая — [Очереди](features/queues.md).

## Логи (домен `logs`)

| Метод | Путь | Доступ | Описание |
|---|---|---|---|
| GET | `/api/logs` | domain: logs (чтение) | живой буфер в памяти процесса (не файл) — `level=error\|warn\|info\|debug\|trace` (этот и серьёзнее), `target`, `search`, `since`/`until`, `sort_dir=asc\|desc` |

Обнуляется при перезапуске процесса — полная история пишется отдельно в лог-файл
(`journalctl`/`docker logs`). Подробнее — [Логи](features/logs.md).

## Профили (домен `profiles`)

| Метод | Путь | Доступ | Описание |
|---|---|---|---|
| GET | `/api/profiles` | domain: profiles (чтение) | `search` (по имени и именам метрик), `sort_by=name\|priority` |
| POST | `/api/profiles` | domain: profiles (запись) | upsert по имени — см. ниже |
| GET | `/api/profiles/:name` | domain: profiles (чтение) | один профиль |
| DELETE | `/api/profiles/:name` | domain: profiles (запись) | удалить |
| POST | `/api/profiles/:name/sync-devices` | domain: profiles (запись) | сбросить override метрик у всех устройств этого профиля |

`POST /api/profiles` принимает **целиком** структуру профиля — то же, что возвращает
`GET /api/profiles/:name`:

```
{
  "profile": {"name": "switch-access", "priority": 10},
  "match": {"expression": "true"},
  "metrics": {"poll": {"cpu_load": {"oid": "1.3.6.1...", "schedule": {"interval_secs": 30}}}},
  "alerts": [{"name": "high_cpu", "level": "warning", "expression": "facts.cpu_load > 90", "message": "..."}],
  "syslog": {...},
  "traps": {...},
  "service_checks": {...}
}
```

Имя — ключ upsert (существующее имя — редактирование, новое — создание); переименовать
существующий профиль нельзя, только клонировать под новым именем. Полную схему каждой из
6 вкладок (метрики, тревоги, syslog, trap, service check — включая Rhai-выражения) — см.
[Профили](features/profiles.md), там же — валидация,
которую эта ручка делает при сохранении (конфликт имён метрик, зарезервированное имя
`device_unreachable`, некорректные syslog/trap-биндинги).

## Дискаверинг (домен `discovery_configs`)

| Метод | Путь | Доступ | Описание |
|---|---|---|---|
| GET | `/api/discovery-configs` | domain: discovery_configs (чтение) | `search`, `enabled=true\|false`, `sort_by=name\|enabled` |
| POST | `/api/discovery-configs` | domain: discovery_configs (запись) | upsert по имени |
| GET | `/api/discovery-configs/:name` | domain: discovery_configs (чтение) | одна конфигурация |
| DELETE | `/api/discovery-configs/:name` | domain: discovery_configs (запись) | удалить |
| POST | `/api/discovery-configs/:name/run` | domain: discovery_configs (запись) | запустить сканирование сейчас, не дожидаясь расписания |

```
{
  "name": "voronezh-access",
  "enabled": true,
  "schedule": {"interval_secs": 3600},
  "subnets": [{
    "ip": "10.0.0.0", "mask": "255.255.255.0", "port": 161,
    "credentials": [{"kind": "community", "version": "v2c", "community": "public"}],
    "oids": {}, "labels": {"area_name": "Воронеж"},
    "snmp_timeout_ms": null, "snmp_retries": null, "create_dead_devices": false
  }]
}
```

`schedule` — **без тега варианта** (`#[serde(untagged)]`): форма JSON сама определяет
режим — `{"interval_secs": N}` (по периоду) или `{"months": [1,6], "days_of_month": [1,15],
"time": "03:00:00"}` (по календарю, `months`/`days_of_month` пустые = каждый месяц/день,
`time` — **локальное время сервера**, не UTC). Отправка обоих наборов полей сразу или
ни одного не задокументирована и не гарантирует конкретный результат — выбирайте одну
форму.

Полную схему подсетей (SNMP-кандидаты community/v3, OID-обогащение, метки) — см.
[Дискаверинг](features/discovery-configs.md).

## Окна обслуживания (домен `maintenance_windows`)

| Метод | Путь | Доступ | Описание |
|---|---|---|---|
| GET | `/api/maintenance-windows` | domain: maintenance_windows (чтение) | список |
| POST | `/api/maintenance-windows` | domain: maintenance_windows (запись) | создать/изменить — `id: null` создаёт, `id` существующего — редактирует |
| GET | `/api/maintenance-windows/:id` | domain: maintenance_windows (чтение) | одно окно |
| DELETE | `/api/maintenance-windows/:id` | domain: maintenance_windows (запись) | удалить |

```
{
  "id": null,
  "name": "Плановые работы на аплинке",
  "enabled": true,
  "starts_at": "2026-01-01T00:00:00Z",
  "ends_at": "2026-01-02T00:00:00Z",
  "subnets": [{"ip": "10.0.0.0", "mask": "255.255.255.0"}],
  "profiles": ["switch-access"],
  "device_ids": []
}
```

Устройство попадает под окно, если подходит **хотя бы под один** из трёх селекторов;
пустые все три — окно не действует ни на одно устройство (в отличие от матрицы
уведомлений ниже, где пусто = все). Подробнее — [Окна обслуживания](features/maintenance-windows.md).

## Уведомления (домен `notifications`)

Три независимых семейства ручек — личные каналы (self-service, без доменного гейта — как
`/api/auth/password`), матрица правил (`domain: notifications`) и провайдер (тоже
`domain: notifications`).

| Метод | Путь | Доступ | Описание |
|---|---|---|---|
| GET/POST | `/api/notifications/channels` | требует сессию (self-service) | свои собственные каналы |
| DELETE | `/api/notifications/channels/:id` | требует сессию (self-service) | удалить свой канал |
| GET/POST | `/api/users/:id/notification-channels` | администратор | каналы другого пользователя (поддержка) |
| DELETE | `/api/users/:id/notification-channels/:channel_id` | администратор | — |
| GET/POST | `/api/notifications/rules` | domain: notifications | матрица «кого извещать по какой тревоге» |
| GET/DELETE | `/api/notifications/rules/:id` | domain: notifications | — |
| GET | `/api/notifications/recipients` | domain: notifications (чтение) | `[{"id", "username"}]` — список пользователей для выбора получателей, без прав `/api/users` |
| GET | `/api/notifications/recipient-roles` | domain: notifications (чтение) | `[{"id", "name"}]` — то же самое, но список ролей, без прав `/api/roles` |
| GET/PUT | `/api/settings/notifications` | domain: notifications | SMTP/Telegram-реквизиты — см. ниже |

```
POST /api/notifications/channels
{"id": null, "kind": "email" | "telegram" | "webhook", "target": "...", "secret": "...", "enabled": true}
```

`kind` — **строго нижний регистр**, `"Email"`/`"Telegram"` не пройдёт валидацию (`422`).
`target`: email-адрес / Telegram `chat_id` (числовой, не username) / полный URL вебхука.
`secret` — только для `webhook`, включает HMAC-SHA256-подпись запроса.

```
POST /api/notifications/rules
{
  "id": null, "name": "Критические — сразу", "enabled": true, "min_level": "Critical",
  "subnets": [], "profiles": [], "device_ids": [],
  "active_from": null, "active_to": null, "days_of_week": [],
  "notify_on_activate": true, "notify_on_clear": true,
  "recipients": ["<user-uuid>", {"role": "<role-uuid>"}, ...]
}
```

`min_level` — с большой буквы (`"Info"`/`"Warning"`/`"Critical"`) — см. «Базовые
соглашения» выше про регистр enum-значений в теле vs. в query-параметрах.

Пустые все три из `subnets`/`profiles`/`device_ids` — правило действует **на все**
устройства (обратное поведение по сравнению с окнами обслуживания выше). `active_from`/
`active_to` — либо оба заданы, либо оба пусты (`400` на смешанный вариант); время — UTC.
`days_of_week` — подмножество `["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]`.

`recipients` — массив без тега варианта (`#[serde(untagged)]`): голая UUID-строка — id
пользователя, объект `{"role": "<uuid>"}` — целая роль. Роль резолвится в её **текущий**
состав в момент срабатывания тревоги, не в момент сохранения правила. Если один и тот же
пользователь получился в итоговом списке дважды (указан напрямую и одновременно состоит в
указанной роли, или попал под несколько подошедших правил сразу) — уведомление
дедуплицируется, повторно не уходит.

```
PUT /api/settings/notifications
{"smtp_host": "...", "smtp_port": 587, "smtp_username": "...", "smtp_password": "...", "from_address": "...", "telegram_bot_token": "..."}
```

Без настроенного `DISCOVERY_SECRET_KEY` на сервере сохранение пароля/токена завершается
`500`, значение не сохраняется ни в открытом, ни в повреждённом виде. Подробнее — [Уведомления](features/notifications.md).

## Топология (домен `topology`)

| Метод | Путь | Доступ | Описание |
|---|---|---|---|
| GET | `/api/topology/rules` | domain: topology (чтение) | список правил |
| POST | `/api/topology/rules` | domain: topology (запись) | создать/изменить — `id: null` создаёт, `id` существующего — редактирует |
| GET | `/api/topology/rules/:id` | domain: topology (чтение) | одно правило |
| DELETE | `/api/topology/rules/:id` | domain: topology (запись) | удалить |
| GET | `/api/topology/rules/:name/neighbors/:device_id` | domain: topology (чтение) | соседи одного устройства по этому правилу (по имени правила, не `id`) |
| GET | `/api/topology/rules/:name/edges` | domain: topology (чтение) | связи по этому правилу — см. ниже |
| PUT | `/api/topology/rules/:name/hierarchy/:device_a/:device_b` | domain: topology (запись) | вручную задать направление связи — `{"upstream_device_id": "..."}` |
| DELETE | `/api/topology/rules/:name/hierarchy/:device_a/:device_b` | domain: topology (запись) | сбросить ручное направление, вернуться к автоматическому по рангу |

```
{
  "id": null,
  "name": "lldp",
  "enabled": true,
  "my_key_expression": "metrics.lldp_chassis_id",
  "claimed_neighbors_expression": "metrics.lldp_rem_table.map(|row| row.chassis_id)",
  "rank_expression": "facts.role == \"core\" ? 0 : 1",
  "watched_metrics": null
}
```

`claimed_neighbors_expression: null` — правило только группирует устройства по общему
идентификатору, без утверждения о прямой связи. `rank_expression: null` — правило не
участвует в определении направления (кто чей аплинк), см. [Топология](features/topology.md#направление--кто-чей-аплинк).
`GET .../edges` принимает `search` (по IP любого из двух устройств пары),
`status=confirmed|unconfirmed`, `direction=determined|undetermined`,
`sort_by=device_a|device_b|status|direction` (по умолчанию `device_a`), `sort_dir`,
`page`/`page_size` (по умолчанию 50, максимум 500) — возвращает `{"items": [...], "total":
N}`, тот же формат страницы, что у списочных эндпоинтов из «Базовых соглашений» выше.

`watched_metrics: null` — discovery сам определяет, какие метрики упомянуты в выражениях
выше, и пересчитывает правило сразу после их обновления; можно указать список явно, если
имя метрики вычисляется динамически и не видно текстовым разбором. Все три выражения
проверяются на синтаксис при сохранении — некорректное выражение отклоняется сразу, не
сохраняется. Подробнее — [Топология](features/topology.md).

## Групповые тревоги (домен `group_alerts`)

| Метод | Путь | Доступ | Описание |
|---|---|---|---|
| GET | `/api/group-alerts/rules` | domain: group_alerts (чтение) | список правил |
| POST | `/api/group-alerts/rules` | domain: group_alerts (запись) | создать/изменить — `id: null` создаёт, `id` существующего — редактирует |
| GET | `/api/group-alerts/rules/:id` | domain: group_alerts (чтение) | одно правило |
| DELETE | `/api/group-alerts/rules/:id` | domain: group_alerts (запись) | удалить |

```
{
  "id": null,
  "name": "unreachable-cascade",
  "enabled": true,
  "cause_expression": "name == \"device_unreachable\"",
  "effect_expression": "name == \"device_unreachable\""
}
```

`cause_expression` проверяется на тревоге-кандидате на аплинке, `effect_expression` — на
тревоге-кандидате на зависимом устройстве; подавление применяется, только если совпало и
то, и другое. Оба выражения проверяются на синтаксис при сохранении. Требует направления
в топологии (`rank_expression` или ручной override) — без него подавлять нечего.
Подробнее — [Групповые тревоги](features/group-alerts.md).

## Ассистент

Единственный раздел без домена вообще — ни `domain:`, ни `администратор` для основных
ручек. Сам чат — self-service (как личные каналы уведомлений выше): доступен любому
залогиненному пользователю для его собственных разговоров. Настройка провайдера ИИ —
`администратор`, без привязки к какой-либо роли.

| Метод | Путь | Доступ | Описание |
|---|---|---|---|
| GET/POST | `/api/assistant/conversations` | требует сессию (self-service) | свои разговоры — список / создать |
| PUT | `/api/assistant/conversations/:id` | требует сессию, владелец разговора | настройки своего разговора — сейчас `{"auto_approve_writes": true|false}` |
| GET | `/api/assistant/conversations/:id/messages` | требует сессию, владелец разговора | вся история, от старых к новым |
| POST | `/api/assistant/conversations/:id/messages` | требует сессию, владелец разговора | отправить сообщение — см. ниже |
| POST | `/api/assistant/conversations/:id/messages/:mid/confirm` | требует сессию, владелец разговора | выполнить предложенное действие |
| POST | `/api/assistant/conversations/:id/messages/:mid/reject` | требует сессию, владелец разговора | отклонить предложенное действие |
| GET/PUT | `/api/settings/ai-assistant` | администратор | реквизиты провайдера — `{"enabled", "provider", "client_id", "client_secret"}` (GigaChat), `{"enabled", "provider", "openrouter_api_key", "openrouter_model"}` (OpenRouter) либо `{"enabled", "provider", "self_hosted_base_url", "self_hosted_api_key", "self_hosted_model"}` (self-hosted), см. ниже |

Разговор, принадлежащий другому пользователю — `404`, не `403` (чужие id не
подтверждаются даже фактом существования).

```http
PUT /api/assistant/conversations/:id
Content-Type: application/json

{"auto_approve_writes": true}
```

Настройка действует только для этого разговора и возвращает обновлённый объект разговора.
При `true` изменяющие действия, которые не являются необратимыми, выполняются без отдельной
карточки подтверждения, но права текущего пользователя проверяются так же. Опасные или
необратимые действия по-прежнему требуют подтверждения. Значение по умолчанию — `false`.

```
POST /api/assistant/conversations/:id/messages
{"content": "Покажи активные критические тревоги"}
→ 200 {"status": "final" | "awaiting_confirmation", "message": {...}}
```

`status: "final"` — модель ответила текстом, разговор ждёт следующего сообщения.
`status: "awaiting_confirmation"` — модель предложила изменяющее действие (`message.
tool_call: {"name", "arguments"}`), ничего ещё не выполнено — нужно явно вызвать
`.../confirm` или `.../reject` на `message.id`, если для разговора не включён
`auto_approve_writes`. `503`, если администратор ещё не подключил провайдера (текст —
«ИИ-ассистент выключен...», либо «не настроены client_id/client_secret...» для GigaChat /
«не настроены openrouter_api_key/openrouter_model...» для OpenRouter / «не настроены base
URL/модель провайдера ИИ-ассистента (self-hosted)...» для self-hosted, в зависимости от
того, какого поля не хватает у выбранного `provider`).

`provider` в настройках — `"gigachat"`, `"openrouter"` или `"self_hosted"`; поле `enabled`
не помогает, если не заполнены обязательные поля именно выбранного провайдера, — ответ
явно называет, какого поля не хватает. У self-hosted `self_hosted_api_key` — единственное
необязательное поле среди всех трёх провайдеров: сервер без авторизации настраивается без
него, запрос уйдёт без заголовка `Authorization` вовсе.

**Права ассистента внутри разговора — это права того же пользователя, который его
ведёт**, не отдельная привилегия: если у вас нет `domain: alerts (запись)`, просьба
закрыть тревогу через чат так же получит `403 requires write access to alerts`, как и
попытка сделать это напрямую через `POST /api/alerts/:id/close`. Каждое подтверждённое
действие — обычный вызов соответствующей ручки этого справочника и точно так же
попадает в [Журнал](features/journal.md). Подробнее о том, что ассистент умеет и как
работает подтверждение — [Ассистент](features/ai-assistant.md).

## Настройки (домен `settings`)

Плоские категории — каждая своя пара GET/PUT, тело GET и тело PUT одинаковой формы:

| Путь | Тело |
|---|---|
| `/api/settings/poll-intervals` | `{identity_secs, metric_secs, profiles_reload_secs, discovery_schedule_check_secs, metric_history_cleanup_secs, reachability_secs, alert_cleanup_secs, dead_device_cleanup_secs, logs_cleanup_secs, journal_cleanup_secs, trap_ttl_sweep_secs, syslog_ttl_sweep_secs, service_check_secs}` (все — секунды) |
| `/api/settings/alert-retention` | `{"retention_secs": число или null}` (`null` = хранить вечно) |
| `/api/settings/log-retention` | `{"retention_secs": число или null}` |
| `/api/settings/journal-retention` | `{"retention_secs": число или null}` |
| `/api/settings/dead-device-retention` | `{"unreachable_for_secs": число}` (`0` = не удалять) |
| `/api/settings/ping` | `{"timeout_ms": число, "retries": число}` |
| `/api/settings/databases` | `{"databases": [...], "default_database": "имя" или null}` — см. ниже |
| `/api/settings/routing` | объект из 12 ключей (по одному на домен) → имя подключения или `null` (= по умолчанию) |

```
PUT /api/settings/databases
{
  "databases": [{"name": "main", "kind": "postgres"|"mysql"|"sqlite"|"memory"|"clickhouse"|"cassandra", "host": "...", "port": 5432, "database": "...", "username": "...", "password": "...", "file_path": "...", "pool_size": 10}],
  "default_database": "main"
}
```

`kind: "mysql"` — одно слово, без подчёркивания.

`GET/PUT /api/settings/databases` и `/api/settings/routing` **требуют перезапуска
процесса**, чтобы вступить в силу — ответ на `PUT` всегда `{"needs_restart": true}`.
Перезапустить — `POST /api/system/restart` (тоже `domain: settings`, запись).

Все прочие категории настроек применяются на лету, без перезапуска. Подробнее по каждой —
[Настройки](features/settings.md).

## Пользователи и роли (администратор)

Всё под `/api/users*` и `/api/roles*` — только `is_admin = true`, доменные права роли
здесь не участвуют вообще.

| Метод | Путь | Описание |
|---|---|---|
| GET | `/api/users` | список — `[{id, username, is_admin, must_change_password, created_at, role_id, role_name}]` |
| POST | `/api/users` | создать — `{username, password, is_admin?, must_change_password?, role_id?}` |
| DELETE | `/api/users/:id` | удалить |
| PUT | `/api/users/:id/password` | `{"password": "..."}` — сброс без проверки старого пароля (в отличие от self-service `/api/auth/password`) |
| PUT | `/api/users/:id/admin` | `{"is_admin": bool}` |
| PUT | `/api/users/:id/role` | `{"role_id": "uuid" или null}` — `null` снимает роль |
| GET | `/api/roles` | список — `[{id, name, permissions: {"<domain>": "read"\|"write", ...}}]`, домены без записи в `permissions` = нет доступа |
| POST | `/api/roles` | создать — `{"name": "...", "permissions": {"notifications": "write", "devices": "read", ...}}` |
| GET | `/api/roles/:id` | одна роль |
| PUT | `/api/roles/:id` | **полная замена** прав (не merge) — то же тело, что POST |
| DELETE | `/api/roles/:id` | удалить — пользователи на ней остаются без роли, не удаляются |

`permissions`/названия доменов в теле запроса — латинские идентификаторы (`devices`,
`discovery_configs`, `device_metrics`, `maintenance_windows`, `notifications`
и т.д.), не русские подписи из дашборда. Подробнее — [Пользователи](features/users.md).

## Журнал (администратор, только чтение)

| Метод | Путь | Описание |
|---|---|---|
| GET | `/api/journal` | `search`, `domain` (точное совпадение), `username` (точное совпадение), `since`/`until`, `sort_by=ts\|username\|domain\|action` |

Записи создаёт сам сервер (см. «Побочный эффект» выше) — писать в журнал напрямую нельзя,
эндпоинта на запись не существует. Подробнее — [Журнал](features/journal.md).
## Дополнительные operator и alert endpoints

Для активных тревог доступны отдельные операторские состояния:

- POST /api/alerts/:id/acknowledge — подтвердить с сохранением пользователя и времени;
- POST /api/alerts/:id/unacknowledge — снять подтверждение;
- POST /api/alerts/:id/snooze с телом {"until": "2026-09-25T18:00:00Z"} — временно
  подавить activation/recovery;
- POST /api/alerts/:id/unsnooze — снять подавление.

В ответе тревоги могут присутствовать acknowledgement, snooze, escalation и flapping.
В теле правила уведомлений повторная доставка задаётся полями
repeat_after_seconds, repeat_interval_seconds, max_repeats и escalation_levels; нулевые
значения сохраняют исходное поведение только с activation/clear.

Для устройств добавлены:

- POST /api/service-discovery — bounded-проверка SNMP/SSH/HTTP/HTTPS/TCP для IP;
- GET/POST /api/devices/:id/actions и /api/devices/:id/actions/:action — история и запуск
  test, poll-now, rediscover, backup;
- GET/DELETE /api/devices/:id/actions/jobs/:job_id — результат или отмена ожидающего job;
- GET /api/devices/:id/backups и GET /api/devices/:id/backups/:job_id — успешные backup;
- GET /api/devices/:id/backups/:left/diff/:right — bounded unified diff двух backup.

Операторские маршруты требуют права Devices:Write; неуспешный service-discovery не создаёт
устройство, а backup отдаёт только redacted/normalized конфигурацию.

### Расширенные правила тревог

| Метод | Путь | Результат |
|---|---|---|
| GET | `/api/alert-rules/shared` | Доступные общие определения правил |
| POST | `/api/alert-rules/shared` | Создание/изменение `AlertRule`, `204` |
| DELETE | `/api/alert-rules/shared/{name}` | Удаление; `409`, если есть ссылки из профилей |
| GET | `/api/devices/{id}/alert-rules` | Диагностика доступных правил и ключей устройства |
| GET | `/api/alerts/screen` | Доступные, неподтверждённые экранные уведомления |
| POST | `/api/alerts/{id}/actions/{action}` | Операция из предлагаемого правилом списка, `202` и задача |

Операции в пути: `test`, `poll-now`, `rediscover`, `backup`; в `policy` и результате
задачи используется `poll_now`. Связанная задача содержит `alert_id`; её состояние и
результат читаются существующими маршрутами операций устройства. Запуск требует
`alerts:write`, `devices:write` и доступа к правилу.

`AlertRule.policy` задаёт режим, период, границы/историю, событийное окно, эскалацию
реакции, действия, роли и экранные уведомления. `Alert.details` содержит снимок политики,
наблюдаемое и предыдущее значение, границы, источник, восстановление, число событий и
состояние эскалации реакции. Настройка `viewer_roles`/`operator_roles` требует
администратора; чтение и изменение самого инцидента дополнительно проверяют эти роли.
Описание режимов и примеры — в [Тревогах](features/alerts.md).

`NotificationRule.selection` содержит `alert_names`, `row_keys`, `source_metrics`,
`recipient_expression`, `notify_on_escalation`, `notify_on_deescalation`.
