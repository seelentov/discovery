//! The tool catalog for the AI assistant — each [`ToolDef`] maps one model-callable
//! function onto an existing REST endpoint this crate already serves. Adding a domain is a
//! new [`ToolDef`] entry here, not a change to the orchestration engine in
//! `crate::assistant` that executes them. See `docs/Architecture/AI Assistant.md`.
//!
//! v1 (2026-09-18) covered only Alerts/Devices/MaintenanceWindows/Jobs, direct user
//! request. Extended (2026-09-18, same day, separate follow-up request) to 11 of the 12
//! `discovery_core::Domain`s — every "operational" domain: `DeviceMetrics`, `Profiles`,
//! `Logs`, `Notifications`, `Topology`, `GroupAlerts`, `DiscoveryConfigs`. **Still
//! deliberately excludes `Settings`** (system restart, DB routing/credentials — direct
//! user request to keep system-level operations out of the assistant's reach) **and
//! users/roles** (`/api/users*`/`/api/roles*` — `admin_guard!`-gated, not even a routed
//! `Domain`; account/permission management, same reasoning as `Settings`).
//!
//! [`ToolDef::method`] is not just routing metadata — it's what
//! `crate::assistant::execute_tool_call`/`run_assistant_turn` use to decide whether a call
//! is safe to run immediately (GET/HEAD) or must wait for the user's explicit confirmation
//! (everything else), the exact same rule `require_domain_permission` already uses to
//! decide `AccessLevel::Read` vs `Write`. There is deliberately no separate per-tool
//! "is this dangerous" flag — **with exactly one narrow exception**: the three
//! `DiscoveryConfigs` tools named below, where `crate::assistant::execute_tool_call`
//! special-cases the tool *name* (not a new generic flag on [`ToolDef`]) to redact SNMP
//! credentials from read results and to reject overwriting an existing config by name.
//! See that function's docs for why this one domain needed it and every other one didn't:
//! `DiscoveryConfig`'s subnets carry unredacted SNMP community strings/USM passphrases —
//! unlike every credential this assistant touches elsewhere (GigaChat/SMTP provider
//! secrets), there is no existing "always empty on read" convention for this store to lean
//! on, because the dashboard's own edit form needs the real values.

use axum::http::Method;
use serde_json::{json, Value};

pub struct ToolDef {
    pub name: &'static str,
    pub description: &'static str,
    pub parameters_schema: fn() -> Value,
    pub method: Method,
    /// `{name}` segments are substituted from the model's tool-call arguments by
    /// `crate::assistant::execute_tool_call`; whatever's left over becomes the query string
    /// (GET/HEAD) or JSON body (everything else) of the internal REST sub-request.
    pub path_template: &'static str,
}

fn schema(required: &[&str], properties: Value) -> Value {
    json!({"type": "object", "properties": properties, "required": required})
}

/// The full tool catalog — 11 of 12 domains. See this module's docs for what's excluded
/// and why.
pub fn v1_tools() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "list_alerts",
            description: "Список тревог с поиском/фильтром/пагинацией — активных и снятых.",
            parameters_schema: || {
                schema(
                    &[],
                    json!({
                        "search": {"type": "string", "description": "Свободный текстовый поиск"},
                        "level": {"type": "string", "enum": ["info", "warning", "critical"]},
                        "state": {"type": "string", "enum": ["active", "cleared"]},
                        "page": {"type": "integer", "description": "Номер страницы, с 1"},
                        "page_size": {"type": "integer", "description": "Размер страницы, по умолчанию 50"},
                    }),
                )
            },
            method: Method::GET,
            path_template: "/api/alerts",
        },
        ToolDef {
            name: "get_alert",
            description: "Одна тревога по id, со всеми полями.",
            parameters_schema: || schema(&["id"], json!({"id": {"type": "string", "description": "UUID тревоги"}})),
            method: Method::GET,
            path_template: "/api/alerts/{id}",
        },
        ToolDef {
            name: "close_alert",
            description: "Закрыть тревогу вручную. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["id"], json!({"id": {"type": "string", "description": "UUID тревоги"}})),
            method: Method::POST,
            path_template: "/api/alerts/{id}/close",
        },
        ToolDef {
            name: "comment_alert",
            description: "Добавить свободный комментарий к тревоге. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["id", "text"], json!({"id": {"type": "string"}, "text": {"type": "string", "description": "Текст комментария"}})),
            method: Method::POST,
            path_template: "/api/alerts/{id}/comments",
        },
        ToolDef {
            name: "list_devices",
            description: "Список устройств — поиск/фильтр по профилю/пагинация.",
            parameters_schema: || {
                schema(
                    &[],
                    json!({
                        "search": {"type": "string"},
                        "profile": {"type": "string", "description": "Точное имя профиля"},
                        "has_error": {"type": "boolean", "description": "Только устройства с метрикой в состоянии ошибки"},
                        "page": {"type": "integer"},
                        "page_size": {"type": "integer"},
                    }),
                )
            },
            method: Method::GET,
            path_template: "/api/devices",
        },
        ToolDef {
            name: "get_device",
            description: "Одно устройство по id, со всеми метриками.",
            parameters_schema: || schema(&["id"], json!({"id": {"type": "string", "description": "UUID устройства"}})),
            method: Method::GET,
            path_template: "/api/devices/{id}",
        },
        ToolDef {
            name: "set_device_enabled",
            description: "Включить/выключить мониторинг устройства. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["id", "enabled"], json!({"id": {"type": "string"}, "enabled": {"type": "boolean"}})),
            method: Method::PUT,
            path_template: "/api/devices/{id}/enabled",
        },
        ToolDef {
            name: "sync_device_profile",
            description: "Пересинхронизировать метрики устройства с его текущим профилем. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["id"], json!({"id": {"type": "string"}})),
            method: Method::POST,
            path_template: "/api/devices/{id}/sync-profile",
        },
        ToolDef {
            name: "list_maintenance_windows",
            description: "Список окон обслуживания (подавление тревог на время плановых работ).",
            parameters_schema: || schema(&[], json!({})),
            method: Method::GET,
            path_template: "/api/maintenance-windows",
        },
        ToolDef {
            name: "create_maintenance_window",
            description: "Создать окно обслуживания. Требует подтверждения пользователя перед выполнением. Пустой список profiles означает, что окно ни на что не подействует — почти всегда нужно указать хотя бы один профиль устройств.",
            parameters_schema: || {
                schema(
                    &["name", "enabled", "starts_at", "ends_at"],
                    json!({
                        "name": {"type": "string"},
                        "enabled": {"type": "boolean"},
                        "starts_at": {"type": "string", "description": "ISO-8601, например 2026-09-20T22:00:00Z"},
                        "ends_at": {"type": "string", "description": "ISO-8601"},
                        "profiles": {"type": "array", "items": {"type": "string"}, "description": "Имена профилей устройств, на которые действует окно"},
                    }),
                )
            },
            method: Method::POST,
            path_template: "/api/maintenance-windows",
        },
        ToolDef {
            name: "delete_maintenance_window",
            description: "Удалить окно обслуживания. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["id"], json!({"id": {"type": "string"}})),
            method: Method::DELETE,
            path_template: "/api/maintenance-windows/{id}",
        },
        ToolDef {
            name: "list_queues",
            description: "Статистика по всем очередям фоновой обработки.",
            parameters_schema: || schema(&[], json!({})),
            method: Method::GET,
            path_template: "/api/queues",
        },
        ToolDef {
            name: "set_queue_paused",
            description: "Поставить на паузу или возобновить очередь целиком. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["kind", "paused"], json!({"kind": {"type": "string", "description": "Идентификатор очереди, см. list_queues"}, "paused": {"type": "boolean"}})),
            method: Method::PUT,
            path_template: "/api/queues/{kind}/paused",
        },
        ToolDef {
            name: "list_workers",
            description: "Живая активность фоновых воркеров.",
            parameters_schema: || schema(&[], json!({})),
            method: Method::GET,
            path_template: "/api/workers",
        },
        // ---------------------------------------------------------- DeviceMetrics
        ToolDef {
            name: "get_metric_history",
            description: "История значений одной метрики устройства ('state run' модель — интервалы с одним и тем же значением, не точка на каждый опрос).",
            parameters_schema: || {
                schema(
                    &["id", "name"],
                    json!({
                        "id": {"type": "string", "description": "UUID устройства"},
                        "name": {"type": "string", "description": "Имя метрики, см. get_device"},
                        "since": {"type": "string", "description": "ISO-8601, нижняя граница last_observed_at"},
                        "until": {"type": "string", "description": "ISO-8601, верхняя граница"},
                        "page": {"type": "integer"},
                        "page_size": {"type": "integer"},
                    }),
                )
            },
            method: Method::GET,
            path_template: "/api/devices/{id}/metrics/{name}/history",
        },
        ToolDef {
            name: "set_metric_override",
            description: "Включить/выключить конкретную метрику на конкретном устройстве вручную (не весь мониторинг устройства, см. set_device_enabled). Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["id", "name", "enabled"], json!({"id": {"type": "string"}, "name": {"type": "string"}, "enabled": {"type": "boolean"}})),
            method: Method::PUT,
            path_template: "/api/devices/{id}/metrics/{name}/enabled",
        },
        ToolDef {
            name: "clear_metric_override",
            description: "Снять ручной override с метрики устройства — метрика возвращается под управление профиля. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["id", "name"], json!({"id": {"type": "string"}, "name": {"type": "string"}})),
            method: Method::DELETE,
            path_template: "/api/devices/{id}/metrics/{name}/enabled",
        },
        // ---------------------------------------------------------- Profiles
        ToolDef {
            name: "list_profiles",
            description: "Список профилей устройств — поиск/сортировка/пагинация.",
            parameters_schema: || {
                schema(
                    &[],
                    json!({
                        "search": {"type": "string", "description": "Ищет по имени профиля и по именам опрашиваемых метрик"},
                        "sort_by": {"type": "string", "enum": ["name", "priority"]},
                        "sort_dir": {"type": "string", "enum": ["asc", "desc"]},
                        "page": {"type": "integer"},
                        "page_size": {"type": "integer"},
                    }),
                )
            },
            method: Method::GET,
            path_template: "/api/profiles",
        },
        ToolDef {
            name: "get_profile",
            description: "Один профиль по имени, целиком (match-выражение, опрашиваемые метрики, тревоги).",
            parameters_schema: || schema(&["name"], json!({"name": {"type": "string"}})),
            method: Method::GET,
            path_template: "/api/profiles/{name}",
        },
        ToolDef {
            name: "upsert_profile",
            description: "Создать или полностью заменить профиль устройств по имени (`profile.name`). Требует подтверждения пользователя перед выполнением. `match.expression` — булево Rhai-выражение над `facts`/`metrics` (например `metrics.sys_descr.contains(\"Cisco\")`); `metrics.poll` — карта имя метрики → как и как часто опрашивать; `alerts` — список правил тревог. Не зная точного текущего содержимого профиля — сначала вызови get_profile, отредактируй результат и отправь целиком, иначе рискуешь стереть существующие метрики/тревоги.",
            parameters_schema: || {
                schema(
                    &["profile", "match"],
                    json!({
                        "profile": {"type": "object", "description": "{name: string, priority?: integer — выше пробуется раньше}"},
                        "match": {"type": "object", "description": "{expression: string} — Rhai булево выражение"},
                        "metrics": {"type": "object", "description": "{poll: {имя метрики: спецификация опроса}} — опционально"},
                        "traps": {"type": "object", "description": "SNMP trap bindings — опционально"},
                        "syslog": {"type": "object", "description": "Syslog bindings — опционально"},
                        "service_checks": {"type": "object", "description": "TCP/HTTP(S)/SSH проверки — опционально"},
                        "alerts": {"type": "array", "items": {"type": "object"}, "description": "Правила тревог — опционально"},
                    }),
                )
            },
            method: Method::POST,
            path_template: "/api/profiles",
        },
        ToolDef {
            name: "delete_profile",
            description: "Удалить профиль по имени. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["name"], json!({"name": {"type": "string"}})),
            method: Method::DELETE,
            path_template: "/api/profiles/{name}",
        },
        ToolDef {
            name: "sync_profile_devices",
            description: "Пересинхронизировать метрики всех устройств на этом профиле с его текущим содержимым. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["name"], json!({"name": {"type": "string"}})),
            method: Method::POST,
            path_template: "/api/profiles/{name}/sync-devices",
        },
        // ---------------------------------------------------------- Logs
        ToolDef {
            name: "get_logs",
            description: "Строки серверного лога — фильтр по уровню/источнику/тексту/времени, пагинация.",
            parameters_schema: || {
                schema(
                    &[],
                    json!({
                        "level": {"type": "string", "enum": ["error", "warn", "info", "debug", "trace"], "description": "Этот уровень и хуже"},
                        "target": {"type": "string", "description": "Префикс имени модуля, например discovery_agent"},
                        "search": {"type": "string"},
                        "since": {"type": "string", "description": "ISO-8601"},
                        "until": {"type": "string", "description": "ISO-8601"},
                        "sort_dir": {"type": "string", "enum": ["asc", "desc"], "description": "desc (по умолчанию) — сначала новые"},
                        "page": {"type": "integer"},
                        "page_size": {"type": "integer"},
                    }),
                )
            },
            method: Method::GET,
            path_template: "/api/logs",
        },
        // ---------------------------------------------------------- Notifications
        ToolDef {
            name: "list_notification_rules",
            description: "Список правил матрицы нотификации (кто и когда получает уведомления по тревогам).",
            parameters_schema: || schema(&[], json!({})),
            method: Method::GET,
            path_template: "/api/notifications/rules",
        },
        ToolDef {
            name: "get_notification_rule",
            description: "Одно правило нотификации по id.",
            parameters_schema: || schema(&["id"], json!({"id": {"type": "string"}})),
            method: Method::GET,
            path_template: "/api/notifications/rules/{id}",
        },
        ToolDef {
            name: "upsert_notification_rule",
            description: "Создать или полностью заменить правило нотификации (по `id`, если передан — иначе создаёт новое). Требует подтверждения пользователя перед выполнением. `active_from`/`active_to` — либо оба заданы (окно времени суток), либо ни один.",
            parameters_schema: || {
                schema(
                    &["name", "enabled", "min_level", "notify_on_activate", "notify_on_clear"],
                    json!({
                        "id": {"type": "string", "description": "UUID существующего правила — опустить при создании нового"},
                        "name": {"type": "string"},
                        "enabled": {"type": "boolean"},
                        // PascalCase, unlike `list_alerts`'s `level` filter above — this
                        // one is the request *body*, deserialized straight into
                        // `AlertLevel` (no `#[serde(rename_all)]`, see that type's docs),
                        // not a query-string param parsed by `AlertLevel::from_str`'s
                        // lowercase convention. Found live (TASK-20260921-016): a model
                        // following the old lowercase enum got a 400 on every attempt.
                        "min_level": {"type": "string", "enum": ["Info", "Warning", "Critical"]},
                        "subnets": {"type": "array", "items": {"type": "object", "description": "{ip, mask}"}},
                        "profiles": {"type": "array", "items": {"type": "string"}},
                        "device_ids": {"type": "array", "items": {"type": "string"}},
                        "active_from": {"type": "string", "description": "HH:MM:SS, вместе с active_to"},
                        "active_to": {"type": "string", "description": "HH:MM:SS, вместе с active_from"},
                        "days_of_week": {"type": "array", "items": {"type": "string", "enum": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]}},
                        "notify_on_activate": {"type": "boolean"},
                        "notify_on_clear": {"type": "boolean"},
                        "recipients": {"type": "array", "items": {"type": "string"}, "description": "UUID пользователей, см. list_notification_recipients"},
                    }),
                )
            },
            method: Method::POST,
            path_template: "/api/notifications/rules",
        },
        ToolDef {
            name: "delete_notification_rule",
            description: "Удалить правило нотификации. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["id"], json!({"id": {"type": "string"}})),
            method: Method::DELETE,
            path_template: "/api/notifications/rules/{id}",
        },
        ToolDef {
            name: "list_notification_recipients",
            description: "Список пользователей, которых можно указать получателями в правиле нотификации (id + username).",
            parameters_schema: || schema(&[], json!({})),
            method: Method::GET,
            path_template: "/api/notifications/recipients",
        },
        // ---------------------------------------------------------- Topology
        ToolDef {
            name: "list_topology_rules",
            description: "Список правил извлечения топологии (Rhai-выражения, определяющие ключ устройства и его заявленных соседей).",
            parameters_schema: || schema(&[], json!({})),
            method: Method::GET,
            path_template: "/api/topology/rules",
        },
        ToolDef {
            name: "get_topology_rule",
            description: "Одно правило топологии по id.",
            parameters_schema: || schema(&["id"], json!({"id": {"type": "string"}})),
            method: Method::GET,
            path_template: "/api/topology/rules/{id}",
        },
        ToolDef {
            name: "upsert_topology_rule",
            description: "Создать или полностью заменить правило топологии (по `id`, если передан). Требует подтверждения пользователя перед выполнением. Выражения — Rhai, синтаксически проверяются на сервере перед сохранением.",
            parameters_schema: || {
                schema(
                    &["name", "enabled", "my_key_expression"],
                    json!({
                        "id": {"type": "string", "description": "UUID существующего правила — опустить при создании нового"},
                        "name": {"type": "string"},
                        "enabled": {"type": "boolean"},
                        "my_key_expression": {"type": "string", "description": "Rhai-выражение — идентификатор устройства с точки зрения этого протокола"},
                        "claimed_neighbors_expression": {"type": "string", "description": "Rhai-выражение — список заявленных соседних ключей, опционально"},
                        "rank_expression": {"type": "string", "description": "Rhai-выражение для определения направления связи (upstream/downstream), опционально"},
                        "watched_metrics": {"type": "array", "items": {"type": "string"}, "description": "Какие метрики триггерят пересбор топологии, опционально"},
                    }),
                )
            },
            method: Method::POST,
            path_template: "/api/topology/rules",
        },
        ToolDef {
            name: "delete_topology_rule",
            description: "Удалить правило топологии. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["id"], json!({"id": {"type": "string"}})),
            method: Method::DELETE,
            path_template: "/api/topology/rules/{id}",
        },
        ToolDef {
            name: "get_topology_neighbors",
            description: "Разрешённые соседи одного устройства по одному правилу топологии.",
            parameters_schema: || schema(&["name", "device_id"], json!({"name": {"type": "string", "description": "Имя правила топологии"}, "device_id": {"type": "string"}})),
            method: Method::GET,
            path_template: "/api/topology/rules/{name}/neighbors/{device_id}",
        },
        ToolDef {
            name: "get_topology_edges",
            description: "Все связи (рёбра), разрешённые одним правилом топологии, целиком.",
            parameters_schema: || schema(&["name"], json!({"name": {"type": "string", "description": "Имя правила топологии"}})),
            method: Method::GET,
            path_template: "/api/topology/rules/{name}/edges",
        },
        ToolDef {
            name: "set_topology_hierarchy_override",
            description: "Вручную задать, какая сторона связи между двумя устройствами — upstream (используется, когда rank_expression не может определить направление или дал ничью). Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || {
                schema(
                    &["name", "device_a", "device_b", "upstream_device_id"],
                    json!({
                        "name": {"type": "string", "description": "Имя правила топологии"},
                        "device_a": {"type": "string", "description": "UUID одного из двух устройств связи"},
                        "device_b": {"type": "string", "description": "UUID другого устройства связи"},
                        "upstream_device_id": {"type": "string", "description": "Должен совпадать с device_a или device_b"},
                    }),
                )
            },
            method: Method::PUT,
            path_template: "/api/topology/rules/{name}/hierarchy/{device_a}/{device_b}",
        },
        ToolDef {
            name: "clear_topology_hierarchy_override",
            description: "Снять ручной override направления связи — решение возвращается к rank_expression. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || {
                schema(
                    &["name", "device_a", "device_b"],
                    json!({"name": {"type": "string"}, "device_a": {"type": "string"}, "device_b": {"type": "string"}}),
                )
            },
            method: Method::DELETE,
            path_template: "/api/topology/rules/{name}/hierarchy/{device_a}/{device_b}",
        },
        // ---------------------------------------------------------- GroupAlerts
        ToolDef {
            name: "list_group_alert_rules",
            description: "Список правил группировки тревог (подавление одних тревог другими по причинно-следственной связи, например порт вверх по течению гасит тревоги за ним).",
            parameters_schema: || schema(&[], json!({})),
            method: Method::GET,
            path_template: "/api/group-alerts/rules",
        },
        ToolDef {
            name: "get_group_alert_rule",
            description: "Одно правило группировки тревог по id.",
            parameters_schema: || schema(&["id"], json!({"id": {"type": "string"}})),
            method: Method::GET,
            path_template: "/api/group-alerts/rules/{id}",
        },
        ToolDef {
            name: "upsert_group_alert_rule",
            description: "Создать или полностью заменить правило группировки тревог (по `id`, если передан). Требует подтверждения пользователя перед выполнением. `cause_expression`/`effect_expression` — Rhai-выражения, проверяются на сервере перед сохранением.",
            parameters_schema: || {
                schema(
                    &["name", "enabled", "cause_expression", "effect_expression"],
                    json!({
                        "id": {"type": "string", "description": "UUID существующего правила — опустить при создании нового"},
                        "name": {"type": "string", "description": "Отображаемое имя, без проверки уникальности"},
                        "enabled": {"type": "boolean"},
                        "cause_expression": {"type": "string", "description": "Rhai-выражение — какая тревога считается причиной"},
                        "effect_expression": {"type": "string", "description": "Rhai-выражение — какие тревоги эта причина подавляет"},
                    }),
                )
            },
            method: Method::POST,
            path_template: "/api/group-alerts/rules",
        },
        ToolDef {
            name: "delete_group_alert_rule",
            description: "Удалить правило группировки тревог. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["id"], json!({"id": {"type": "string"}})),
            method: Method::DELETE,
            path_template: "/api/group-alerts/rules/{id}",
        },
        // ---------------------------------------------------------- DiscoveryConfigs
        //
        // These three tools get special handling in `crate::assistant::execute_tool_call`
        // — see this module's docs and that function's for why (unredacted SNMP
        // credentials in `subnets`, no existing "empty on read" convention to lean on).
        ToolDef {
            name: "list_discovery_configs",
            description: "Список конфигов автодискаверинга подсетей — поиск/фильтр/сортировка/пагинация. SNMP-креды подсетей (credentials) скрыты в ответе — их не видно даже для уже настроенных конфигов.",
            parameters_schema: || {
                schema(
                    &[],
                    json!({
                        "search": {"type": "string", "description": "Ищет по имени конфига и по подсетям (ip/mask/label)"},
                        "enabled": {"type": "boolean"},
                        "sort_by": {"type": "string", "enum": ["name", "enabled"]},
                        "sort_dir": {"type": "string", "enum": ["asc", "desc"]},
                        "page": {"type": "integer"},
                        "page_size": {"type": "integer"},
                    }),
                )
            },
            method: Method::GET,
            path_template: "/api/discovery-configs",
        },
        ToolDef {
            name: "get_discovery_config",
            description: "Один конфиг автодискаверинга по имени. SNMP-креды подсетей (credentials) скрыты в ответе.",
            parameters_schema: || schema(&["name"], json!({"name": {"type": "string"}})),
            method: Method::GET,
            path_template: "/api/discovery-configs/{name}",
        },
        ToolDef {
            name: "create_discovery_config",
            description: "Создать НОВЫЙ конфиг автодискаверинга — только создание, не редактирование: если конфиг с таким `name` уже существует, вызов будет отклонён (измените существующий конфиг вручную в дашборде). `schedule` — ровно одна из двух форм: {\"interval_secs\": число} (периодически) или {\"months\": [1-12], \"days_of_month\": [1-31], \"time\": \"HH:MM:SS\"} (пустые months/days_of_month = каждый месяц/день). Каждый элемент `subnets` может включать `credentials` (SNMP community/USM) — это единственный способ задать их через ассистента, доступный только при создании. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || {
                schema(
                    &["name", "schedule"],
                    json!({
                        "name": {"type": "string"},
                        "enabled": {"type": "boolean", "description": "По умолчанию true"},
                        "schedule": {"type": "object", "description": "{interval_secs: integer} ИЛИ {months: [integer], days_of_month: [integer], time: \"HH:MM:SS\"}"},
                        "subnets": {
                            "type": "array",
                            "items": {"type": "object", "description": "{ip, mask, port?(161), credentials?: [{...SNMP community/USM}], oids?: {...}}"},
                        },
                    }),
                )
            },
            method: Method::POST,
            path_template: "/api/discovery-configs",
        },
        ToolDef {
            name: "delete_discovery_config",
            description: "Удалить конфиг автодискаверинга. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["name"], json!({"name": {"type": "string"}})),
            method: Method::DELETE,
            path_template: "/api/discovery-configs/{name}",
        },
        ToolDef {
            name: "run_discovery_config_now",
            description: "Запустить дискаверинг по конфигу немедленно, не дожидаясь расписания. Требует подтверждения пользователя перед выполнением.",
            parameters_schema: || schema(&["name"], json!({"name": {"type": "string"}})),
            method: Method::POST,
            path_template: "/api/discovery-configs/{name}/run",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_name_is_unique() {
        let tools = v1_tools();
        let mut names: Vec<&str> = tools.iter().map(|t| t.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            tools.len(),
            "duplicate tool name in v1_tools()"
        );
    }

    #[test]
    fn every_schema_builds_a_valid_object_shape() {
        for tool in v1_tools() {
            let schema = (tool.parameters_schema)();
            assert_eq!(
                schema["type"], "object",
                "tool '{}' schema must be a JSON-schema object",
                tool.name
            );
            assert!(
                schema["properties"].is_object(),
                "tool '{}' schema missing properties",
                tool.name
            );
        }
    }

    #[test]
    fn every_path_placeholder_has_a_matching_required_or_documented_property() {
        for tool in v1_tools() {
            let schema = (tool.parameters_schema)();
            let props = schema["properties"].as_object().unwrap();
            for segment in tool.path_template.split('/') {
                if let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                    assert!(props.contains_key(name), "tool '{}' path template references '{{{name}}}' but its schema doesn't document that property", tool.name);
                }
            }
        }
    }
}
