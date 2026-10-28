use super::*;
use discovery_core::{AlertLifecycle, AlertPolicy};
use discovery_dsl::AlertRule;

pub(crate) fn permits(policy: &AlertPolicy, user: &AuthenticatedUser, write: bool) -> bool {
    if user.is_admin {
        return true;
    }
    let viewers = &policy.viewer_roles;
    let operators = &policy.operator_roles;
    (viewers.is_empty() || user.role_id.is_some_and(|id| viewers.contains(&id)))
        && (!write
            || operators.is_empty()
            || user.role_id.is_some_and(|id| operators.contains(&id)))
}

pub(crate) fn require_profile_rule_access(
    state: &DashboardState,
    profile: &ProfileFile,
    user: &AuthenticatedUser,
) -> Result<(), ApiError> {
    for rule in &profile.alerts {
        let shared = rule
            .policy
            .shared_rule
            .as_ref()
            .and_then(|name| state.alerts.shared_rule(name));
        let policy = match shared {
            Some(value) => {
                serde_json::from_value::<AlertRule>(value)
                    .map_err(|e| internal_error(e.into()))?
                    .policy
            }
            None => rule.policy.clone(),
        };
        if !permits(&policy, user, true) {
            return Err((
                StatusCode::FORBIDDEN,
                "profile contains an inaccessible alert rule".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn current_policy(
    state: &DashboardState,
    alert: &Alert,
) -> Result<AlertPolicy, ApiError> {
    if let Some(device) = state
        .devices
        .get_device(alert.device_id)
        .await
        .map_err(internal_error)?
    {
        if let Some(profile) = match device.profile {
            Some(name) => state.matcher.profile_by_name(&name).await,
            None => None,
        } {
            if let Some(rule) = profile.alerts.iter().find(|r| {
                r.name == alert.name
                    || alert.name.strip_suffix(".flapping") == Some(r.name.as_str())
            }) {
                if let Some(shared) = &rule.policy.shared_rule {
                    if let Some(value) = state.alerts.shared_rule(shared) {
                        let rule: AlertRule =
                            serde_json::from_value(value).map_err(|e| internal_error(e.into()))?;
                        return Ok(rule.policy);
                    }
                }
                return Ok(rule.policy.clone());
            }
        }
    }
    Ok(alert.details.policy.clone())
}

pub(crate) async fn require_alert_access(
    state: &DashboardState,
    alert: &Alert,
    user: &AuthenticatedUser,
    write: bool,
) -> Result<(), ApiError> {
    if !permits(&current_policy(state, alert).await?, user, write) {
        return Err((StatusCode::FORBIDDEN, "alert rule access denied".into()));
    }
    Ok(())
}

pub(crate) async fn visible_page(
    state: &DashboardState,
    query: &AlertListQuery,
    user: &AuthenticatedUser,
) -> Result<AlertListPage, ApiError> {
    if user.is_admin {
        return state.alert_store.list(query).await.map_err(internal_error);
    }
    let mut scan = query.clone();
    scan.limit = 500;
    scan.offset = 0;
    let mut visible = 0i64;
    let mut items = Vec::new();
    let mut policies = HashMap::<(Uuid, String), AlertPolicy>::new();
    loop {
        let page = state
            .alert_store
            .list(&scan)
            .await
            .map_err(internal_error)?;
        if page.items.is_empty() {
            break;
        }
        let count = page.items.len() as i64;
        for alert in page.items {
            let key = (alert.device_id, alert.name.clone());
            let policy = if let Some(p) = policies.get(&key) {
                p.clone()
            } else {
                let p = current_policy(state, &alert).await?;
                policies.insert(key, p.clone());
                p
            };
            if !permits(&policy, user, false) {
                continue;
            }
            if visible >= query.offset && items.len() < (query.limit.max(0) as usize) {
                items.push(alert);
            }
            visible += 1;
        }
        scan.offset += count;
        if scan.offset >= page.total {
            break;
        }
    }
    Ok(AlertListPage {
        items,
        total: visible,
    })
}

pub(crate) async fn shared_rules(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AlertRule>>, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    let rules = state
        .alert_store
        .shared_rules()
        .await
        .map_err(internal_error)?;
    let mut result = Vec::new();
    for (_, value) in rules {
        let rule: AlertRule =
            serde_json::from_value(value).map_err(|e| internal_error(e.into()))?;
        if permits(&rule.policy, &user, false) {
            result.push(rule);
        }
    }
    Ok(Json(result))
}

pub(crate) fn validate_authoring(
    rule: &AlertRule,
    user: &AuthenticatedUser,
) -> Result<(), ApiError> {
    discovery_dsl::AlertEvaluator::new()
        .validate_rule(rule)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("alerts[\"{}\"]: {e}", rule.name),
            )
        })?;
    if !rule.policy.actions.is_empty() && !user.can(Domain::Devices, AccessLevel::Write) {
        return Err((
            StatusCode::FORBIDDEN,
            "automatic device actions require Devices:Write".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn save_shared_rule(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Json(rule): Json<AlertRule>,
) -> Result<StatusCode, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    validate_authoring(&rule, &user)?;
    if rule.name.trim().is_empty() || rule.name.len() > 128 || rule.policy.shared_rule.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "shared rule requires a name and cannot reference another shared rule".into(),
        ));
    }
    let existing = state
        .alert_store
        .shared_rules()
        .await
        .map_err(internal_error)?;
    if !existing.contains_key(&rule.name) && existing.len() >= 1000 {
        return Err((StatusCode::CONFLICT, "shared rule limit reached".into()));
    }
    let before = existing
        .get(&rule.name)
        .cloned()
        .map(serde_json::from_value::<AlertRule>)
        .transpose()
        .map_err(|e| internal_error(e.into()))?;
    if before
        .as_ref()
        .is_some_and(|r| !permits(&r.policy, &user, true))
    {
        return Err((StatusCode::FORBIDDEN, "shared rule access denied".into()));
    }
    let roles_changed = before.as_ref().is_none_or(|r| {
        r.policy.viewer_roles != rule.policy.viewer_roles
            || r.policy.operator_roles != rule.policy.operator_roles
    });
    if !user.is_admin
        && roles_changed
        && (!rule.policy.viewer_roles.is_empty()
            || !rule.policy.operator_roles.is_empty()
            || before.as_ref().is_some_and(|r| {
                !r.policy.viewer_roles.is_empty() || !r.policy.operator_roles.is_empty()
            }))
    {
        return Err((
            StatusCode::FORBIDDEN,
            "rule permissions require an administrator".into(),
        ));
    }
    state
        .alert_store
        .save_shared_rule(
            &rule.name,
            serde_json::to_value(&rule).map_err(|e| internal_error(e.into()))?,
        )
        .await
        .map_err(internal_error)?;
    state.alerts.replace_shared_rules(
        state
            .alert_store
            .shared_rules()
            .await
            .map_err(internal_error)?,
    );
    nudge_devices(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn delete_shared_rule(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    let rules = state
        .alert_store
        .shared_rules()
        .await
        .map_err(internal_error)?;
    let rule: AlertRule = serde_json::from_value(
        rules
            .get(&name)
            .cloned()
            .ok_or((StatusCode::NOT_FOUND, "no such shared rule".into()))?,
    )
    .map_err(|e| internal_error(e.into()))?;
    if !permits(&rule.policy, &user, true) {
        return Err((StatusCode::FORBIDDEN, "shared rule access denied".into()));
    }
    if state
        .profiles
        .load_all()
        .await
        .map_err(internal_error)?
        .iter()
        .any(|p| {
            p.alerts
                .iter()
                .any(|r| r.policy.shared_rule.as_deref() == Some(&name))
        })
    {
        return Err((
            StatusCode::CONFLICT,
            "shared rule is referenced by a profile".into(),
        ));
    }
    state
        .alert_store
        .delete_shared_rule(&name)
        .await
        .map_err(internal_error)?;
    state.alerts.replace_shared_rules(
        state
            .alert_store
            .shared_rules()
            .await
            .map_err(internal_error)?,
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn nudge_devices(state: &DashboardState) -> Result<(), ApiError> {
    let mut offset = 0;
    loop {
        let page = state
            .devices
            .list_devices(&discovery_devices::DeviceListQuery {
                limit: 500,
                offset,
                ..Default::default()
            })
            .await
            .map_err(internal_error)?;
        if page.items.is_empty() {
            break;
        }
        for device in &page.items {
            state
                .store
                .enqueue(
                    QueueKind::AlertEval,
                    serde_json::json!({"device_id":device.id}),
                    Some(&device.id.to_string()),
                )
                .await
                .map_err(internal_error)?;
        }
        offset += page.items.len() as i64;
        if offset >= page.total {
            break;
        }
    }
    Ok(())
}

pub(crate) async fn rule_statuses(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    let device = state
        .devices
        .get_device(id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "no such device".into()))?;
    let profile = match device.profile {
        Some(name) => state.matcher.profile_by_name(&name).await,
        None => None,
    };
    let mut result = Vec::new();
    for status in state.alerts.rule_statuses(id) {
        let mut policy = profile
            .as_ref()
            .and_then(|p| p.alerts.iter().find(|r| r.name == status.name))
            .map(|r| r.policy.clone())
            .unwrap_or_default();
        if let Some(name) = &policy.shared_rule {
            if let Some(value) = state.alerts.shared_rule(name) {
                let r: AlertRule =
                    serde_json::from_value(value).map_err(|e| internal_error(e.into()))?;
                policy = r.policy;
            }
        }
        if permits(&policy, &user, false) {
            let mut value = serde_json::to_value(status).map_err(|e| internal_error(e.into()))?;
            if let Some(fields) = value.as_object_mut() {
                for internal in [
                    "processed_events",
                    "event_times",
                    "signature",
                    "event_since",
                ] {
                    fields.remove(internal);
                }
            }
            result.push(value);
        }
    }
    Ok(Json(result))
}

pub(crate) async fn enqueue_interactive_action(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path((id, action)): Path<(Uuid, String)>,
) -> Result<axum::response::Response, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    if !user.can(Domain::Devices, AccessLevel::Write) {
        return Err((
            StatusCode::FORBIDDEN,
            "device action requires Devices:Write".into(),
        ));
    }
    let alert = state
        .alert_store
        .get(id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "no such alert".into()))?;
    require_alert_access(&state, &alert, &user, true).await?;
    let action = OperatorAction::from_str(&action)
        .ok_or((StatusCode::BAD_REQUEST, "unknown action".into()))?;
    let policy = current_policy(&state, &alert).await?;
    if !policy.interactive_actions.contains(&action) {
        return Err((
            StatusCode::FORBIDDEN,
            "action is not offered by this rule".into(),
        ));
    }
    enqueue_checked_device_action(&state, alert.device_id, action, user.username, Some(id)).await
}

pub(crate) async fn lifecycle_actions(
    state: &DashboardState,
    alert: &Alert,
    on: AlertLifecycle,
    username: &str,
) -> Result<(), ApiError> {
    let actions = discovery_dsl::AlertEvaluator::new()
        .applicable_actions(alert, on)
        .map_err(|e| internal_error(e.into()))?;
    for action in actions {
        discovery_queue::enqueue_alert_action(state.store.as_ref(), alert, action, username, on)
            .await
            .map_err(internal_error)?;
    }
    Ok(())
}

pub(crate) async fn screen_alerts(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Alert>>, ApiError> {
    let user = authenticate_request(&state, &headers).await?;
    let mut query = AlertListQuery {
        limit: 500,
        screen_only: true,
        sort_by: AlertSortBy::FirstSeen,
        sort_dir: SortDir::Desc,
        ..Default::default()
    };
    let now = chrono::Utc::now();
    let mut notices = Vec::new();
    loop {
        let page = state
            .alert_store
            .list(&query)
            .await
            .map_err(internal_error)?;
        let count = page.items.len() as i64;
        for mut alert in page.items {
            if alert.acknowledged_at.is_some()
                || alert.notifications_snoozed_at(now)
                || alert.flapping
                || alert.suppressed_by_alert_id.is_some()
            {
                continue;
            }
            let policy = current_policy(&state, &alert).await?;
            if !policy.screen_notification || !permits(&policy, &user, false) {
                continue;
            }
            if alert.state != AlertState::Active && !policy.acknowledge_required {
                continue;
            }
            if !policy.acknowledge_required
                && policy.notification_lifetime_seconds.is_some_and(|seconds| {
                    now - alert.first_seen >= chrono::Duration::seconds(seconds as i64)
                })
            {
                continue;
            }
            alert.details.policy = policy;
            notices.push(alert);
        }
        query.offset += count;
        if count == 0 || query.offset >= page.total {
            break;
        }
    }
    Ok(Json(notices))
}
