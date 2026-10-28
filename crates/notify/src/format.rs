use discovery_core::{Alert, AlertState, NotificationTrigger};

/// Renders one `(subject, body)` pair for a notification — shared by the email and
/// Telegram senders (both need human-readable text; the webhook sender doesn't call this at
/// all, it ships the alert as structured JSON instead — see `crate::real::RealNotifier`'s
/// docs). Plain `format!`, no new DSL: `alert.message` is already the fully-rendered text
/// `discovery_dsl::AlertRule`'s own Rhai `message` template produced at activation time —
/// this only wraps it with "what happened" framing.
pub fn format_alert_notification(alert: &Alert, trigger: NotificationTrigger) -> (String, String) {
    let verb = match trigger {
        NotificationTrigger::Activated => "АКТИВНА",
        NotificationTrigger::Cleared => "ЗАКРЫТА",
        NotificationTrigger::Repeated => "ПОВТОР",
        NotificationTrigger::Escalated => "ЭСКАЛАЦИЯ",
        NotificationTrigger::Deescalated => "ДЕЭСКАЛАЦИЯ",
    };
    let subject = format!(
        "[{}] {} — {} на {}",
        level_ru(alert),
        verb,
        alert.name,
        alert.device_ip
    );

    let mut body = format!(
        "Тревога {}: {}\nУстройство: {}\nПравило: {}\n",
        verb, alert.message, alert.device_ip, alert.name
    );
    if let Some(row_key) = &alert.row_key {
        body.push_str(&format!("Строка: {row_key}\n"));
    }
    body.push_str(&format!(
        "Впервые замечена: {}\n",
        alert.first_seen.to_rfc3339()
    ));
    match (&alert.state, alert.cleared_at) {
        (AlertState::Cleared, Some(cleared_at)) => {
            body.push_str(&format!("Закрыта: {}\n", cleared_at.to_rfc3339()))
        }
        _ => body.push_str(&format!(
            "Последний раз замечена: {}\n",
            alert.last_seen.to_rfc3339()
        )),
    }

    (subject, body)
}

fn level_ru(alert: &Alert) -> &'static str {
    match alert.level {
        discovery_core::AlertLevel::Info => "Инфо",
        discovery_core::AlertLevel::Warning => "Внимание",
        discovery_core::AlertLevel::Critical => "Критично",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_core::{AlertLevel, AlertState};
    use uuid::Uuid;

    fn alert() -> Alert {
        Alert {
            details: Default::default(),
            id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            device_ip: "10.0.0.5".to_string(),
            name: "high_cpu".to_string(),
            row_key: None,
            level: AlertLevel::Critical,
            message: "CPU 97%".to_string(),
            state: AlertState::Active,
            facts: None,
            first_seen: "2026-09-10T08:00:00Z".parse().unwrap(),
            last_seen: "2026-09-10T08:05:00Z".parse().unwrap(),
            cleared_at: None,
            closed_by: None,
            acknowledged_by: None,
            acknowledged_at: None,
            snoozed_until: None,
            snoozed_by: None,
            auto_clear_reason: None,
            repeat_count: 0,
            escalation_level: 0,
            repeated_at: None,
            escalation_reason: None,
            flapping: false,
            suppression_reason: None,
            comment_count: 0,
            suppressed_by_alert_id: None,
            reopened_from_alert_id: None,
        }
    }

    #[test]
    fn activated_subject_and_body_mention_the_device_and_message() {
        let (subject, body) = format_alert_notification(&alert(), NotificationTrigger::Activated);
        assert!(subject.contains("10.0.0.5"));
        assert!(subject.contains("high_cpu"));
        assert!(subject.contains("Критично"));
        assert!(body.contains("CPU 97%"));
        assert!(body.contains("Последний раз замечена"));
        assert!(!body.contains("Закрыта:"));
    }

    #[test]
    fn cleared_body_shows_cleared_at_not_last_seen() {
        let mut a = alert();
        a.state = AlertState::Cleared;
        a.cleared_at = Some("2026-09-10T09:00:00Z".parse().unwrap());
        let (_, body) = format_alert_notification(&a, NotificationTrigger::Cleared);
        assert!(body.contains("Закрыта: 2026-09-10T09:00:00+00:00"));
        assert!(!body.contains("Последний раз замечена"));
    }

    #[test]
    fn row_scoped_alert_mentions_its_row_key() {
        let mut a = alert();
        a.row_key = Some("Gi0/1".to_string());
        let (_, body) = format_alert_notification(&a, NotificationTrigger::Activated);
        assert!(body.contains("Строка: Gi0/1"));
    }
}
