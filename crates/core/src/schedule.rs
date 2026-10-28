use chrono::{Datelike, NaiveDate, NaiveTime, Timelike};
use serde::{Deserialize, Serialize};

/// When something should fire — shared between discovery-config scheduling
/// (`discovery-config-store::DiscoveryConfig::schedule`) and per-metric poll scheduling
/// (`discovery-dsl::MetricSpec::Detailed::schedule`, added 2026-08-16 as a direct
/// follow-up: "впиши такую же логику в метрики в профиле — опрашивать либо периодично
/// либо по времени/месяцу/дате, аналогично тому как щас в дискаверинге"). Two modes, one
/// switch, just applied to a different "thing to trigger" by each caller:
///
/// - [`Schedule::Calendar`] — months/days-of-month/time-of-day, exactly what discovery's
///   schedule already was before this type existed (months/days_of_month empty = every
///   month/day respectively; `time` is the **server's own local time zone**,
///   `chrono::Local` — not UTC, not a per-config offset, see
///   `discovery_agent::discovery_scan`'s docs for why).
/// - [`Schedule::Periodic`] — fires every `interval_secs`, regardless of calendar
///   position. This is what a plain `interval_secs` field used to be on its own before
///   this type existed (for `MetricSpec`) — folded into this enum instead of kept as a
///   sibling field, specifically to avoid two overlapping ways to say "how often" ever
///   drifting out of sync with each other.
///
/// `#[serde(untagged)]` — no explicit `"mode"` discriminant field. Which variant a given
/// JSON blob is is unambiguous from its shape alone: `Calendar` requires `time`,
/// `Periodic` requires `interval_secs`, and neither variant's required field is optional
/// in the other. This also means an old, pre-this-type stored `Schedule` blob
/// (`{"months":[],"days_of_month":[],"time":"03:00:00"}`, from before `Periodic` existed)
/// still deserializes fine as `Calendar` — free backward compatibility, not something
/// hand-written.
///
/// Deliberately not a full cron expression (no minute-repeat-within-an-hour, no
/// day-of-week, no seconds) — this is exactly "период, либо месяца/даты/время", nothing
/// more, matching what was actually asked for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Schedule {
    Calendar {
        /// 1-12, empty = every month.
        #[serde(default)]
        months: Vec<u32>,
        /// 1-31, empty = every day of the month. A value that doesn't exist in a given
        /// month (e.g. 31 in April) simply never matches that month — not an error.
        #[serde(default)]
        days_of_month: Vec<u32>,
        /// Interpreted in the server's local time zone (`chrono::Local`) — see this
        /// type's docs.
        time: NaiveTime,
    },
    Periodic {
        interval_secs: u64,
    },
}

impl Schedule {
    /// `true` only for a [`Schedule::Calendar`] whose months/days/time-of-day (to the
    /// minute — seconds are ignored, matching a check loop that ticks more often than
    /// once a second) all match. Always `false` for [`Schedule::Periodic`] — periodic
    /// firing is tracked by elapsed time since the last fire, not calendar position;
    /// callers must track that separately (see
    /// `discovery_agent::discovery_scan::run_discovery_schedule_loop` and
    /// `discovery_agent::handlers::MetricPollHandler`, which both hold their own
    /// last-fired state per caller's natural granularity).
    pub fn matches_calendar(&self, date: NaiveDate, hour: u32, minute: u32) -> bool {
        match self {
            Schedule::Calendar {
                months,
                days_of_month,
                time,
            } => {
                let months_match = months.is_empty() || months.contains(&date.month());
                let days_match = days_of_month.is_empty() || days_of_month.contains(&date.day());
                let time_matches = time.hour() == hour && time.minute() == minute;
                months_match && days_match && time_matches
            }
            Schedule::Periodic { .. } => false,
        }
    }

    /// `Some(interval)` only for [`Schedule::Periodic`] — `None` for `Calendar` (there is
    /// no fixed interval; whether it's "due" is a calendar-position question, answered by
    /// [`Self::matches_calendar`] instead).
    pub fn interval_secs(&self) -> Option<u64> {
        match self {
            Schedule::Periodic { interval_secs } => Some(*interval_secs),
            Schedule::Calendar { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calendar(months: Vec<u32>, days: Vec<u32>, hm: (u32, u32)) -> Schedule {
        Schedule::Calendar {
            months,
            days_of_month: days,
            time: NaiveTime::from_hms_opt(hm.0, hm.1, 0).unwrap(),
        }
    }

    #[test]
    fn empty_months_and_days_match_every_day_at_the_configured_time() {
        let s = calendar(vec![], vec![], (3, 0));
        let date = NaiveDate::from_ymd_opt(2026, 7, 15).unwrap();
        assert!(s.matches_calendar(date, 3, 0));
        assert!(
            !s.matches_calendar(date, 3, 1),
            "wrong minute must not match"
        );
        assert!(!s.matches_calendar(date, 4, 0), "wrong hour must not match");
    }

    #[test]
    fn specific_months_and_days_only_match_those() {
        let s = calendar(vec![1, 6], vec![1, 15], (3, 0));
        assert!(s.matches_calendar(NaiveDate::from_ymd_opt(2026, 6, 15).unwrap(), 3, 0));
        assert!(
            !s.matches_calendar(NaiveDate::from_ymd_opt(2026, 7, 15).unwrap(), 3, 0),
            "unlisted month must not match"
        );
        assert!(
            !s.matches_calendar(NaiveDate::from_ymd_opt(2026, 6, 2).unwrap(), 3, 0),
            "unlisted day must not match"
        );
    }

    #[test]
    fn a_day_that_never_occurs_in_the_configured_months_simply_never_fires() {
        let s = calendar(vec![2], vec![31], (3, 0));
        assert!(!s.matches_calendar(NaiveDate::from_ymd_opt(2026, 2, 28).unwrap(), 3, 0));
    }

    #[test]
    fn periodic_never_matches_calendar_and_has_no_calendar_fields() {
        let s = Schedule::Periodic {
            interval_secs: 3600,
        };
        assert!(!s.matches_calendar(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(), 0, 0));
        assert_eq!(s.interval_secs(), Some(3600));
    }

    #[test]
    fn calendar_has_no_interval() {
        let s = calendar(vec![], vec![], (3, 0));
        assert_eq!(s.interval_secs(), None);
    }

    #[test]
    fn calendar_deserializes_without_an_explicit_mode_tag_backward_compat() {
        // The exact shape a pre-`Periodic` stored Schedule blob has — must still parse.
        let json = r#"{"months":[],"days_of_month":[],"time":"03:00:00"}"#;
        let s: Schedule = serde_json::from_str(json).unwrap();
        assert!(matches!(s, Schedule::Calendar { .. }));
    }

    #[test]
    fn periodic_deserializes_from_its_own_shape() {
        let json = r#"{"interval_secs": 60}"#;
        let s: Schedule = serde_json::from_str(json).unwrap();
        assert_eq!(s, Schedule::Periodic { interval_secs: 60 });
    }
}
