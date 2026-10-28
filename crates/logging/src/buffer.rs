use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::Serialize;

/// One captured log event, as shown on the dashboard's "Логи" view.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    /// "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR"
    pub level: String,
    /// The tracing target — usually a module path, e.g. `discovery_agent::handlers`.
    /// Coarser than "which queue" (several handlers share a module), but combined with
    /// `fields` (which often carries `queue`, `worker`, `device_id`, `ip`, ...) it's
    /// enough to tell what an entry is about.
    pub target: String,
    pub message: String,
    /// Every other structured field on the event, flattened to strings — the dashboard
    /// only needs to display them, not query them.
    pub fields: BTreeMap<String, String>,
}

/// Bounded in-memory ring buffer of recent log entries. Oldest entries are dropped once
/// `capacity` is reached — this is a live tail for the dashboard, not a durable record
/// (that's what the file sink configured in `discovery-agent` is for; the buffer resets
/// on every restart same as everything else in-memory).
pub struct LogBuffer {
    capacity: usize,
    entries: Mutex<VecDeque<LogEntry>>,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
        }
    }

    pub fn push(&self, entry: LogEntry) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Most recent entries first. `min_level` keeps entries at that severity *or worse*
    /// (e.g. `"info"` keeps INFO/WARN/ERROR, drops DEBUG/TRACE — the usual log-level
    /// convention). `target_prefix` keeps only entries whose target starts with it.
    /// `search`, if given, keeps only entries whose `message` or `target` contains it
    /// (case-insensitive) — added 2026-08-17, direct user request (dashboard pagination/
    /// search/sort/filter pass). Returns *every* matching entry, not just a page of
    /// them — the buffer itself is already bounded (`capacity`, typically ~1000), so
    /// "return everything that matches" is cheap; slicing out a page (and the total match
    /// count for pagination controls) is the caller's job now, not this method's — see
    /// `discovery-web::logs`'s docs for why (paging here would need a `limit` *and* an
    /// `offset` plus a way to report the pre-slice total, which the caller can do just as
    /// well over the already-filtered `Vec` this returns).
    #[allow(clippy::too_many_arguments)]
    pub fn snapshot(
        &self,
        min_level: Option<&str>,
        target_prefix: Option<&str>,
        search: Option<&str>,
        since: Option<chrono::DateTime<chrono::Utc>>,
        until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Vec<LogEntry> {
        let min_rank = min_level.map(level_rank);
        let needle = search.map(str::to_lowercase);
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .rev()
            .filter(|e| min_rank.map_or(true, |min| level_rank(&e.level) <= min))
            .filter(|e| target_prefix.map_or(true, |p| e.target.starts_with(p)))
            .filter(|e| {
                needle.as_deref().map_or(true, |n| {
                    e.message.to_lowercase().contains(n) || e.target.to_lowercase().contains(n)
                })
            })
            .filter(|e| since.map_or(true, |s| e.timestamp >= s))
            .filter(|e| until.map_or(true, |u| e.timestamp <= u))
            .cloned()
            .collect()
    }
}

/// Lower rank = more severe. `FATAL` outranks `ERROR` — see `crate::fatal!` for what
/// actually produces it (there's no real `tracing::Level::FATAL`). Unknown level strings
/// sort as the least severe, so an unrecognized `min_level` filter value just shows
/// everything rather than hiding everything — a wrong filter value should never silently
/// suppress real logs.
fn level_rank(level: &str) -> u8 {
    match level.to_ascii_uppercase().as_str() {
        "FATAL" => 0,
        "ERROR" => 1,
        "WARN" => 2,
        "INFO" => 3,
        "DEBUG" => 4,
        "TRACE" => 5,
        _ => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(level: &str, target: &str, message: &str) -> LogEntry {
        LogEntry {
            timestamp: Utc::now(),
            level: level.into(),
            target: target.into(),
            message: message.into(),
            fields: BTreeMap::new(),
        }
    }

    #[test]
    fn evicts_oldest_once_capacity_is_reached() {
        let buffer = LogBuffer::new(2);
        buffer.push(entry("INFO", "a", "first"));
        buffer.push(entry("INFO", "a", "second"));
        buffer.push(entry("INFO", "a", "third"));

        let snap = buffer.snapshot(None, None, None, None, None);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].message, "third", "newest first");
        assert_eq!(snap[1].message, "second");
    }

    #[test]
    fn min_level_keeps_that_severity_and_worse() {
        let buffer = LogBuffer::new(10);
        buffer.push(entry("DEBUG", "a", "debug msg"));
        buffer.push(entry("INFO", "a", "info msg"));
        buffer.push(entry("WARN", "a", "warn msg"));
        buffer.push(entry("ERROR", "a", "error msg"));

        let snap = buffer.snapshot(Some("info"), None, None, None, None);
        let messages: Vec<&str> = snap.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(
            messages,
            vec!["error msg", "warn msg", "info msg"],
            "debug must be excluded by an info floor"
        );
    }

    #[test]
    fn fatal_outranks_error() {
        let buffer = LogBuffer::new(10);
        buffer.push(entry("ERROR", "a", "regular error"));
        buffer.push(entry("FATAL", "a", "fatal error"));

        // Filtering at "error" must still include fatals (they're worse, not excluded).
        let at_error = buffer.snapshot(Some("error"), None, None, None, None);
        assert_eq!(at_error.len(), 2);

        // Filtering at "fatal" must exclude the plain error.
        let at_fatal = buffer.snapshot(Some("fatal"), None, None, None, None);
        assert_eq!(at_fatal.len(), 1);
        assert_eq!(at_fatal[0].message, "fatal error");
    }

    #[test]
    fn target_prefix_filters_by_module() {
        let buffer = LogBuffer::new(10);
        buffer.push(entry("INFO", "discovery_agent::handlers", "a"));
        buffer.push(entry("INFO", "discovery_queue::worker", "b"));

        let snap = buffer.snapshot(None, Some("discovery_queue"), None, None, None);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].message, "b");
    }

    #[test]
    fn search_matches_message_case_insensitively() {
        let buffer = LogBuffer::new(10);
        buffer.push(entry("INFO", "a", "Device 10.0.0.1 unreachable"));
        buffer.push(entry("INFO", "a", "profile applied"));

        let snap = buffer.snapshot(None, None, Some("unreachable"), None, None);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].message, "Device 10.0.0.1 unreachable");

        // Case-insensitive — the stored message has a capital "D", the search doesn't.
        let snap_lower = buffer.snapshot(None, None, Some("device"), None, None);
        assert_eq!(snap_lower.len(), 1);
    }

    #[test]
    fn search_also_matches_target_not_just_message() {
        let buffer = LogBuffer::new(10);
        buffer.push(entry("INFO", "discovery_agent::handlers", "a"));
        buffer.push(entry("INFO", "discovery_queue::worker", "b"));

        let snap = buffer.snapshot(None, None, Some("queue"), None, None);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].message, "b");
    }

    #[test]
    fn unrecognized_level_filter_shows_everything_rather_than_nothing() {
        let buffer = LogBuffer::new(10);
        buffer.push(entry("INFO", "a", "x"));
        let snap = buffer.snapshot(Some("not-a-real-level"), None, None, None, None);
        assert_eq!(
            snap.len(),
            1,
            "a malformed filter value must fail open, not silently hide real logs"
        );
    }
}
