use serde::{Deserialize, Serialize};

/// Sort direction for any paginated/sortable list view across this project — job records
/// (`discovery_queue::JobListQuery`), alerts (`discovery_alerts::AlertListQuery`), and
/// anywhere else a "page N of M, sorted by X asc/desc" view exists. Lives here (not in
/// whichever crate first needed it) because it's genuinely generic — moved out of
/// `discovery-queue` 2026-08-17 once `discovery-alerts` needed the exact same type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortDir {
    Asc,
    Desc,
}

impl SortDir {
    /// The literal SQL keyword — safe to interpolate directly into a query string (not a
    /// user-supplied value, always one of these two fixed variants).
    pub fn as_sql(&self) -> &'static str {
        match self {
            SortDir::Asc => "ASC",
            SortDir::Desc => "DESC",
        }
    }
}
