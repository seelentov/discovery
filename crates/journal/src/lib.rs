//! `discovery-journal` — the "Журнал" audit trail. See [`JournalStore`]'s docs.

mod sea_orm_store;
mod store;

pub use sea_orm_store::SeaOrmJournalStore;
pub use store::{JournalEntry, JournalListPage, JournalListQuery, JournalSortBy, JournalStore};
