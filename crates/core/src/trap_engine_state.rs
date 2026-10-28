use serde::{Deserialize, Serialize};

/// Durable state for the SNMPv3 authoritative engine identity `discovery-agent`'s trap
/// listener presents to devices sending v3 traps/informs — SNMP Trap ingestion,
/// 2026-08-30. `discovery-snmp::AuthoritativeEngine::install`/`restart` need exactly these
/// two fields loaded before the engine is usable across a process restart (a fresh
/// `engine_id` on every restart would make every v3 device re-run engine discovery, and a
/// non-monotonic `engine_boots` breaks USM's replay-protection guarantee) — this is what
/// `discovery-agent` reads/writes via `SettingsStore::get_trap_engine_state`/
/// `set_trap_engine_state` to bridge that into the DB-backed settings this project already
/// uses for everything else live-editable/persistent, rather than a bespoke file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrapEngineState {
    pub engine_id: Vec<u8>,
    pub engine_boots: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_json() {
        let original = TrapEngineState {
            engine_id: vec![1, 2, 3, 4],
            engine_boots: 7,
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: TrapEngineState = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }
}
