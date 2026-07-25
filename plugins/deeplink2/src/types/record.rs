use serde::{Deserialize, Serialize};
use specta::Type;

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct RecordSearch {
    pub action: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_start_action() {
        let search: RecordSearch = serde_qs::from_str("action=start").unwrap();
        assert_eq!(search.action, "start");
    }

    #[test]
    fn parses_stop_action() {
        let search: RecordSearch = serde_qs::from_str("action=stop").unwrap();
        assert_eq!(search.action, "stop");
    }
}
