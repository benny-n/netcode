use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn time_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should not go backwards")
        .as_secs()
}
pub(crate) fn time_now_secs_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should not go backwards")
        .as_secs_f64()
}
