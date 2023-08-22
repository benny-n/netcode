use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn time_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should not go backwards")
}

pub(crate) fn time_now_secs() -> u64 {
    time_now().as_secs()
}
pub(crate) fn time_now_secs_f64() -> f64 {
    time_now().as_secs_f64()
}
