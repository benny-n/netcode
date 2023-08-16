use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::NetcodeError;

pub(crate) fn time_now_secs() -> Result<u64, NetcodeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub(crate) fn time_now_secs_f64() -> Result<f64, NetcodeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64())
}
