use chrono::DateTime;

use crate::core::crypto::MsSinceEpoch;

impl<T: chrono::TimeZone> From<DateTime<T>> for MsSinceEpoch {
    fn from(value: DateTime<T>) -> Self {
        Self(value.timestamp_millis())
    }
}