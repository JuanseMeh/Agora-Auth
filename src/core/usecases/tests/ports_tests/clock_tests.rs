

//! Tests for Clock port.

use crate::core::usecases::ports::Clock;
use chrono::{DateTime, Utc, TimeZone};

struct MockClock;
impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        Utc.timestamp_opt(1672531200, 0).unwrap()
    }
}

#[test]
fn clock_now_returns_time() {
    let clock = MockClock;
    let now = clock.now();
    assert_eq!(now, Utc.timestamp_opt(1672531200, 0).unwrap());
}
