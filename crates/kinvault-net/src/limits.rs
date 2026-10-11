//! Bandwidth and time-of-day limits, applied by hosts to incoming uploads and
//! by senders to their own outgoing traffic.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::Instant;

/// A daily window in local time, e.g. `01:00-07:00`. May wrap past midnight
/// (`22:00-06:00`); equal start and end means all day.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TimeWindow {
    start_min: u16,
    end_min: u16,
}

const DAY_MIN: u16 = 24 * 60;

impl TimeWindow {
    pub fn new(start_min: u16, end_min: u16) -> Option<Self> {
        (start_min < DAY_MIN && end_min < DAY_MIN).then_some(Self { start_min, end_min })
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let bad = || format!("invalid time window {s:?}; expected e.g. 01:00-07:00");
        let (a, b) = s.trim().split_once('-').ok_or_else(bad)?;
        let parse_hm = |t: &str| -> Option<u16> {
            let (h, m) = t.trim().split_once(':')?;
            let (h, m): (u16, u16) = (h.parse().ok()?, m.parse().ok()?);
            (h < 24 && m < 60).then_some(h * 60 + m)
        };
        Self::new(parse_hm(a).ok_or_else(bad)?, parse_hm(b).ok_or_else(bad)?).ok_or_else(bad)
    }

    pub fn contains_minute(&self, minute: u16) -> bool {
        match self.start_min.cmp(&self.end_min) {
            std::cmp::Ordering::Equal => true,
            std::cmp::Ordering::Less => minute >= self.start_min && minute < self.end_min,
            std::cmp::Ordering::Greater => minute >= self.start_min || minute < self.end_min,
        }
    }

    /// Time until the window next opens from `now` (seconds since local midnight);
    /// zero if it is open.
    pub fn until_open_from(&self, now_secs: u32) -> Duration {
        let minute = (now_secs / 60) as u16;
        if self.contains_minute(minute) {
            return Duration::ZERO;
        }
        let start = self.start_min as u32 * 60;
        let wait = (start + DAY_MIN as u32 * 60 - now_secs) % (DAY_MIN as u32 * 60);
        Duration::from_secs(wait as u64)
    }

    pub fn is_open_now(&self) -> bool {
        self.until_open().is_zero()
    }

    pub fn until_open(&self) -> Duration {
        self.until_open_from(local_secs_of_day())
    }
}

fn local_secs_of_day() -> u32 {
    let now = jiff::Zoned::now();
    now.hour() as u32 * 3600 + now.minute() as u32 * 60 + now.second() as u32
}

impl fmt::Display for TimeWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02}:{:02}-{:02}:{:02}",
            self.start_min / 60,
            self.start_min % 60,
            self.end_min / 60,
            self.end_min % 60
        )
    }
}

impl TryFrom<String> for TimeWindow {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        Self::parse(&s)
    }
}

impl From<TimeWindow> for String {
    fn from(w: TimeWindow) -> String {
        w.to_string()
    }
}

/// Paces byte transfers to an average rate.
#[derive(Debug)]
pub struct RateLimiter {
    bytes_per_sec: u64,
    next_free: Mutex<Instant>,
}

/// Transfers are paced in pieces of this size.
pub(crate) const PACE_CHUNK: usize = 64 * 1024;

impl RateLimiter {
    pub fn new(bytes_per_sec: u64) -> Self {
        Self {
            bytes_per_sec: bytes_per_sec.max(1),
            next_free: Mutex::new(Instant::now()),
        }
    }

    pub fn bytes_per_sec(&self) -> u64 {
        self.bytes_per_sec
    }

    /// Waits until `n` more bytes may be transferred.
    pub async fn consume(&self, n: usize) {
        let start = {
            let mut next = self.next_free.lock().await;
            let start = (*next).max(Instant::now());
            *next = start + Duration::from_secs_f64(n as f64 / self.bytes_per_sec as f64);
            start
        };
        tokio::time::sleep_until(start).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows() {
        let night = TimeWindow::parse("22:00-06:00").unwrap();
        assert_eq!(night.to_string(), "22:00-06:00");
        assert!(night.contains_minute(23 * 60));
        assert!(night.contains_minute(60));
        assert!(!night.contains_minute(6 * 60));
        assert!(!night.contains_minute(12 * 60));
        assert_eq!(
            night.until_open_from(21 * 3600 + 30 * 60),
            Duration::from_secs(30 * 60)
        );
        assert_eq!(night.until_open_from(23 * 3600), Duration::ZERO);

        let early = TimeWindow::parse("01:00-07:00").unwrap();
        assert_eq!(
            early.until_open_from(8 * 3600),
            Duration::from_secs(17 * 3600)
        );
        assert!(TimeWindow::parse("09:00-09:00").unwrap().contains_minute(0));

        for bad in ["", "1-2", "25:00-01:00", "10:60-11:00", "10:00"] {
            assert!(TimeWindow::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(String::from(night), "22:00-06:00");
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limiter_paces() {
        let limiter = RateLimiter::new(100_000);
        let start = Instant::now();
        for _ in 0..10 {
            limiter.consume(50_000).await;
        }
        // 500 kB at 100 kB/s: the last piece may start after 4.5 s.
        assert_eq!(start.elapsed(), Duration::from_millis(4500));
    }
}
