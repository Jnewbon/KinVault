//! Which snapshots to keep: the newest few, plus the newest snapshot in each
//! of the most recent hours, days, weeks, months and years (UTC buckets).

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ids::SnapshotId;

/// Maps seconds since the epoch to a time bucket (hour, day, ...).
type Bucket = fn(i64) -> i64;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RetentionPolicy {
    #[serde(default)]
    pub last: Option<u32>,
    #[serde(default)]
    pub hourly: Option<u32>,
    #[serde(default)]
    pub daily: Option<u32>,
    #[serde(default)]
    pub weekly: Option<u32>,
    #[serde(default)]
    pub monthly: Option<u32>,
    #[serde(default)]
    pub yearly: Option<u32>,
}

impl RetentionPolicy {
    pub fn recommended() -> Self {
        Self {
            last: Some(10),
            hourly: Some(24),
            daily: Some(14),
            weekly: Some(8),
            monthly: Some(12),
            yearly: Some(5),
        }
    }

    /// A policy with no rules keeps every snapshot.
    pub fn keeps_everything(&self) -> bool {
        *self == Self::default()
    }

    /// Returns the snapshots to keep from `(id, time in ns)` pairs. The newest
    /// snapshot is always kept.
    pub fn select(&self, snapshots: &[(SnapshotId, i64)]) -> HashSet<SnapshotId> {
        let mut sorted = snapshots.to_vec();
        sorted.sort_by_key(|&(_, time)| std::cmp::Reverse(time));
        if self.keeps_everything() {
            return sorted.iter().map(|(id, _)| *id).collect();
        }
        let mut keep = HashSet::new();
        if let Some((newest, _)) = sorted.first() {
            keep.insert(*newest);
        }
        if let Some(n) = self.last {
            keep.extend(sorted.iter().take(n as usize).map(|(id, _)| *id));
        }
        let rules: [(Option<u32>, Bucket); 5] = [
            (self.hourly, |s| s.div_euclid(3600)),
            (self.daily, |s| s.div_euclid(86_400)),
            // 1970-01-01 was a Thursday; shifting by 3 days starts weeks on Monday.
            (self.weekly, |s| (s.div_euclid(86_400) + 3).div_euclid(7)),
            (self.monthly, |s| {
                let (y, m) = year_month(s.div_euclid(86_400));
                y * 12 + m
            }),
            (self.yearly, |s| year_month(s.div_euclid(86_400)).0),
        ];
        for (count, bucket) in rules {
            let Some(count) = count else { continue };
            let mut kept = 0;
            let mut last_bucket = None;
            for (id, time_ns) in &sorted {
                if kept >= count {
                    break;
                }
                let b = bucket(time_ns.div_euclid(1_000_000_000));
                if last_bucket != Some(b) {
                    keep.insert(*id);
                    kept += 1;
                    last_bucket = Some(b);
                }
            }
        }
        keep
    }
}

/// Civil year and month (1-12) from days since the Unix epoch (Howard Hinnant).
fn year_month(days: i64) -> (i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month)
}

impl fmt::Display for RetentionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.keeps_everything() {
            return f.write_str("keep everything");
        }
        let parts: Vec<String> = [
            (self.last, "latest"),
            (self.hourly, "hourly"),
            (self.daily, "daily"),
            (self.weekly, "weekly"),
            (self.monthly, "monthly"),
            (self.yearly, "yearly"),
        ]
        .iter()
        .filter_map(|(n, label)| n.map(|n| format!("{n} {label}")))
        .collect();
        f.write_str(&parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3600 * 1_000_000_000;

    fn snaps(times_h: &[i64]) -> Vec<(SnapshotId, i64)> {
        times_h
            .iter()
            .enumerate()
            .map(|(i, h)| (SnapshotId([i as u8; 32]), h * HOUR))
            .collect()
    }

    fn kept_hours(policy: RetentionPolicy, s: &[(SnapshotId, i64)]) -> Vec<i64> {
        let keep = policy.select(s);
        let mut out: Vec<i64> = s
            .iter()
            .filter(|(id, _)| keep.contains(id))
            .map(|(_, t)| t / HOUR)
            .collect();
        out.sort();
        out
    }

    #[test]
    fn empty_policy_keeps_all() {
        let s = snaps(&[1, 2, 3]);
        assert_eq!(kept_hours(RetentionPolicy::default(), &s), vec![1, 2, 3]);
    }

    #[test]
    fn last_n_and_newest_always() {
        let s = snaps(&[1, 2, 3, 4, 5]);
        assert_eq!(
            kept_hours(
                RetentionPolicy {
                    last: Some(2),
                    ..Default::default()
                },
                &s
            ),
            vec![4, 5]
        );
        // Even a policy that keeps nothing by its rules keeps the newest.
        assert_eq!(
            kept_hours(
                RetentionPolicy {
                    last: Some(0),
                    ..Default::default()
                },
                &s
            ),
            vec![5]
        );
    }

    #[test]
    fn daily_keeps_newest_per_day() {
        // Several snapshots on each of four days.
        let s = snaps(&[1, 5, 23, 25, 30, 49, 50, 73]);
        let policy = RetentionPolicy {
            daily: Some(3),
            ..Default::default()
        };
        // Days 3, 2 and 1 (newest first): newest of each is 73, 50 and 30.
        assert_eq!(kept_hours(policy, &s), vec![30, 50, 73]);
    }

    #[test]
    fn rules_combine() {
        let s = snaps(&(0..24 * 40).step_by(6).collect::<Vec<_>>());
        let policy = RetentionPolicy {
            hourly: Some(4),
            daily: Some(7),
            weekly: Some(3),
            ..Default::default()
        };
        let kept = kept_hours(policy, &s);
        // 4 hourly + 7 daily (the newest overlaps) + up to 3 weekly, all distinct snapshots.
        assert!(kept.len() <= 4 + 7 + 3 && kept.len() >= 10, "{kept:?}");
        assert!(kept.contains(&(24 * 40 - 6)));
    }

    #[test]
    fn calendar_buckets() {
        assert_eq!(year_month(0), (1970, 1));
        assert_eq!(year_month(31), (1970, 2));
        assert_eq!(year_month(11_016), (2000, 2)); // 2000-02-29
        assert_eq!(year_month(20_737), (2026, 10));
    }

    #[test]
    fn display() {
        assert_eq!(RetentionPolicy::default().to_string(), "keep everything");
        assert_eq!(
            RetentionPolicy {
                last: Some(3),
                daily: Some(7),
                ..Default::default()
            }
            .to_string(),
            "3 latest, 7 daily"
        );
    }
}
