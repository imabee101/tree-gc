//! "In-use days" clock.
//!
//! Wall-clock age is the wrong measure of staleness: after three weeks away,
//! every project you are in the middle of would look abandoned. Instead,
//! tree-gc records which days the machine was actually *used* (shell/agent
//! history files, project activity) and measures idleness in those days.
//!
//! Counting rule for each day d in (day(t), day(now)]:
//!   - before tree-gc's first recorded run: counts (no history -> calendar)
//!   - after the last recorded run (e.g. a `--days N` simulation): counts
//!   - otherwise: counts only if user activity was seen that day
//!     (observed-but-idle days and days the machine was off don't count)
use crate::util::DAY;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub fn day(t: i64) -> i64 {
    t.div_euclid(DAY)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActivityClock {
    pub first_run: Option<i64>,
    pub last_run: Option<i64>,
    /// Day indexes with observed user activity.
    pub active: BTreeSet<i64>,
}

const FILE: &str = "activity.json";

impl ActivityClock {
    /// Missing or unreadable state means "no history": calendar days.
    pub fn load(state_dir: &Path) -> Self {
        fs::read(state_dir.join(FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, state_dir: &Path) -> Result<()> {
        fs::create_dir_all(state_dir)?;
        let tmp = state_dir.join(format!("{FILE}.tmp"));
        fs::write(&tmp, serde_json::to_vec(self)?)?;
        fs::rename(tmp, state_dir.join(FILE))?;
        Ok(())
    }

    /// Record a run at `now`, given the newest user-activity timestamps seen.
    pub fn record(&mut self, now: i64, activity: &[i64]) {
        self.first_run = Some(self.first_run.map_or(now, |f| f.min(now)));
        self.last_run = Some(self.last_run.map_or(now, |l| l.max(now)));
        let first = day(self.first_run.unwrap());
        for &t in activity {
            if t <= now && day(t) >= first {
                self.active.insert(day(t));
            }
        }
        // Keep about two years.
        let cutoff = day(now) - 730;
        self.active = self.active.split_off(&cutoff);
    }

    /// In-use days in (day(t), day(now)].
    pub fn idle_days(&self, t: i64, now: i64) -> i64 {
        let (a, b) = (day(t), day(now));
        if b <= a {
            return 0;
        }
        let (Some(first), Some(last)) = (self.first_run, self.last_run) else {
            return b - a; // no history: calendar days
        };
        let (fd, ld) = (day(first), day(last));
        let before = (fd.min(b + 1) - (a + 1)).max(0); // days < fd
        let after = (b - ld.max(a)).max(0); // days > ld
        let lo = (a + 1).max(fd);
        let hi = b.min(ld);
        let mid = if lo <= hi { self.active.range(lo..=hi).count() as i64 } else { 0 };
        before + mid + after
    }

    /// The clock moved backwards since the last run (bad RTC, manual change):
    /// ages would be meaningless, so nothing should be acted on.
    pub fn went_backwards(&self, now: i64) -> bool {
        self.last_run.is_some_and(|l| now < l - 3600)
    }
}

/// Newest modification time among user-activity signal files.
pub fn user_activity(files: &[std::path::PathBuf]) -> Option<i64> {
    files.iter().filter_map(|f| crate::util::mtime(f)).max()
}

#[cfg(test)]
mod tests {
    use super::*;
    const D: i64 = DAY;

    #[test]
    fn no_history_is_calendar() {
        let c = ActivityClock::default();
        assert_eq!(c.idle_days(0, 10 * D), 10);
    }

    #[test]
    fn vacation_days_do_not_count() {
        let mut c = ActivityClock::default();
        // used daily for days 0..=9, then away days 10..=30, runs kept going
        for d in 0..=9 {
            c.record(d * D + 100, &[d * D + 50]);
        }
        for d in 10..=30 {
            c.record(d * D + 100, &[9 * D + 50]);
        }
        // touched on day 5: idle = active days 6..=9 = 4, not 25
        assert_eq!(c.idle_days(5 * D, 30 * D + 100), 4);
        // back on day 31: that day counts again
        c.record(31 * D + 100, &[31 * D + 60]);
        assert_eq!(c.idle_days(5 * D, 31 * D + 100), 5);
    }

    #[test]
    fn machine_off_days_do_not_count_but_simulation_future_does() {
        let mut c = ActivityClock::default();
        c.record(10 * D, &[10 * D]);
        c.record(40 * D, &[40 * D]); // off from day 11 to 39
        assert_eq!(c.idle_days(10 * D, 40 * D), 1);
        // simulating 7 days past the last run: all 7 count
        assert_eq!(c.idle_days(10 * D, 47 * D), 8);
        // before first run: calendar
        assert_eq!(c.idle_days(0, 10 * D), 10);
    }

    #[test]
    fn backwards_clock_detected() {
        let mut c = ActivityClock::default();
        c.record(100 * D, &[]);
        assert!(c.went_backwards(99 * D));
        assert!(!c.went_backwards(100 * D + 10));
    }
}
