//! Access windows / auto-expiring exposure (#779): the per-tunnel policy an owner sets
//! in the portal, the control plane stores, and the edge enforces **locally** at its
//! `:443` front door from the copy it was pushed (rehydrated at boot, re-pushed on every
//! change) -- never with a per-request control-plane call.
//!
//! Pure and wasm32-portable: every evaluation takes `now` (Unix seconds) from the caller,
//! so this module never touches a clock, and the same code answers the portal's "closed
//! until ..." line, the edge's refusal page, and the unit tests below.
//!
//! Semantics, in evaluation order:
//!
//! 1. **Expiry wins.** `expires_at` in the past (`now >= expires_at`) is closed, whatever
//!    the schedule says. An expired policy never re-opens on its own -- the owner re-arms
//!    it explicitly (the portal's "Re-arm 24 h").
//! 2. **Schedule.** With a [`WeeklySchedule`], the policy is open iff `now`, shifted by
//!    the schedule's fixed UTC offset, falls inside at least one [`Slot`]. A schedule
//!    object with **zero slots is always closed** -- it is the explicit "no hours at all"
//!    state, distinct from having no schedule; callers that want "no restriction" omit the
//!    schedule instead. Slots whose fields are out of range ([`Slot::validate`]) never
//!    match, so a malformed row degrades to closed, not to open.
//! 3. **No policy, no restriction.** A policy with neither field, or no policy at all, is
//!    open -- absent JSON on the wire means exactly what it meant before this feature.
//!
//! A [`Slot`] is `[start_minute, end_minute)` on `day` (0 = Monday .. 6 = Sunday) in the
//! schedule's local time; `end_minute == 1440` is end of day. A slot whose end is not
//! after its start **wraps past midnight** into the next day (`Fri 22:00 -> 02:00` is
//! open Friday from 22:00 and Saturday until 02:00). The offset is a fixed number of
//! minutes, not an IANA zone: DST shifts are the owner's to re-select; this module has no
//! zone database and the edge must not need one.

use serde::{Deserialize, Serialize};

/// Minutes in a civil day; the exclusive upper bound of [`Slot::end_minute`].
pub const MINUTES_PER_DAY: u16 = 1440;

/// Smallest accepted UTC offset (`-12:00`).
pub const MIN_TZ_OFFSET_MINUTES: i32 = -12 * 60;
/// Largest accepted UTC offset (`+14:00`).
pub const MAX_TZ_OFFSET_MINUTES: i32 = 14 * 60;

const SECS_PER_MINUTE: i64 = 60;
const SECS_PER_DAY: i64 = 86_400;
const SECS_PER_WEEK: i64 = 7 * SECS_PER_DAY;
/// 1970-01-01 was a Thursday; with Monday = 0 that is day 3 of the week.
const EPOCH_WEEKDAY: i64 = 3;

/// One weekly opening: `[start_minute, end_minute)` on `day`, in the schedule's local time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slot {
    /// 0 = Monday .. 6 = Sunday.
    pub day: u8,
    /// Minutes after local midnight, `0..MINUTES_PER_DAY`, inclusive start.
    pub start_minute: u16,
    /// Minutes after local midnight, `1..=MINUTES_PER_DAY`, exclusive end. Not after
    /// `start_minute` means the slot wraps into the following day.
    pub end_minute: u16,
}

impl Slot {
    /// `Ok` iff every field is in range. `end_minute == start_minute` is rejected: it
    /// would read as either "nothing" or "a full 24 h wrap", and neither is what a form
    /// with two equal times meant.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.day > 6 {
            return Err("day must be 0 (Monday) .. 6 (Sunday)");
        }
        if self.start_minute >= MINUTES_PER_DAY {
            return Err("start must be before 24:00");
        }
        if self.end_minute == 0 || self.end_minute > MINUTES_PER_DAY {
            return Err("end must be between 00:01 and 24:00");
        }
        if self.end_minute == self.start_minute {
            return Err("end must differ from start");
        }
        Ok(())
    }

    fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    fn wraps_midnight(&self) -> bool {
        self.end_minute <= self.start_minute
    }

    /// Does local `(weekday, minute_of_day)` fall inside this slot?
    fn contains(&self, weekday: u8, minute_of_day: u16) -> bool {
        if !self.is_valid() {
            return false;
        }
        if self.wraps_midnight() {
            (weekday == self.day && minute_of_day >= self.start_minute)
                || (weekday == (self.day + 1) % 7 && minute_of_day < self.end_minute)
        } else {
            weekday == self.day && minute_of_day >= self.start_minute && minute_of_day < self.end_minute
        }
    }

    /// The slot's two boundaries as second offsets from the local week's Monday
    /// 00:00, `(start, end)`. A wrapping slot's end lands on the next day, so it may
    /// exceed one week for a Sunday slot; callers normalize modulo the week.
    fn week_offsets(&self) -> (i64, i64) {
        let start = (i64::from(self.day) * i64::from(MINUTES_PER_DAY) + i64::from(self.start_minute)) * SECS_PER_MINUTE;
        let end_day = if self.wraps_midnight() { i64::from(self.day) + 1 } else { i64::from(self.day) };
        let end = (end_day * i64::from(MINUTES_PER_DAY) + i64::from(self.end_minute)) * SECS_PER_MINUTE;
        (start, end)
    }
}

/// Weekly opening hours at a fixed UTC offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeeklySchedule {
    /// Minutes east of UTC the slots are expressed in (`+120` for CEST).
    pub tz_offset_minutes: i32,
    /// The openings. Empty = always closed (see the module doc).
    pub slots: Vec<Slot>,
}

impl WeeklySchedule {
    /// `Ok` iff the offset is a real one and every slot passes [`Slot::validate`].
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(MIN_TZ_OFFSET_MINUTES..=MAX_TZ_OFFSET_MINUTES).contains(&self.tz_offset_minutes) {
            return Err("timezone offset must be between -12:00 and +14:00");
        }
        self.slots.iter().try_for_each(Slot::validate)
    }

    fn local_secs(&self, now_unix: i64) -> i64 {
        now_unix.saturating_add(i64::from(self.tz_offset_minutes) * SECS_PER_MINUTE)
    }

    /// `(weekday 0=Mon..6=Sun, minute_of_day)` of a local timestamp.
    fn civil(local: i64) -> (u8, u16) {
        let days = local.div_euclid(SECS_PER_DAY);
        let weekday = (days + EPOCH_WEEKDAY).rem_euclid(7) as u8;
        let minute_of_day = (local.rem_euclid(SECS_PER_DAY) / SECS_PER_MINUTE) as u16;
        (weekday, minute_of_day)
    }

    /// Open at `now_unix`?
    pub fn is_open(&self, now_unix: i64) -> bool {
        let (weekday, minute) = Self::civil(self.local_secs(now_unix));
        self.slots.iter().any(|s| s.contains(weekday, minute))
    }

    /// The first instant strictly after `now_unix` at which [`is_open`](Self::is_open)
    /// flips, or `None` when it never does (no valid slot at all, or slots that cover
    /// the whole week without a gap).
    pub fn next_change(&self, now_unix: i64) -> Option<i64> {
        let valid: Vec<&Slot> = self.slots.iter().filter(|s| s.is_valid()).collect();
        if valid.is_empty() {
            return None;
        }
        let local = self.local_secs(now_unix);
        let (weekday, minute) = Self::civil(local);
        // Local Monday 00:00 of the week `local` falls in.
        let secs_into_week = (i64::from(weekday) * i64::from(MINUTES_PER_DAY) + i64::from(minute)) * SECS_PER_MINUTE
            + local.rem_euclid(SECS_PER_MINUTE);
        let week_start = local - secs_into_week;
        let open_now = self.is_open(now_unix);
        let mut candidates: Vec<i64> = Vec::with_capacity(valid.len() * 2);
        for slot in valid {
            let (start, end) = slot.week_offsets();
            for boundary in [start, end] {
                // First occurrence of this boundary strictly after `local`.
                let mut at = week_start + boundary;
                while at <= local {
                    at += SECS_PER_WEEK;
                }
                while at - SECS_PER_WEEK > local {
                    at -= SECS_PER_WEEK;
                }
                candidates.push(at - i64::from(self.tz_offset_minutes) * SECS_PER_MINUTE);
            }
        }
        candidates.sort_unstable();
        // Overlapping slots make some boundaries no-ops (9-12 and 11-14 do not change
        // state at 12); the first boundary where the evaluated state differs is the answer.
        candidates.into_iter().find(|&t| self.is_open(t) != open_now)
    }
}

/// The access policy of one tunnel. Both fields optional and independent; see the
/// module doc for how they combine. Wire shape (JSON):
/// `{"expires_at": 1789084800, "schedule": {"tz_offset_minutes": 120, "slots":
/// [{"day": 0, "start_minute": 540, "end_minute": 1020}]}}` -- absent fields are
/// omitted when serializing and default to `None` when parsing, so `{}` is a valid,
/// unrestricted policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Unix seconds after which the tunnel is closed until re-armed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Weekly opening hours; absent = open at any hour (subject to `expires_at`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<WeeklySchedule>,
}

impl AccessPolicy {
    /// Neither an expiry nor a schedule -- semantically the same as no policy row at all.
    pub fn is_unrestricted(&self) -> bool {
        self.expires_at.is_none() && self.schedule.is_none()
    }

    /// `Ok` iff the schedule (when present) passes [`WeeklySchedule::validate`].
    pub fn validate(&self) -> Result<(), &'static str> {
        match &self.schedule {
            Some(s) => s.validate(),
            None => Ok(()),
        }
    }

    /// Has `expires_at` passed at `now_unix`?
    pub fn is_expired(&self, now_unix: i64) -> bool {
        matches!(self.expires_at, Some(e) if now_unix >= e)
    }

    /// May a browser reach the tunnel at `now_unix`? Expiry first, then the schedule,
    /// then "no restriction".
    pub fn is_open(&self, now_unix: i64) -> bool {
        if self.is_expired(now_unix) {
            return false;
        }
        match &self.schedule {
            Some(s) => s.is_open(now_unix),
            None => true,
        }
    }

    /// The next instant strictly after `now_unix` at which [`is_open`](Self::is_open)
    /// changes, for a countdown / `Retry-After`. `None` when the state is final from
    /// here on: already expired (only a re-arm changes that), unrestricted with no
    /// expiry, or closed by a schedule that cannot open again before the expiry.
    pub fn next_change(&self, now_unix: i64) -> Option<i64> {
        if self.is_expired(now_unix) {
            return None;
        }
        let scheduled = self.schedule.as_ref().and_then(|s| s.next_change(now_unix));
        match (self.is_open(now_unix), scheduled, self.expires_at) {
            // Open: whichever comes first, the scheduled close or the expiry.
            (true, Some(s), Some(e)) => Some(s.min(e)),
            (true, Some(s), None) => Some(s),
            (true, None, e) => e,
            // Closed by the schedule: the next scheduled open, unless the expiry
            // lands first -- then it never opens again.
            (false, Some(s), Some(e)) if s < e => Some(s),
            (false, Some(s), None) => Some(s),
            (false, _, _) => None,
        }
    }
}

/// Unix seconds as `YYYY-MM-DD HH:MM` in UTC, for the edge's refusal page and the
/// portal's status line (both read across time zones; the text says UTC). Proleptic
/// Gregorian civil-from-days (Howard Hinnant's algorithm), so neither crate needs a
/// date-time dependency for a display string; negative inputs clamp to the epoch.
pub fn format_utc_ymd_hm(secs: i64) -> String {
    let secs = secs.max(0);
    let days = secs / SECS_PER_DAY;
    let rem = secs % SECS_PER_DAY;
    let (hour, minute) = (rem / 3_600, (rem % 3_600) / 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}")
}

/// Days since 1970-01-01 of a proleptic-Gregorian civil date (Howard Hinnant's
/// `days_from_civil`); the inverse of [`format_utc_ymd_hm`]'s date half. Used by the
/// portal to turn a `datetime-local` form value into Unix seconds without a date-time
/// dependency. No range validation beyond what the arithmetic implies -- callers
/// check `month`/`day` themselves.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(month);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unix seconds of a UTC civil time, so every fixture below is self-describing.
    fn utc(year: i64, month: u32, day: u32, hour: i64, minute: i64) -> i64 {
        days_from_civil(year, month, day) * SECS_PER_DAY + hour * 3_600 + minute * 60
    }

    // 2026-09-07 is a Monday (checked against `date -u -d 2026-09-07 +%s` = 1788739200).
    const MONDAY: (i64, u32, u32) = (2026, 9, 7);

    fn on(day_offset: u32, hour: i64, minute: i64) -> i64 {
        utc(MONDAY.0, MONDAY.1, MONDAY.2 + day_offset, hour, minute)
    }

    fn slot(day: u8, start: u16, end: u16) -> Slot {
        Slot { day, start_minute: start, end_minute: end }
    }

    fn schedule(tz: i32, slots: Vec<Slot>) -> WeeklySchedule {
        WeeklySchedule { tz_offset_minutes: tz, slots }
    }

    #[test]
    fn fixtures_are_anchored_on_a_monday() {
        assert_eq!(on(0, 0, 0), 1_788_739_200);
        assert_eq!(WeeklySchedule::civil(on(0, 0, 0)), (0, 0), "Monday 00:00");
        assert_eq!(WeeklySchedule::civil(on(6, 23, 59)), (6, 1439), "Sunday 23:59");
    }

    #[test]
    fn no_policy_is_open_with_no_change_ahead() {
        let p = AccessPolicy::default();
        assert!(p.is_unrestricted());
        assert!(p.is_open(on(0, 12, 0)));
        assert_eq!(p.next_change(on(0, 12, 0)), None);
    }

    #[test]
    fn expiry_closes_at_the_instant_and_never_reopens() {
        let e = on(3, 0, 0);
        let p = AccessPolicy { expires_at: Some(e), schedule: None };
        assert!(p.is_open(e - 1));
        assert_eq!(p.next_change(e - 1), Some(e), "countdown targets the expiry");
        assert!(!p.is_open(e), "closed exactly at expires_at");
        assert!(!p.is_open(e + 86_400));
        assert!(p.is_expired(e));
        assert_eq!(p.next_change(e), None, "an expired policy only re-opens on an explicit re-arm");
    }

    #[test]
    fn schedule_opens_only_inside_a_slot() {
        // Mon 09:00-17:00, UTC.
        let p = AccessPolicy { expires_at: None, schedule: Some(schedule(0, vec![slot(0, 540, 1020)])) };
        assert!(!p.is_open(on(0, 8, 59)));
        assert!(p.is_open(on(0, 9, 0)), "start is inclusive");
        assert!(p.is_open(on(0, 16, 59)));
        assert!(!p.is_open(on(0, 17, 0)), "end is exclusive");
        assert!(!p.is_open(on(1, 12, 0)), "Tuesday is not in the schedule");
        assert_eq!(p.next_change(on(0, 10, 0)), Some(on(0, 17, 0)), "open -> closes at 17:00");
        assert_eq!(p.next_change(on(0, 18, 0)), Some(on(7, 9, 0)), "closed -> opens next Monday 09:00");
        assert_eq!(p.next_change(on(0, 8, 0)), Some(on(0, 9, 0)), "closed before the slot -> opens today");
    }

    #[test]
    fn schedule_honors_the_fixed_utc_offset() {
        // Mon 09:00-17:00 in UTC+2: that is 07:00-15:00 UTC.
        let p = AccessPolicy { expires_at: None, schedule: Some(schedule(120, vec![slot(0, 540, 1020)])) };
        assert!(p.is_open(on(0, 7, 30)), "09:30 local");
        assert!(!p.is_open(on(0, 15, 30)), "17:30 local");
        assert!(!p.is_open(on(0, 6, 59)));
        assert_eq!(p.next_change(on(0, 7, 30)), Some(on(0, 15, 0)));
        // A negative offset moves the other way: UTC-5, Mon 09:00 local = 14:00 UTC.
        let p = AccessPolicy { expires_at: None, schedule: Some(schedule(-300, vec![slot(0, 540, 1020)])) };
        assert!(!p.is_open(on(0, 13, 59)));
        assert!(p.is_open(on(0, 14, 0)));
        // An offset can move the local weekday across the UTC one: Sunday 23:30 UTC is
        // Monday 01:30 in UTC+2, inside a Monday 00:00-02:00 slot.
        let p = AccessPolicy { expires_at: None, schedule: Some(schedule(120, vec![slot(0, 0, 120)])) };
        assert!(p.is_open(on(6, 23, 30)));
    }

    #[test]
    fn a_slot_whose_end_is_not_after_its_start_wraps_past_midnight() {
        // Fri 22:00 -> 02:00 (Saturday).
        let p = AccessPolicy { expires_at: None, schedule: Some(schedule(0, vec![slot(4, 1320, 120)])) };
        assert!(!p.is_open(on(4, 21, 59)));
        assert!(p.is_open(on(4, 22, 0)));
        assert!(p.is_open(on(4, 23, 59)));
        assert!(p.is_open(on(5, 1, 59)), "Saturday 01:59 is still inside the wrapped slot");
        assert!(!p.is_open(on(5, 2, 0)));
        assert!(!p.is_open(on(5, 22, 30)), "Saturday night is not Friday night");
        assert_eq!(p.next_change(on(4, 23, 0)), Some(on(5, 2, 0)));
        assert_eq!(p.next_change(on(5, 3, 0)), Some(on(11, 22, 0)), "next Friday 22:00");
        // Sunday wraps into Monday, and Monday's tail is found from the previous week.
        let p = AccessPolicy { expires_at: None, schedule: Some(schedule(0, vec![slot(6, 1380, 60)])) };
        assert!(p.is_open(on(6, 23, 30)));
        assert!(p.is_open(on(7, 0, 30)), "the following Monday 00:30");
        assert!(p.is_open(on(0, 0, 30)), "this Monday 00:30 belongs to last Sunday's slot");
        assert_eq!(p.next_change(on(0, 0, 30)), Some(on(0, 1, 0)));
    }

    #[test]
    fn expiry_takes_precedence_over_an_open_schedule() {
        let p = AccessPolicy { expires_at: Some(on(0, 12, 0)), schedule: Some(schedule(0, vec![slot(0, 540, 1020)])) };
        assert!(p.is_open(on(0, 11, 0)), "inside the slot and before the expiry");
        assert!(!p.is_open(on(0, 13, 0)), "inside the slot but expired");
        assert_eq!(p.next_change(on(0, 11, 0)), Some(on(0, 12, 0)), "the expiry lands before the slot's end");
        // Closed by the schedule with an expiry before the next opening: final.
        let p = AccessPolicy { expires_at: Some(on(2, 0, 0)), schedule: Some(schedule(0, vec![slot(0, 540, 1020)])) };
        assert!(!p.is_open(on(0, 18, 0)));
        assert_eq!(p.next_change(on(0, 18, 0)), None, "it would only re-open after it has expired");
        // ... but with the expiry after the next opening, the opening is the next change.
        let p = AccessPolicy { expires_at: Some(on(9, 0, 0)), schedule: Some(schedule(0, vec![slot(0, 540, 1020)])) };
        assert_eq!(p.next_change(on(0, 18, 0)), Some(on(7, 9, 0)));
    }

    #[test]
    fn a_schedule_with_no_slots_is_always_closed() {
        let p = AccessPolicy { expires_at: None, schedule: Some(schedule(0, vec![])) };
        assert!(!p.is_unrestricted(), "an empty schedule is a restriction, not the absence of one");
        for d in 0..7 {
            assert!(!p.is_open(on(d, 12, 0)));
        }
        assert_eq!(p.next_change(on(0, 12, 0)), None);
    }

    #[test]
    fn overlapping_slots_do_not_report_a_change_at_an_inner_boundary() {
        // 09-12 and 11-14 on Monday: open 09:00-14:00 with no flip at 11:00 or 12:00.
        let p = AccessPolicy {
            expires_at: None,
            schedule: Some(schedule(0, vec![slot(0, 540, 720), slot(0, 660, 840)])),
        };
        assert_eq!(p.next_change(on(0, 10, 0)), Some(on(0, 14, 0)));
        assert!(p.is_open(on(0, 12, 0)));
    }

    #[test]
    fn invalid_slots_never_match_and_are_reported_by_validate() {
        assert!(slot(7, 0, 60).validate().is_err(), "day 7");
        assert!(slot(0, 1440, 60).validate().is_err(), "start at 24:00");
        assert!(slot(0, 0, 1441).validate().is_err(), "end past 24:00");
        assert!(slot(0, 0, 0).validate().is_err(), "end 00:00");
        assert!(slot(0, 600, 600).validate().is_err(), "equal");
        assert!(slot(0, 0, 1440).validate().is_ok(), "a full day");
        assert!(slot(6, 1380, 60).validate().is_ok(), "a wrap");
        let p = AccessPolicy { expires_at: None, schedule: Some(schedule(0, vec![slot(9, 0, 1440)])) };
        assert!(!p.is_open(on(0, 12, 0)), "a malformed slot degrades to closed, never to open");
        assert_eq!(p.next_change(on(0, 12, 0)), None);
        assert!(p.validate().is_err());
        assert!(schedule(900, vec![]).validate().is_err(), "offset beyond +14:00");
        assert!(schedule(-721, vec![]).validate().is_err(), "offset beyond -12:00");
        assert!(schedule(840, vec![]).validate().is_ok());
    }

    #[test]
    fn json_shape_round_trips_and_absent_fields_mean_unrestricted() {
        let p = AccessPolicy {
            expires_at: Some(1_789_084_800),
            schedule: Some(schedule(120, vec![slot(0, 540, 1020)])),
        };
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(
            json,
            r#"{"expires_at":1789084800,"schedule":{"tz_offset_minutes":120,"slots":[{"day":0,"start_minute":540,"end_minute":1020}]}}"#
        );
        assert_eq!(serde_json::from_str::<AccessPolicy>(&json).unwrap(), p);
        let empty: AccessPolicy = serde_json::from_str("{}").unwrap();
        assert!(empty.is_unrestricted());
        assert_eq!(serde_json::to_string(&empty).unwrap(), "{}", "None fields are omitted, not written as null");
        let expiry_only: AccessPolicy = serde_json::from_str(r#"{"expires_at":5}"#).unwrap();
        assert_eq!(expiry_only.schedule, None);
    }

    #[test]
    fn utc_formatting_and_civil_days_agree() {
        assert_eq!(format_utc_ymd_hm(on(0, 9, 5)), "2026-09-07 09:05");
        assert_eq!(format_utc_ymd_hm(0), "1970-01-01 00:00");
        assert_eq!(format_utc_ymd_hm(-5), "1970-01-01 00:00", "negative clamps to the epoch");
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2026, 9, 7) * SECS_PER_DAY, 1_788_739_200);
    }
}
