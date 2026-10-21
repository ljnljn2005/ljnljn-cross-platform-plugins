//! Injection feature matching and the windowed suspicion rule.
//!
//! A `(path, param)` pair is a *suspicious candidate* when **one** window of
//! `window_seconds` (measured on the log's own timestamps) contains at least
//! `min_requests` requests that carry the parameter, at most
//! `max_distinct_ips` distinct client IPs inside that same window, and whose
//! parameter values hit at least `min_families` distinct [`Family`]
//! patterns. Hits are matched on the `%XX`-decoded value; the raw value is
//! preserved next to each sample line.

use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};

use crate::model::{Config, Family, FamilyHits, TimestampParts};

static FAMILY_REGEXES: OnceLock<Vec<Regex>> = OnceLock::new();

fn family_regexes() -> &'static [Regex] {
    FAMILY_REGEXES.get_or_init(|| {
        Family::ALL
            .iter()
            .map(|family| {
                // SQL keywords appear in every case in real payloads, so the
                // documented patterns are matched case-insensitively.
                RegexBuilder::new(family.pattern())
                    .case_insensitive(true)
                    .build()
                    .expect("family pattern")
            })
            .collect()
    })
}

/// Family matches of one decoded value (`hits[i] > 0` = family hit).
pub fn family_hits(value: &[u8]) -> FamilyHits {
    let text = String::from_utf8_lossy(value);
    let mut hits = [0_u64; 8];
    for (index, regex) in family_regexes().iter().enumerate() {
        hits[index] = regex.find_iter(&text).count() as u64;
    }
    hits
}

/// Adds `source` into `target`.
pub fn merge_hits(target: &mut FamilyHits, source: &FamilyHits) {
    for (into, from) in target.iter_mut().zip(source.iter()) {
        *into = into.saturating_add(*from);
    }
}

/// The families that hit, with their counts.
pub fn family_entries(hits: &FamilyHits) -> Vec<(Family, u64)> {
    Family::ALL
        .iter()
        .copied()
        .zip(hits.iter().copied())
        .filter(|(_, count)| *count > 0)
        .collect()
}

/// `(hit families, total matches)`.
pub fn family_totals(hits: &FamilyHits) -> (usize, u64) {
    let entries = family_entries(hits);
    (entries.len(), entries.iter().map(|(_, count)| *count).sum())
}

/// `"time-func:3,order-by:1"`, or `none`.
pub fn family_summary(hits: &FamilyHits) -> String {
    let entries = family_entries(hits);
    if entries.is_empty() {
        return "none".to_owned();
    }
    entries
        .iter()
        .map(|(family, count)| format!("{}:{count}", family.name()))
        .collect::<Vec<_>>()
        .join(",")
}

/// One request that carried a parameter, as seen by the scans.
#[derive(Clone, Debug)]
pub struct RequestRecord {
    pub time: TimestampParts,
    pub ip: String,
    pub method: String,
    pub status: Option<u16>,
    pub hits: FamilyHits,
}

/// Incremental statistics on linear time (`[min,max]`, distinct IPs, statuses,
/// family hits). Used both for the whole file and per window, without
/// requiring the window to be reconstructed afterwards.
#[derive(Clone, Debug, Default, PartialEq)]
struct TimeStats {
    min: Option<(u64, u64)>,
    max: Option<(u64, u64)>,
    /// (linear seconds, ip) of *all* window records, for distinct-IP counting.
    ips: Vec<(i64, String)>,
    status: Vec<(Option<u16>, u64)>,
    families: FamilyHits,
}

impl TimeStats {
    fn add(&mut self, record: &RequestRecord) {
        let time = record.time.linear_nanos();
        let seconds = record.time.linear_seconds();
        self.min = Some(
            self.min
                .map_or((time, time), |(low, high)| (low.min(time), high)),
        );
        self.max = Some(
            self.max
                .map_or((time, time), |(low, high)| (low, high.max(time))),
        );
        let repeated = self
            .ips
            .iter()
            .any(|(seen, ip)| *seen == seconds && *ip == record.ip);
        if !repeated {
            self.ips.push((seconds, record.ip.clone()));
        }
        self.status.push((record.status, time));
        for (into, from) in self.families.iter_mut().zip(record.hits.iter()) {
            if *from > 0 {
                *into = 1;
            }
        }
    }

    fn distinct_ips(&self) -> u64 {
        let mut ips: Vec<&str> = self.ips.iter().map(|(_, ip)| ip.as_str()).collect();
        ips.sort_unstable();
        ips.dedup();
        ips.len() as u64
    }

    fn status_distribution(&self) -> Vec<(Option<u16>, u64)> {
        let mut pairs = self.status.clone();
        pairs.sort_by_key(|(status, _)| *status);
        let mut out: Vec<(Option<u16>, u64)> = Vec::new();
        for (status, _) in pairs {
            match out.last_mut() {
                Some((last, count)) if *last == status => *count += 1,
                _ => out.push((status, 1)),
            }
        }
        out
    }

    fn family_count(&self) -> usize {
        self.families.iter().filter(|count| **count > 0).count()
    }
}

/// Outcome of the window scan for one `(path, param)` pair.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WindowScan {
    /// Requests carrying the parameter in the whole file.
    pub total_requests: u64,
    /// Requests carrying the parameter in the best window.
    pub window_requests: u64,
    /// Distinct client IPs in the best window.
    pub window_ips: u64,
    /// Family hits in the best window (`> 0` = family present).
    pub window_families: FamilyHits,
    /// Status distribution of the best window.
    pub window_status: Vec<(Option<u16>, u64)>,
    /// Raw `[time]` text of the first / last request of the best window.
    pub window_first_seen: Option<String>,
    pub window_last_seen: Option<String>,
    /// Offset in seconds (log's own scale) of first / last request.
    pub window_first_offset: Option<i64>,
    pub window_last_offset: Option<i64>,
    /// Requests that carried at least one family hit anywhere in the file.
    pub payload_requests: u64,
}

impl WindowScan {
    pub fn family_count(&self) -> usize {
        self.window_families
            .iter()
            .filter(|count| **count > 0)
            .count()
    }

    /// The best window meets the configured thresholds.
    pub fn qualifies(&self, config: &Config) -> bool {
        self.window_requests >= config.min_requests
            && self.window_ips <= config.max_distinct_ips
            && self.family_count() >= config.min_families
    }

    /// The file-wide window (every request) meets the thresholds — then the
    /// burst constraint is not needed to explain the pair.
    pub fn whole_file_qualifies(&self, config: &Config) -> bool {
        self.total_requests >= config.min_requests
            && self.window_ips <= config.max_distinct_ips
            && self.family_count() >= config.min_families
    }
}

/// Result of the scan: the best window plus a no-window baseline.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ScanResult {
    pub best: WindowScan,
    /// True when the burst constraint is what makes the pair suspicious.
    pub window_necessary: bool,
}

/// Scans every window of `config.window_seconds` and keeps the most specific
/// one: it maximises (distinct families, requests, distinct IPs) — i.e. the
/// densest burst from the fewest identities. Ties keep the earliest window.
pub fn scan_windows(records: &mut [RequestRecord], config: &Config) -> ScanResult {
    let mut scan = WindowScan::default();
    for record in records.iter() {
        scan.total_requests += 1;
        if record.hits.iter().any(|count| *count > 0) {
            scan.payload_requests += 1;
        }
    }
    if records.is_empty() {
        return ScanResult::default();
    }
    records.sort_by(|a, b| a.time.linear_nanos().cmp(&b.time.linear_nanos()));

    let nanos = 1_000_000_000_i64;
    let window = config.window_seconds.saturating_mul(nanos);
    let mut best: Option<(usize, TimeStats)> = None;
    let mut start = 0;
    for end in 0..records.len() {
        let end_time = records[end].time.linear_nanos() as i64;
        while start < end && end_time - (records[start].time.linear_nanos() as i64) >= window {
            start += 1;
        }
        let mut stats = TimeStats::default();
        for record in &records[start..=end] {
            stats.add(record);
        }
        let keys = (
            stats.family_count(),
            stats.ips.len(),
            usize::MAX - stats.distinct_ips() as usize,
        );
        let better = match &best {
            None => true,
            Some((best_families, best_stats)) => {
                let best_keys = (
                    *best_families,
                    best_stats.ips.len(),
                    usize::MAX - best_stats.distinct_ips() as usize,
                );
                keys > best_keys
            }
        };
        if better {
            let count = stats.family_count();
            best = Some((count, stats));
        }
    }
    let Some((_, stats)) = best else {
        return ScanResult::default();
    };
    scan.window_requests = stats.ips.len() as u64;
    scan.window_ips = stats.distinct_ips();
    scan.window_families = stats.families;
    scan.window_status = stats.status_distribution();
    if let (Some((first, _)), Some((_, last))) = (stats.min, stats.max) {
        let to_seconds = |value: u64| value.div_euclid(nanos as u64) as i64;
        let first = to_seconds(first);
        let last = to_seconds(last);
        scan.window_first_offset = Some(first);
        scan.window_last_offset = Some(last);
        scan.window_first_seen = raw_time_of(records, first, true);
        scan.window_last_seen = raw_time_of(records, last, false);
    }
    let whole_ok = scan.total_requests >= config.min_requests
        && record_distinct_ips(records) <= config.max_distinct_ips
        && count_any_family(records) >= config.min_families;
    ScanResult {
        window_necessary: !whole_ok,
        best: scan,
    }
}

fn record_distinct_ips(records: &[RequestRecord]) -> u64 {
    let mut ips: Vec<&str> = records.iter().map(|record| record.ip.as_str()).collect();
    ips.sort_unstable();
    ips.dedup();
    ips.len() as u64
}

fn count_any_family(records: &[RequestRecord]) -> usize {
    let mut families = [0_u64; 8];
    for record in records {
        for (into, from) in families.iter_mut().zip(record.hits.iter()) {
            if *from > 0 {
                *into = 1;
            }
        }
    }
    families.iter().filter(|count| **count > 0).count()
}

fn raw_time_of(records: &[RequestRecord], offset: i64, first: bool) -> Option<String> {
    let candidates = records
        .iter()
        .filter(|record| record.time.linear_seconds() == offset);
    let record = if first {
        candidates.min_by_key(|record| record.time.nanos)
    } else {
        candidates.max_by_key(|record| record.time.nanos)
    };
    record.map(|record| record.time.without_offset.clone())
}
