//! 心跳统计：按 (qname, qtype) 分组 → 时间排序 → 相邻间隔统计 → 周期性判定。
//!
//! 每条域名输出的指标（与需求输出字段一一对应）：
//! `queryCount`、`firstTs/lastTs`、`intervalMedianSec`、`intervalMeanSec`、
//! `intervalStdevSec`、`intervalMinSec`、`intervalMaxSec`、`stability`、
//! `periodic`、`candidateScore` 与间隔明细的前 K 条。
//!
//! 严格有界：单个分组的查询条数上限 [`MAX_QUERIES_PER_GROUP`]，超出后仍然
//! 计数但不再保留时间戳，并记录被截断的条数；明细只保留 `detail_limit` 条。

use std::collections::BTreeMap;

use crate::options::AnalysisOptions;

/// 单个分组保留的时间戳上限（内存上界）。
pub const MAX_QUERIES_PER_GROUP: usize = 65_536;
/// 输出的间隔明细条数上限（防止结果项过大）。
pub const MAX_DETAIL_LIMIT: usize = 64;

/// 一次 DNS 查询事件。
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct QueryHit {
    /// epoch 秒（`ts_sec + ts_frac/分辨率`）。
    pub epoch: f64,
    /// 该记录是否属于乱序报文（原始时间戳保留，排序后使用）。
    pub out_of_order: bool,
    /// 源记录在抓包文件中的槽位号（0 起，文件顺序）。
    pub slot: u64,
    /// 源记录在抓包文件中的字节偏移。
    pub offset: u64,
    /// 该记录在抓包文件中的结束偏移（不含），用于记录级来源区间。
    pub end: u64,
}

/// 预聚合结果：供输出层格式化。
#[derive(Clone, Debug, PartialEq)]
pub struct GroupStats {
    pub qname: String,
    pub qtype: u16,
    /// 序号（按查询条数降序、名字升序排列后的位次，从 1 开始）。
    pub rank: usize,
    pub query_count: u64,
    /// 被保留时间戳的条数（≤ MAX_QUERIES_PER_GROUP）。
    pub sampled: usize,
    /// 因上限未保留的条数。
    pub truncated: u64,
    /// 乱序记录的条数。
    pub out_of_order: u64,
    pub first_epoch: f64,
    pub last_epoch: f64,
    pub interval_count: u64,
    pub interval_mean: f64,
    pub interval_stdev: f64,
    pub interval_min: f64,
    pub interval_max: f64,
    pub interval_median: f64,
    /// 落在 [median*(1-tol), median*(1+tol)] 内的间隔占比。
    pub stability: f64,
    pub periodic: bool,
    /// 是否因样本不足而未判定（`query_count < N`）。
    pub insufficient_samples: bool,
    /// 候选定级 0..=1。
    pub candidate_score: f64,
    /// 间隔明细（前 K 条，按时间顺序）。
    pub detail: Vec<f64>,
    /// 明细被截断的条数。
    pub detail_omitted: u64,
    /// 是否全部来自单一时间戳（interval 数为 0）。
    pub zero_intervals: bool,
    /// 该分组最早一帧的源记录槽位。
    pub first_slot: u64,
    /// 该分组最晚一帧的源记录槽位。
    pub last_slot: u64,
    /// 该分组最早一帧的抓包文件字节偏移。
    pub first_offset: u64,
    /// 该分组最晚一帧的抓包文件字节偏移。
    pub last_offset: u64,
    /// 该分组最晚一帧记录在抓包文件中的结束偏移（不含）。
    pub last_end: u64,
}

/// 每个域名的聚合桶。
#[derive(Debug, Default)]
pub struct Bucket {
    count: u64,
    truncated: u64,
    out_of_order: u64,
    /// (时间, 槽位, 偏移, 结束偏移)，超限后不再保留。
    epochs: Vec<(f64, u64, u64, u64)>,
}

/// (qname, qtype) → 聚合桶。
pub type Groups = BTreeMap<(String, u16), Bucket>;

#[cfg(test)]
impl QueryHit {
    /// 测试辅助：槽位按时间顺序推导。
    fn test(epoch: f64) -> Self {
        Self::at(epoch, false, epoch.max(0.0) as u64)
    }

    fn at(epoch: f64, out_of_order: bool, slot: u64) -> Self {
        let offset = 24 + slot * 64;
        Self {
            epoch,
            out_of_order,
            slot,
            offset,
            end: offset + 64,
        }
    }
}

/// 记录一次查询；超过上限后只计数。
pub fn record(groups: &mut Groups, qname: &str, qtype: u16, hit: QueryHit) {
    let bucket = groups
        .entry((qname.to_string(), qtype))
        .or_insert_with(Bucket::default);
    bucket.count += 1;
    if hit.out_of_order {
        bucket.out_of_order += 1;
    }
    if bucket.epochs.len() < MAX_QUERIES_PER_GROUP {
        bucket
            .epochs
            .push((hit.epoch, hit.slot, hit.offset, hit.end));
    } else {
        bucket.truncated += 1;
    }
}

/// 对全部桶做统计，并按 queryCount 降序、qname 升序、qtype 升序排序。
pub fn analyze(groups: Groups, options: &AnalysisOptions) -> Vec<GroupStats> {
    let mut stats: Vec<GroupStats> = groups
        .into_iter()
        .map(|((qname, qtype), bucket)| group_stats(qname, qtype, bucket, options))
        .collect();
    stats.sort_by(|left, right| {
        right
            .query_count
            .cmp(&left.query_count)
            .then_with(|| left.qname.cmp(&right.qname))
            .then_with(|| left.qtype.cmp(&right.qtype))
    });
    for (index, item) in stats.iter_mut().enumerate() {
        item.rank = index + 1;
    }
    stats
}

fn group_stats(qname: String, qtype: u16, bucket: Bucket, options: &AnalysisOptions) -> GroupStats {
    let mut samples = bucket.epochs;
    // 乱序：先排序，原始值不变；相同时间戳保留（slot 作次键保证稳定）。
    samples.sort_by(|left, right| {
        left.0
            .partial_cmp(&right.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.1.cmp(&right.1))
    });
    let epochs: Vec<f64> = samples.iter().map(|sample| sample.0).collect();
    let intervals: Vec<f64> = epochs.windows(2).map(|pair| pair[1] - pair[0]).collect();
    let sampled = epochs.len();
    let first_epoch = epochs.first().copied().unwrap_or(0.0);
    let last_epoch = epochs.last().copied().unwrap_or(0.0);
    // 来源区间按文件顺序取最小/最大槽位与偏移；时间排序只用于间隔统计。
    let first_slot = samples.iter().map(|sample| sample.1).min().unwrap_or(0);
    let last_slot = samples.iter().map(|sample| sample.1).max().unwrap_or(0);
    let first_offset = samples.iter().map(|sample| sample.2).min().unwrap_or(0);
    let last_offset = samples.iter().map(|sample| sample.2).max().unwrap_or(0);
    let last_end = samples.iter().map(|sample| sample.3).max().unwrap_or(0);
    let zero_intervals = intervals.is_empty();

    let interval_count = intervals.len() as u64;
    let interval_mean = if intervals.is_empty() {
        0.0
    } else {
        intervals.iter().sum::<f64>() / intervals.len() as f64
    };
    let interval_stdev = if intervals.len() < 2 {
        0.0
    } else {
        let variance = intervals
            .iter()
            .map(|value| (value - interval_mean) * (value - interval_mean))
            .sum::<f64>()
            / (intervals.len() as f64 - 1.0);
        variance.sqrt()
    };
    let interval_min = intervals.iter().copied().fold(f64::INFINITY, f64::min);
    let interval_max = intervals.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let interval_median = median(&intervals);

    // 稳定性：以 median 为基线的容差窗口占比；median<=0 时无法定义，记 0。
    let stability = if interval_median > 0.0 {
        let low = options.lower_bound(interval_median);
        let high = options.upper_bound(interval_median);
        let inside = intervals
            .iter()
            .filter(|value| **value >= low && **value <= high)
            .count();
        inside as f64 / intervals.len() as f64
    } else {
        0.0
    };

    let insufficient_samples = bucket.count < options.min_samples as u64;
    let periodic = !insufficient_samples
        && interval_median > 0.0
        && !zero_intervals
        && stability >= options.stability_threshold;

    let candidate_score = candidate_score(stability, interval_median, &intervals.len());
    let detail_limit = options.detail_limit.min(MAX_DETAIL_LIMIT);
    let detail: Vec<f64> = intervals.iter().take(detail_limit).copied().collect();
    let detail_omitted = interval_count.saturating_sub(detail.len() as u64);

    GroupStats {
        qname,
        qtype,
        rank: 0,
        query_count: bucket.count,
        sampled,
        truncated: bucket.truncated,
        out_of_order: bucket.out_of_order,
        first_epoch,
        last_epoch,
        interval_count,
        interval_mean,
        interval_stdev,
        interval_min: if interval_min.is_finite() {
            interval_min
        } else {
            0.0
        },
        interval_max: if interval_max.is_finite() {
            interval_max
        } else {
            0.0
        },
        interval_median,
        stability,
        periodic,
        insufficient_samples,
        candidate_score,
        detail,
        detail_omitted,
        zero_intervals,
        first_slot,
        last_slot,
        first_offset,
        last_offset,
        last_end,
    }
}

/// 候选定级：`stability × 样本量饱和因子`。样本量越少越保守。
fn candidate_score(stability: f64, median: f64, interval_count: &usize) -> f64 {
    if median <= 0.0 || *interval_count == 0 {
        return 0.0;
    }
    let sample_factor = (*interval_count as f64 / (*interval_count as f64 + 2.0)).clamp(0.0, 1.0);
    (stability * sample_factor).clamp(0.0, 1.0)
}

/// 中位数：偶数个取中间两数平均；空集返回 0。
pub fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(epochs: &[f64]) -> Groups {
        let mut groups = Groups::new();
        for epoch in epochs {
            record(&mut groups, "a.example", 1, QueryHit::test(*epoch));
        }
        groups
    }

    #[test]
    fn fixed_three_second_heartbeat_is_periodic() {
        let epochs: Vec<f64> = (0..8).map(|index| 1000.0 + index as f64 * 3.0).collect();
        let stats = analyze(hits(&epochs), &AnalysisOptions::default());
        assert_eq!(stats.len(), 1);
        let group = &stats[0];
        assert_eq!(group.query_count, 8);
        assert_eq!(group.interval_count, 7);
        assert!((group.interval_median - 3.0).abs() < 1e-9);
        assert!((group.interval_mean - 3.0).abs() < 1e-9);
        assert_eq!(group.interval_stdev, 0.0);
        assert!((group.stability - 1.0).abs() < 1e-9);
        assert!(group.periodic);
        assert!(!group.insufficient_samples);
        assert!(group.candidate_score > 0.5);
        assert_eq!(group.detail.len(), 7);
        assert_eq!(group.detail_omitted, 0);
    }

    #[test]
    fn irregular_intervals_are_not_periodic() {
        let epochs = [0.0, 3.1, 11.0, 12.0, 30.0, 31.0, 60.0];
        let stats = analyze(hits(&epochs), &AnalysisOptions::default());
        assert!(!stats[0].periodic);
        assert!(stats[0].stability < 0.8);
    }

    #[test]
    fn one_missing_sample_doubles_an_interval_and_lowers_stability() {
        // 每 3s 一条，其中第 5 条缺失 → 出现一个 6s 间隔。
        let epochs = [0.0, 3.0, 6.0, 9.0, 15.0, 18.0, 21.0, 24.0];
        let stats = analyze(hits(&epochs), &AnalysisOptions::default());
        let group = &stats[0];
        assert_eq!(group.interval_count, 7);
        assert_eq!(group.intervals_outside_count(&[6.0]), 1);
        assert!(
            (group.stability - 6.0 / 7.0).abs() < 1e-9,
            "stability={}",
            group.stability
        );
        assert!(group.stability < 1.0, "{}", group.stability);
        // median 仍为 3s；6s 间隔超出 10% 容差窗口，故 stability = 6/7。
        assert!((group.interval_median - 3.0).abs() < 1e-9);
        // 6/7 ≈ 0.857 仍 ≥ 0.8：本组仍被判周期性（这是"可容忍一次缺失"的边界），
        // 但稳定性相对规律心跳（1.0）明显下降。
        assert!(group.periodic);
        assert!(
            group.stability
                < analyze(
                    hits(&[0.0, 3.0, 6.0, 9.0, 12.0, 15.0, 18.0, 21.0]),
                    &AnalysisOptions::default()
                )[0]
                .stability
        );
        // 收紧 stability 阈值到 0.9 后即不再判周期。
        let strict = analyze(
            hits(&epochs),
            &AnalysisOptions {
                stability_threshold: 0.9,
                ..AnalysisOptions::default()
            },
        );
        assert!(!strict[0].periodic);
        // 容差放宽到 1.0（不限制抖动）后可容忍。
        let tolerant = analyze(
            hits(&epochs),
            &AnalysisOptions {
                tolerance: 1.0,
                ..AnalysisOptions::default()
            },
        );
        assert!(tolerant[0].periodic);
    }

    #[test]
    fn fewer_than_n_samples_is_never_periodic() {
        let stats = analyze(hits(&[0.0, 3.0, 6.0, 9.0]), &AnalysisOptions::default());
        assert_eq!(stats[0].query_count, 4);
        assert!(stats[0].insufficient_samples);
        assert!(!stats[0].periodic);
        let stats = analyze(hits(&[5.0]), &AnalysisOptions::default());
        assert!(stats[0].zero_intervals);
        assert_eq!(stats[0].interval_median, 0.0);
        assert!(!stats[0].periodic);
    }

    #[test]
    fn out_of_order_timestamps_are_sorted_and_intervals_stay_positive() {
        let epochs = [9.0, 0.0, 6.0, 3.0, 12.0];
        let mut groups = Groups::new();
        for (index, epoch) in epochs.iter().enumerate() {
            record(
                &mut groups,
                "b.example",
                1,
                QueryHit::at(*epoch, index == 1 || index == 3, index as u64),
            );
        }
        let stats = analyze(groups, &AnalysisOptions::default());
        let group = &stats[0];
        assert_eq!(group.first_epoch, 0.0);
        assert_eq!(group.last_epoch, 12.0);
        assert_eq!(group.out_of_order, 2);
        assert!(group.detail.iter().all(|interval| *interval > 0.0));
        assert!((group.interval_median - 3.0).abs() < 1e-9);
    }

    #[test]
    fn grouping_is_per_qname_and_qtype() {
        let mut groups = Groups::new();
        for epoch in [0.0, 3.0, 6.0] {
            record(&mut groups, "a.example", 1, QueryHit::test(epoch));
            record(&mut groups, "a.example", 28, QueryHit::test(epoch));
        }
        let stats = analyze(groups, &AnalysisOptions::default());
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[0].qtype, 1);
        assert_eq!(stats[1].qtype, 28);
        assert_eq!(stats[0].rank, 1);
        assert_eq!(stats[1].rank, 2);
    }

    #[test]
    fn detail_is_capped_by_the_option() {
        let epochs: Vec<f64> = (0..40).map(|index| index as f64 * 3.0).collect();
        let stats = analyze(
            hits(&epochs),
            &AnalysisOptions {
                detail_limit: 5,
                ..AnalysisOptions::default()
            },
        );
        assert_eq!(stats[0].detail.len(), 5);
        assert_eq!(stats[0].detail_omitted, 34);
        assert_eq!(stats[0].interval_count, 39);
    }

    #[test]
    fn per_group_cap_is_enforced_and_counted() {
        let mut groups = Groups::new();
        for index in 0..(MAX_QUERIES_PER_GROUP + 10) {
            record(&mut groups, "cap.example", 1, QueryHit::test(index as f64));
        }
        let stats = analyze(groups, &AnalysisOptions::default());
        assert_eq!(stats[0].query_count, (MAX_QUERIES_PER_GROUP + 10) as u64);
        assert_eq!(stats[0].sampled, MAX_QUERIES_PER_GROUP);
        assert_eq!(stats[0].truncated, 10);
    }

    #[test]
    fn median_handles_even_odd_and_empty_inputs() {
        assert_eq!(median(&[]), 0.0);
        assert_eq!(median(&[5.0]), 5.0);
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), 2.5);
    }

    impl GroupStats {
        /// 测试辅助：给定间隔值里**超出**容差窗口的条数。
        fn intervals_outside_count(&self, values: &[f64]) -> usize {
            let low = self.interval_median * 0.9;
            let high = self.interval_median * 1.1;
            values
                .iter()
                .filter(|value| **value < low || **value > high)
                .count()
        }
    }
}
