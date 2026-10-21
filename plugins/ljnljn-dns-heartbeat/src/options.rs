//! 分析参数与阈值。
//!
//! **阈值来源**：宿主对 `file_analyzer` 只传 analyzer id 与文件句柄，没有自定义
//! 参数通道（见 SDK `runtime.rs` 的 `analyzer.analyze` 分支）。因此本版的
//! N / tolerance / stability 只能取常量默认值，取值直接来自本次开发需求文本
//! （`N=5`、`tolerance=0.1`、`stability>=0.8`），**不来自任何历史案件**。
//! 需要改动阈值时改这里的常量或调用 [`AnalysisOptions`]，不新增宿主参数 API。

/// 最小样本数 N：同一 (qname, qtype) 至少这么多条查询才参与周期性判定。
pub const DEFAULT_MIN_SAMPLES: usize = 5;
/// 允许抖动比例：窗口为 `[median*(1-tolerance), median*(1+tolerance)]`。
pub const DEFAULT_TOLERANCE: f64 = 0.1;
/// 稳定性阈值：落在容差窗口内的间隔占比需 ≥ 该值。
pub const DEFAULT_STABILITY: f64 = 0.8;
/// 每条域名输出的间隔明细条数上限（前 K 条）。
pub const DEFAULT_DETAIL_LIMIT: usize = 16;

/// 帧时间戳来源。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeSource {
    /// classic pcap 文件头精度（微秒或纳秒魔数）+ `thiszone`。
    PcapHeader,
}

impl TimeSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PcapHeader => "pcap.header",
        }
    }
}

/// 分析参数。
#[derive(Clone, Debug, PartialEq)]
pub struct AnalysisOptions {
    /// 最小样本数 N。
    pub min_samples: usize,
    /// 抖动容差比例（0..=1）。
    pub tolerance: f64,
    /// 稳定性阈值（0..=1）。
    pub stability_threshold: f64,
    /// 间隔明细截断条数 K。
    pub detail_limit: usize,
    /// 可选域名后缀过滤（小写、无前导点）：`name == suffix` 或
    /// `name.ends_with(".suffix")` 才统计。默认 `None`（统计全部域名）。
    pub domain_suffix: Option<String>,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            min_samples: DEFAULT_MIN_SAMPLES,
            tolerance: DEFAULT_TOLERANCE,
            stability_threshold: DEFAULT_STABILITY,
            detail_limit: DEFAULT_DETAIL_LIMIT,
            domain_suffix: None,
        }
    }
}

impl AnalysisOptions {
    /// 校验并规范化后缀（小写、去前导点）。
    pub fn normalized(mut self) -> Result<Self, String> {
        if self.min_samples < 2 {
            return Err(format!("最小样本数需 ≥ 2，当前 {}", self.min_samples));
        }
        if !(0.0..=1.0).contains(&self.tolerance) {
            return Err(format!("tolerance 需在 0..=1，当前 {}", self.tolerance));
        }
        if !(0.0..=1.0).contains(&self.stability_threshold) {
            return Err(format!(
                "stability 阈值需在 0..=1，当前 {}",
                self.stability_threshold
            ));
        }
        if self.detail_limit == 0 {
            return Err("间隔明细条数需 ≥ 1".to_string());
        }
        if let Some(suffix) = self.domain_suffix.take() {
            // 归一化：小写、去掉前后点（`.` 与 `..example.com.` 都应等价于
            // `example.com`），空串视为非法。
            let suffix = suffix.trim().trim_matches('.').to_lowercase();
            if suffix.is_empty() {
                return Err("域名后缀不能为空字符串".to_string());
            }
            self.domain_suffix = Some(suffix);
        }
        Ok(self)
    }

    /// 后缀过滤：`name == suffix` 或 `name` 以 `.suffix` 结尾。
    pub fn suffix_matches(&self, name: &str) -> bool {
        match &self.domain_suffix {
            None => true,
            Some(suffix) => name == suffix || name.ends_with(&format!(".{suffix}")),
        }
    }

    /// 稳定性窗口下界 `median*(1-tolerance)`（不小于 0）。
    pub fn lower_bound(&self, median: f64) -> f64 {
        (median * (1.0 - self.tolerance)).max(0.0)
    }

    /// 稳定性窗口上界 `median*(1+tolerance)`。
    pub fn upper_bound(&self, median: f64) -> f64 {
        median * (1.0 + self.tolerance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_come_from_the_requirement_text() {
        let options = AnalysisOptions::default()
            .normalized()
            .expect("默认参数合法");
        assert_eq!(options.min_samples, 5);
        assert_eq!(options.tolerance, 0.1);
        assert_eq!(options.stability_threshold, 0.8);
        assert_eq!(options.detail_limit, 16);
        assert_eq!(options.domain_suffix, None);
    }

    #[test]
    fn suffix_is_normalized_and_matched_on_label_boundary() {
        let options = AnalysisOptions {
            domain_suffix: Some(".Example.COM.".into()),
            ..AnalysisOptions::default()
        }
        .normalized()
        .expect("后缀合法");
        assert_eq!(options.domain_suffix.as_deref(), Some("example.com"));
        assert!(options.suffix_matches("a.example.com"));
        assert!(options.suffix_matches("example.com"));
        // 标签边界：badexample.com 不匹配 example.com。
        assert!(!options.suffix_matches("badexample.com"));
    }

    #[test]
    fn invalid_options_are_rejected() {
        for options in [
            AnalysisOptions {
                min_samples: 1,
                ..AnalysisOptions::default()
            },
            AnalysisOptions {
                tolerance: 1.5,
                ..AnalysisOptions::default()
            },
            AnalysisOptions {
                stability_threshold: -0.1,
                ..AnalysisOptions::default()
            },
            AnalysisOptions {
                detail_limit: 0,
                ..AnalysisOptions::default()
            },
            AnalysisOptions {
                domain_suffix: Some(" .. ".into()),
                ..AnalysisOptions::default()
            },
        ] {
            assert!(
                options.clone().normalized().is_err(),
                "{options:?} 应被拒绝"
            );
        }
    }

    #[test]
    fn stability_bounds_follow_the_median() {
        let options = AnalysisOptions::default();
        assert!((options.lower_bound(3.0) - 2.7).abs() < 1e-12);
        assert!((options.upper_bound(3.0) - 3.3).abs() < 1e-12);
        assert_eq!(options.lower_bound(0.5), 0.45);
    }
}
