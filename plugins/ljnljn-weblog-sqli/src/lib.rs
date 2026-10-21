//! LovelyCarve offline Web-access-log analyzer: query-parameter SQL-injection
//! feature detection.
//!
//! Layers (all pure except `analyzer`):
//!
//! * [`model`] — configuration, data types, the explainable feature families
//!   and the timezone-free time arithmetic.
//! * [`logline`] — line layout (Apache/Nginx `combined`/`common` plus other
//!   lines that still carry `ip - - [time] "METHOD target HTTP/x" status
//!   bytes`), field-mapping overrides, timestamp parsing, `%XX` decoding.
//! * [`detect`] — feature-family matching on decoded values and the sliding
//!   window scan (requests, distinct client IPs, families per window).
//! * [`aggregate`] — per-`(path, param)` statistics, candidates, confidence
//!   and limitations.
//! * [`analyzer`] — the `file_analyzer` / `evidence_analyzer` bindings over
//!   read-only SDK handles.
//!
//! Nothing here executes evidence, touches the network, or carries
//! case-specific parameter names, times, IPs or accounts.

pub mod aggregate;
pub mod analyzer;
pub mod detect;
pub mod logline;
pub mod model;

pub use analyzer::{WebLogAnalyzer, ANALYZER, NS, PLUGIN_ID};
pub use model::{Config, Family, Mapping};
