use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    pub cpu_time_ms: Option<u64>,
    pub wall_time_ms: u64,
    pub memory_bytes: Option<u64>,
    pub max_processes: Option<u64>,
}
