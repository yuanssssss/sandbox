use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SeccompProfile {
    Default,
    Strict,
    Compat,
}

impl Default for SeccompProfile {
    fn default() -> Self {
        Self::Default
    }
}

pub fn roadmap() -> &'static str {
    "M4 scaffold: model seccomp profiles and install syscall filters as defense in depth."
}
