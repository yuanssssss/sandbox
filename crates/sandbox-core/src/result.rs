use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Ok,
    TimeLimitExceeded,
    WallTimeLimitExceeded,
    MemoryLimitExceeded,
    OutputLimitExceeded,
    RuntimeError,
    SandboxError,
}

impl ExecutionStatus {
    pub fn process_exit_code(&self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::RuntimeError => 2,
            Self::TimeLimitExceeded
            | Self::WallTimeLimitExceeded
            | Self::MemoryLimitExceeded
            | Self::OutputLimitExceeded => 3,
            Self::SandboxError => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceUsage {
    pub cpu_time_ms: Option<u64>,
    pub wall_time_ms: u64,
    pub memory_peak_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionResult {
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub term_signal: Option<i32>,
    pub usage: ResourceUsage,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub status: ExecutionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompilationStatus {
    Ok,
    CompilationFailed,
    TimeLimitExceeded,
    WallTimeLimitExceeded,
    MemoryLimitExceeded,
    OutputLimitExceeded,
    SandboxError,
}

impl CompilationStatus {
    pub fn process_exit_code(&self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::CompilationFailed => 2,
            Self::TimeLimitExceeded
            | Self::WallTimeLimitExceeded
            | Self::MemoryLimitExceeded
            | Self::OutputLimitExceeded => 3,
            Self::SandboxError => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompilationResult {
    pub command: Vec<String>,
    pub source_dir: PathBuf,
    pub output_dir: PathBuf,
    pub outputs: Vec<PathBuf>,
    pub exit_code: Option<i32>,
    pub term_signal: Option<i32>,
    pub usage: ResourceUsage,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub status: CompilationStatus,
}
