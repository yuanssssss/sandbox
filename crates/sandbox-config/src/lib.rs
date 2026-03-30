use std::fs;
use std::path::{Path, PathBuf};

use sandbox_core::{ResourceLimits, Result, SandboxError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutionConfig {
    pub process: ProcessConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub io: IoConfig,
}

impl ExecutionConfig {
    pub fn from_toml_str(raw: &str) -> Result<Self> {
        let config: Self =
            toml::from_str(raw).map_err(|err| SandboxError::config(err.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(path.as_ref())
            .map_err(|err| SandboxError::io("reading config file", err))?;
        Self::from_toml_str(&raw)
    }

    pub fn validate(&self) -> Result<()> {
        if self.process.argv.is_empty() {
            return Err(SandboxError::config("process.argv must not be empty"));
        }
        if self.limits.wall_time_ms == 0 {
            return Err(SandboxError::config(
                "limits.wall_time_ms must be greater than 0",
            ));
        }
        if matches!(self.limits.cpu_time_ms, Some(0)) {
            return Err(SandboxError::config(
                "limits.cpu_time_ms must be greater than 0",
            ));
        }
        if matches!(self.limits.memory_bytes, Some(0)) {
            return Err(SandboxError::config(
                "limits.memory_bytes must be greater than 0",
            ));
        }
        if matches!(self.limits.max_processes, Some(0)) {
            return Err(SandboxError::config(
                "limits.max_processes must be greater than 0",
            ));
        }

        for entry in &self.process.env {
            parse_env_entry(entry)?;
        }

        Ok(())
    }

    pub fn parsed_env(&self) -> Result<Vec<(String, String)>> {
        self.process
            .env
            .iter()
            .map(|entry| parse_env_entry(entry))
            .collect()
    }

    pub fn resource_limits(&self) -> ResourceLimits {
        ResourceLimits {
            cpu_time_ms: self.limits.cpu_time_ms,
            wall_time_ms: self.limits.wall_time_ms,
            memory_bytes: self.limits.memory_bytes,
            max_processes: self.limits.max_processes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessConfig {
    pub argv: Vec<String>,
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default = "default_clear_env")]
    pub clear_env: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_wall_time_ms")]
    pub wall_time_ms: u64,
    pub cpu_time_ms: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub max_processes: Option<u64>,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            wall_time_ms: default_wall_time_ms(),
            cpu_time_ms: None,
            memory_bytes: None,
            max_processes: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IoConfig {
    pub stdin_path: Option<PathBuf>,
    pub stdout_path: Option<PathBuf>,
    pub stderr_path: Option<PathBuf>,
    pub artifact_dir: Option<PathBuf>,
}

pub fn parse_env_entry(entry: &str) -> Result<(String, String)> {
    let (key, value) = entry
        .split_once('=')
        .ok_or_else(|| SandboxError::config(format!("invalid env entry `{entry}`")))?;
    if key.is_empty() {
        return Err(SandboxError::config(
            "environment variable key must not be empty",
        ));
    }
    Ok((key.to_owned(), value.to_owned()))
}

const fn default_clear_env() -> bool {
    true
}

const fn default_wall_time_ms() -> u64 {
    3_000
}

#[cfg(test)]
mod tests {
    use super::ExecutionConfig;

    #[test]
    fn parses_minimal_config() {
        let raw = r#"
            [process]
            argv = ["/bin/echo", "hello"]

            [limits]
            wall_time_ms = 250
        "#;

        let config = ExecutionConfig::from_toml_str(raw).expect("config should parse");
        assert_eq!(config.process.argv[0], "/bin/echo");
        assert_eq!(config.limits.wall_time_ms, 250);
    }

    #[test]
    fn rejects_empty_argv() {
        let raw = r#"
            [process]
            argv = []
        "#;

        let err = ExecutionConfig::from_toml_str(raw).expect_err("config should fail");
        assert!(err.to_string().contains("process.argv"));
    }
}
