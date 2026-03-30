use std::fs;
use std::path::{Path, PathBuf};

use sandbox_core::{ResourceLimits, Result, SandboxError};
use sandbox_seccomp::SeccompProfile;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutionConfig {
    pub process: ProcessConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub io: IoConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub filesystem: FilesystemConfig,
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
        self.filesystem.validate()?;

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    #[serde(default)]
    pub seccomp_profile: SeccompProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemConfig {
    #[serde(default = "default_rootfs_enabled")]
    pub enable_rootfs: bool,
    pub rootfs_dir: Option<PathBuf>,
    #[serde(default = "default_enter_user_namespace")]
    pub enter_user_namespace: bool,
    #[serde(default = "default_enter_mount_namespace")]
    pub enter_mount_namespace: bool,
    #[serde(default = "default_enter_pid_namespace")]
    pub enter_pid_namespace: bool,
    #[serde(default = "default_enter_network_namespace")]
    pub enter_network_namespace: bool,
    #[serde(default = "default_enter_ipc_namespace")]
    pub enter_ipc_namespace: bool,
    #[serde(default = "default_apply_mounts")]
    pub apply_mounts: bool,
    #[serde(default = "default_chroot_to_rootfs")]
    pub chroot_to_rootfs: bool,
    #[serde(default = "default_inside_uid")]
    pub inside_uid: u32,
    #[serde(default = "default_inside_gid")]
    pub inside_gid: u32,
    pub outside_uid: Option<u32>,
    pub outside_gid: Option<u32>,
    #[serde(default = "default_deny_setgroups")]
    pub deny_setgroups: bool,
    #[serde(default = "default_drop_capabilities")]
    pub drop_capabilities: bool,
    #[serde(default = "default_work_dir")]
    pub work_dir: PathBuf,
    #[serde(default = "default_tmp_dir")]
    pub tmp_dir: PathBuf,
    #[serde(default = "default_runtime_bind_paths")]
    pub runtime_bind_paths: Vec<PathBuf>,
    #[serde(default)]
    pub executable_bind_paths: Vec<PathBuf>,
    #[serde(default = "default_mount_proc")]
    pub mount_proc: bool,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            enable_rootfs: default_rootfs_enabled(),
            rootfs_dir: None,
            enter_user_namespace: default_enter_user_namespace(),
            enter_mount_namespace: default_enter_mount_namespace(),
            enter_pid_namespace: default_enter_pid_namespace(),
            enter_network_namespace: default_enter_network_namespace(),
            enter_ipc_namespace: default_enter_ipc_namespace(),
            apply_mounts: default_apply_mounts(),
            chroot_to_rootfs: default_chroot_to_rootfs(),
            inside_uid: default_inside_uid(),
            inside_gid: default_inside_gid(),
            outside_uid: None,
            outside_gid: None,
            deny_setgroups: default_deny_setgroups(),
            drop_capabilities: default_drop_capabilities(),
            work_dir: default_work_dir(),
            tmp_dir: default_tmp_dir(),
            runtime_bind_paths: default_runtime_bind_paths(),
            executable_bind_paths: Vec::new(),
            mount_proc: default_mount_proc(),
        }
    }
}

impl FilesystemConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.enable_rootfs {
            return Ok(());
        }
        if self.apply_mounts && !self.enter_mount_namespace {
            return Err(SandboxError::config(
                "filesystem.apply_mounts requires filesystem.enter_mount_namespace = true",
            ));
        }
        if self.enter_mount_namespace && !self.enter_user_namespace {
            return Err(SandboxError::config(
                "filesystem.enter_mount_namespace requires filesystem.enter_user_namespace = true",
            ));
        }
        if self.enter_pid_namespace && !self.enter_mount_namespace {
            return Err(SandboxError::config(
                "filesystem.enter_pid_namespace requires filesystem.enter_mount_namespace = true",
            ));
        }
        if self.enter_network_namespace && !self.enter_mount_namespace {
            return Err(SandboxError::config(
                "filesystem.enter_network_namespace requires filesystem.enter_mount_namespace = true",
            ));
        }
        if self.enter_ipc_namespace && !self.enter_mount_namespace {
            return Err(SandboxError::config(
                "filesystem.enter_ipc_namespace requires filesystem.enter_mount_namespace = true",
            ));
        }
        if self.chroot_to_rootfs && !self.apply_mounts {
            return Err(SandboxError::config(
                "filesystem.chroot_to_rootfs requires filesystem.apply_mounts = true",
            ));
        }
        if !self.enter_user_namespace
            && (self.outside_uid.is_some()
                || self.outside_gid.is_some()
                || self.inside_uid != 0
                || self.inside_gid != 0
                || !self.deny_setgroups)
        {
            return Err(SandboxError::config(
                "user namespace identity mapping options require filesystem.enter_user_namespace = true",
            ));
        }

        if !self.work_dir.is_absolute() {
            return Err(SandboxError::config(
                "filesystem.work_dir must be an absolute path",
            ));
        }
        if !self.tmp_dir.is_absolute() {
            return Err(SandboxError::config(
                "filesystem.tmp_dir must be an absolute path",
            ));
        }

        for path in &self.runtime_bind_paths {
            if !path.is_absolute() {
                return Err(SandboxError::config(format!(
                    "filesystem.runtime_bind_paths must contain absolute paths: {}",
                    path.display()
                )));
            }
        }

        for path in &self.executable_bind_paths {
            if !path.is_absolute() {
                return Err(SandboxError::config(format!(
                    "filesystem.executable_bind_paths must contain absolute paths: {}",
                    path.display()
                )));
            }
        }

        Ok(())
    }
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

const fn default_rootfs_enabled() -> bool {
    true
}

const fn default_enter_mount_namespace() -> bool {
    false
}

const fn default_enter_user_namespace() -> bool {
    false
}

const fn default_enter_pid_namespace() -> bool {
    false
}

const fn default_enter_network_namespace() -> bool {
    false
}

const fn default_enter_ipc_namespace() -> bool {
    false
}

const fn default_apply_mounts() -> bool {
    false
}

const fn default_chroot_to_rootfs() -> bool {
    false
}

const fn default_inside_uid() -> u32 {
    0
}

const fn default_inside_gid() -> u32 {
    0
}

const fn default_deny_setgroups() -> bool {
    true
}

const fn default_drop_capabilities() -> bool {
    true
}

fn default_work_dir() -> PathBuf {
    PathBuf::from("/work")
}

fn default_tmp_dir() -> PathBuf {
    PathBuf::from("/tmp")
}

fn default_runtime_bind_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/usr/lib"),
    ]
}

const fn default_mount_proc() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::ExecutionConfig;
    use sandbox_seccomp::SeccompProfile;

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

    #[test]
    fn applies_filesystem_defaults() {
        let raw = r#"
            [process]
            argv = ["/bin/echo", "hello"]
        "#;

        let config = ExecutionConfig::from_toml_str(raw).expect("config should parse");
        assert!(config.filesystem.enable_rootfs);
        assert_eq!(config.security.seccomp_profile, SeccompProfile::Default);
        assert!(!config.filesystem.enter_user_namespace);
        assert!(!config.filesystem.enter_mount_namespace);
        assert!(!config.filesystem.enter_pid_namespace);
        assert!(!config.filesystem.enter_network_namespace);
        assert!(!config.filesystem.enter_ipc_namespace);
        assert!(!config.filesystem.apply_mounts);
        assert!(!config.filesystem.chroot_to_rootfs);
        assert_eq!(config.filesystem.inside_uid, 0);
        assert_eq!(config.filesystem.inside_gid, 0);
        assert_eq!(config.filesystem.outside_uid, None);
        assert_eq!(config.filesystem.outside_gid, None);
        assert!(config.filesystem.deny_setgroups);
        assert!(config.filesystem.drop_capabilities);
        assert_eq!(config.filesystem.work_dir, PathBuf::from("/work"));
        assert_eq!(config.filesystem.tmp_dir, PathBuf::from("/tmp"));
        assert!(config.filesystem.mount_proc);
        assert_eq!(config.filesystem.runtime_bind_paths.len(), 3);
        assert!(config.filesystem.executable_bind_paths.is_empty());
    }

    #[test]
    fn rejects_relative_runtime_bind_path() {
        let raw = r#"
            [process]
            argv = ["/bin/echo", "hello"]

            [filesystem]
            runtime_bind_paths = ["usr/lib"]
        "#;

        let err = ExecutionConfig::from_toml_str(raw).expect_err("config should fail");
        assert!(err.to_string().contains("runtime_bind_paths"));
    }

    #[test]
    fn rejects_relative_executable_bind_path() {
        let raw = r#"
            [process]
            argv = ["/bin/echo", "hello"]

            [filesystem]
            executable_bind_paths = ["bin"]
        "#;

        let err = ExecutionConfig::from_toml_str(raw).expect_err("config should fail");
        assert!(err.to_string().contains("executable_bind_paths"));
    }

    #[test]
    fn rejects_apply_mounts_without_mount_namespace() {
        let raw = r#"
            [process]
            argv = ["/bin/echo", "hello"]

            [filesystem]
            apply_mounts = true
        "#;

        let err = ExecutionConfig::from_toml_str(raw).expect_err("config should fail");
        assert!(err.to_string().contains("enter_mount_namespace"));
    }

    #[test]
    fn rejects_mount_namespace_without_user_namespace() {
        let raw = r#"
            [process]
            argv = ["/bin/echo", "hello"]

            [filesystem]
            enter_mount_namespace = true
        "#;

        let err = ExecutionConfig::from_toml_str(raw).expect_err("config should fail");
        assert!(err.to_string().contains("enter_user_namespace"));
    }

    #[test]
    fn rejects_user_mapping_without_user_namespace() {
        let raw = r#"
            [process]
            argv = ["/bin/echo", "hello"]

            [filesystem]
            outside_uid = 1000
        "#;

        let err = ExecutionConfig::from_toml_str(raw).expect_err("config should fail");
        assert!(err.to_string().contains("identity mapping"));
    }

    #[test]
    fn rejects_pid_namespace_without_mount_namespace() {
        let raw = r#"
            [process]
            argv = ["/bin/echo", "hello"]

            [filesystem]
            enter_pid_namespace = true
        "#;

        let err = ExecutionConfig::from_toml_str(raw).expect_err("config should fail");
        assert!(err.to_string().contains("enter_mount_namespace"));
    }

    #[test]
    fn rejects_network_namespace_without_mount_namespace() {
        let raw = r#"
            [process]
            argv = ["/bin/echo", "hello"]

            [filesystem]
            enter_network_namespace = true
        "#;

        let err = ExecutionConfig::from_toml_str(raw).expect_err("config should fail");
        assert!(err.to_string().contains("enter_mount_namespace"));
    }

    #[test]
    fn rejects_ipc_namespace_without_mount_namespace() {
        let raw = r#"
            [process]
            argv = ["/bin/echo", "hello"]

            [filesystem]
            enter_ipc_namespace = true
        "#;

        let err = ExecutionConfig::from_toml_str(raw).expect_err("config should fail");
        assert!(err.to_string().contains("enter_mount_namespace"));
    }

    #[test]
    fn rejects_chroot_without_mounts() {
        let raw = r#"
            [process]
            argv = ["/bin/echo", "hello"]

            [filesystem]
            enter_user_namespace = true
            enter_mount_namespace = true
            chroot_to_rootfs = true
        "#;

        let err = ExecutionConfig::from_toml_str(raw).expect_err("config should fail");
        assert!(err.to_string().contains("apply_mounts"));
    }
}
