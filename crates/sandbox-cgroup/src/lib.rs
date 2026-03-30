use std::fs;
use std::path::{Path, PathBuf};

use sandbox_core::{ResourceLimits, ResourceUsage, Result, SandboxError};

const DEFAULT_CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupPlan {
    pub scope_name: String,
    pub limits: ResourceLimits,
}

impl CgroupPlan {
    pub fn new(scope_name: impl Into<String>, limits: ResourceLimits) -> Self {
        Self {
            scope_name: scope_name.into(),
            limits,
        }
    }

    pub fn directory_name(&self) -> String {
        self.scope_name.replace('/', "_")
    }

    pub fn path_under(&self, root: &Path) -> PathBuf {
        root.join(self.directory_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupUsage {
    pub cpu_time_usec: Option<u64>,
    pub memory_current_bytes: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub pids_current: Option<u64>,
}

impl CgroupUsage {
    pub fn into_resource_usage(self, wall_time_ms: u64) -> ResourceUsage {
        ResourceUsage {
            cpu_time_ms: self.cpu_time_usec.map(|value| value / 1_000),
            wall_time_ms,
            memory_peak_bytes: self.memory_peak_bytes.or(self.memory_current_bytes),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupManager {
    root: PathBuf,
}

impl CgroupManager {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn probe_v2_root() -> Result<Self> {
        let root = PathBuf::from(DEFAULT_CGROUP_V2_ROOT);
        ensure_cgroup_v2_root(&root)?;
        Ok(Self::new(root))
    }

    pub fn create(&self, plan: &CgroupPlan) -> Result<PathBuf> {
        ensure_cgroup_v2_root(&self.root)?;
        let path = plan.path_under(&self.root);
        fs::create_dir_all(&path)
            .map_err(|err| SandboxError::io("creating cgroup directory", err))?;
        Ok(path)
    }

    pub fn apply_limits(&self, plan: &CgroupPlan) -> Result<PathBuf> {
        let path = self.create(plan)?;

        if let Some(memory_bytes) = plan.limits.memory_bytes {
            write_control_file(&path.join("memory.max"), &memory_bytes.to_string())?;
            write_control_file(&path.join("memory.swap.max"), "0")?;
        }

        if let Some(max_processes) = plan.limits.max_processes {
            write_control_file(&path.join("pids.max"), &max_processes.to_string())?;
        }

        Ok(path)
    }

    pub fn attach_pid(&self, plan: &CgroupPlan, pid: u32) -> Result<()> {
        let path = plan.path_under(&self.root);
        write_control_file(&path.join("cgroup.procs"), &pid.to_string())
    }

    pub fn read_usage(&self, plan: &CgroupPlan) -> Result<CgroupUsage> {
        let path = plan.path_under(&self.root);
        Ok(CgroupUsage {
            cpu_time_usec: parse_key_value_file(&path.join("cpu.stat"), "usage_usec")?,
            memory_current_bytes: parse_single_u64_file(&path.join("memory.current"))?,
            memory_peak_bytes: parse_single_u64_file(&path.join("memory.peak"))?,
            pids_current: parse_single_u64_file(&path.join("pids.current"))?,
        })
    }

    pub fn cleanup(&self, plan: &CgroupPlan) -> Result<()> {
        let path = plan.path_under(&self.root);
        if !path.exists() {
            return Ok(());
        }

        fs::remove_dir(&path).map_err(|err| SandboxError::io("removing cgroup directory", err))
    }
}

pub fn roadmap() -> &'static str {
    "M3 scaffold: manage cgroup v2 paths, write limits, and collect resource usage."
}

fn ensure_cgroup_v2_root(root: &Path) -> Result<()> {
    if !root.exists() {
        return Err(SandboxError::capability_unavailable(
            "cgroup_v2",
            format!("cgroup root does not exist: {}", root.display()),
        ));
    }

    let controllers = root.join("cgroup.controllers");
    if !controllers.exists() {
        return Err(SandboxError::capability_unavailable(
            "cgroup_v2",
            format!("missing cgroup v2 controller file under {}", root.display()),
        ));
    }

    Ok(())
}

fn write_control_file(path: &Path, value: &str) -> Result<()> {
    fs::write(path, format!("{value}\n"))
        .map_err(|err| SandboxError::io("writing cgroup control file", err))
}

fn parse_single_u64_file(path: &Path) -> Result<Option<u64>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path)
        .map_err(|err| SandboxError::io("reading cgroup stat file", err))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "max" {
        return Ok(None);
    }

    trimmed.parse::<u64>().map(Some).map_err(|err| {
        SandboxError::internal(format!("invalid cgroup numeric value `{trimmed}`: {err}"))
    })
}

fn parse_key_value_file(path: &Path, key: &str) -> Result<Option<u64>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path)
        .map_err(|err| SandboxError::io("reading cgroup stat file", err))?;
    for line in raw.lines() {
        let Some((current_key, value)) = line.split_once(' ') else {
            continue;
        };
        if current_key != key {
            continue;
        }
        if value == "max" {
            return Ok(None);
        }
        return value.parse::<u64>().map(Some).map_err(|err| {
            SandboxError::internal(format!(
                "invalid cgroup key/value entry `{line}` for key `{key}`: {err}"
            ))
        });
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{CgroupManager, CgroupPlan};
    use sandbox_core::ResourceLimits;

    #[test]
    fn resolves_plan_path_under_root() {
        let plan = CgroupPlan::new("jobs/example", ResourceLimits::default());
        let path = plan.path_under(Path::new("/tmp/cgroup-root"));
        assert_eq!(path, PathBuf::from("/tmp/cgroup-root/jobs_example"));
    }

    #[test]
    fn applies_memory_and_pid_limits() {
        let root = unique_dir("cgroup-limits");
        fs::create_dir_all(&root).expect("root should exist");
        fs::write(root.join("cgroup.controllers"), "memory pids")
            .expect("controllers should exist");

        let manager = CgroupManager::new(&root);
        let plan = CgroupPlan::new(
            "job-1",
            ResourceLimits {
                cpu_time_ms: None,
                wall_time_ms: 1000,
                memory_bytes: Some(4096),
                max_processes: Some(32),
            },
        );

        let path = manager.apply_limits(&plan).expect("limits should apply");
        assert_eq!(
            fs::read_to_string(path.join("memory.max")).expect("memory.max should exist"),
            "4096\n"
        );
        assert_eq!(
            fs::read_to_string(path.join("memory.swap.max")).expect("memory.swap.max should exist"),
            "0\n"
        );
        assert_eq!(
            fs::read_to_string(path.join("pids.max")).expect("pids.max should exist"),
            "32\n"
        );
    }

    #[test]
    fn attaches_pid_and_reads_usage() {
        let root = unique_dir("cgroup-usage");
        fs::create_dir_all(&root).expect("root should exist");
        fs::write(root.join("cgroup.controllers"), "memory pids cpu")
            .expect("controllers should exist");

        let manager = CgroupManager::new(&root);
        let plan = CgroupPlan::new("job-2", ResourceLimits::default());
        let path = manager.create(&plan).expect("cgroup should be created");

        manager.attach_pid(&plan, 4242).expect("pid should attach");
        fs::write(path.join("cpu.stat"), "usage_usec 12345\nuser_usec 10000\n")
            .expect("cpu.stat should exist");
        fs::write(path.join("memory.current"), "2048\n").expect("memory.current should exist");
        fs::write(path.join("memory.peak"), "8192\n").expect("memory.peak should exist");
        fs::write(path.join("pids.current"), "3\n").expect("pids.current should exist");

        let usage = manager.read_usage(&plan).expect("usage should read");
        assert_eq!(usage.cpu_time_usec, Some(12_345));
        assert_eq!(usage.memory_current_bytes, Some(2_048));
        assert_eq!(usage.memory_peak_bytes, Some(8_192));
        assert_eq!(usage.pids_current, Some(3));
        assert_eq!(
            fs::read_to_string(path.join("cgroup.procs")).expect("cgroup.procs should exist"),
            "4242\n"
        );
    }

    #[test]
    fn cleanup_removes_directory() {
        let root = unique_dir("cgroup-cleanup");
        fs::create_dir_all(&root).expect("root should exist");
        fs::write(root.join("cgroup.controllers"), "memory pids")
            .expect("controllers should exist");

        let manager = CgroupManager::new(&root);
        let plan = CgroupPlan::new("job-3", ResourceLimits::default());
        let path = manager.create(&plan).expect("cgroup should be created");
        assert!(path.exists());

        manager.cleanup(&plan).expect("cleanup should succeed");
        assert!(!path.exists());
    }

    #[test]
    fn rejects_non_v2_root() {
        let root = unique_dir("cgroup-invalid");
        fs::create_dir_all(&root).expect("root should exist");

        let err = CgroupManager::new(&root)
            .create(&CgroupPlan::new("job-4", ResourceLimits::default()))
            .expect_err("create should fail");
        assert!(err.to_string().contains("cgroup v2"));
    }

    fn unique_dir(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("sandbox-{prefix}-{stamp}"))
    }

    use std::fs;
    use std::path::{Path, PathBuf};
}
