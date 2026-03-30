use std::fs;
use std::path::{Component, Path, PathBuf};

use sandbox_config::FilesystemConfig;
use sandbox_core::{Result, SandboxError};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RootfsLayout {
    pub root: PathBuf,
    pub host_work_dir: PathBuf,
    pub host_tmp_dir: PathBuf,
    pub sandbox_work_dir: PathBuf,
    pub sandbox_tmp_dir: PathBuf,
    pub sandbox_proc_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountKind {
    BindReadOnly,
    BindReadWrite,
    Tmpfs,
    Proc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountPlanEntry {
    pub kind: MountKind,
    pub source: Option<PathBuf>,
    pub target: PathBuf,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsPlan {
    pub layout: RootfsLayout,
    pub mounts: Vec<MountPlanEntry>,
}

impl RootfsPlan {
    pub fn mount_count(&self) -> usize {
        self.mounts.len()
    }
}

pub fn prepare_rootfs(config: &FilesystemConfig, artifact_dir: &Path) -> Result<RootfsPlan> {
    if !config.enable_rootfs {
        return Err(SandboxError::config(
            "filesystem.enable_rootfs must be true to prepare a rootfs scaffold",
        ));
    }

    config.validate()?;

    let layout = RootfsLayout {
        root: config
            .rootfs_dir
            .clone()
            .unwrap_or_else(|| artifact_dir.join("rootfs")),
        host_work_dir: artifact_dir.join("work"),
        host_tmp_dir: artifact_dir.join("tmp"),
        sandbox_work_dir: config.work_dir.clone(),
        sandbox_tmp_dir: config.tmp_dir.clone(),
        sandbox_proc_dir: config.mount_proc.then(|| PathBuf::from("/proc")),
    };

    materialize_rootfs_layout(&layout)?;

    let mut mounts = Vec::new();
    for source in &config.runtime_bind_paths {
        if source.exists() {
            mounts.push(MountPlanEntry {
                kind: MountKind::BindReadOnly,
                source: Some(source.clone()),
                target: source.clone(),
                flags: vec!["ro".into(), "rbind".into()],
            });
            materialize_mount_target(&layout.root, source)?;
        }
    }

    mounts.push(MountPlanEntry {
        kind: MountKind::BindReadWrite,
        source: Some(layout.host_work_dir.clone()),
        target: layout.sandbox_work_dir.clone(),
        flags: vec!["rw".into(), "rbind".into(), "nodev".into(), "nosuid".into()],
    });
    materialize_mount_target(&layout.root, &layout.sandbox_work_dir)?;

    mounts.push(MountPlanEntry {
        kind: MountKind::Tmpfs,
        source: None,
        target: layout.sandbox_tmp_dir.clone(),
        flags: vec![
            "rw".into(),
            "nodev".into(),
            "nosuid".into(),
            "noexec".into(),
        ],
    });
    materialize_mount_target(&layout.root, &layout.sandbox_tmp_dir)?;

    if let Some(proc_dir) = &layout.sandbox_proc_dir {
        mounts.push(MountPlanEntry {
            kind: MountKind::Proc,
            source: None,
            target: proc_dir.clone(),
            flags: vec!["nosuid".into(), "nodev".into(), "noexec".into()],
        });
        materialize_mount_target(&layout.root, proc_dir)?;
    }

    Ok(RootfsPlan { layout, mounts })
}

fn materialize_rootfs_layout(layout: &RootfsLayout) -> Result<()> {
    fs::create_dir_all(&layout.root)
        .map_err(|err| SandboxError::io("creating rootfs root", err))?;
    fs::create_dir_all(&layout.host_work_dir)
        .map_err(|err| SandboxError::io("creating host work directory", err))?;
    fs::create_dir_all(&layout.host_tmp_dir)
        .map_err(|err| SandboxError::io("creating host tmp directory", err))?;

    materialize_mount_target(&layout.root, &layout.sandbox_work_dir)?;
    materialize_mount_target(&layout.root, &layout.sandbox_tmp_dir)?;
    if let Some(proc_dir) = &layout.sandbox_proc_dir {
        materialize_mount_target(&layout.root, proc_dir)?;
    }

    Ok(())
}

fn materialize_mount_target(root: &Path, sandbox_path: &Path) -> Result<()> {
    let relative = relative_sandbox_path(sandbox_path)?;
    let target = root.join(relative);
    fs::create_dir_all(&target)
        .map_err(|err| SandboxError::io("creating rootfs mount target", err))?;
    Ok(())
}

fn relative_sandbox_path(path: &Path) -> Result<PathBuf> {
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => relative.push(part),
            _ => {
                return Err(SandboxError::config(format!(
                    "unsupported sandbox path `{}`",
                    path.display()
                )));
            }
        }
    }

    if relative.as_os_str().is_empty() {
        return Err(SandboxError::config("sandbox path must not point to `/`"));
    }

    Ok(relative)
}

pub fn roadmap() -> &'static str {
    "M2 scaffold: build minimal rootfs, bind runtime libraries, and manage mount cleanup."
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use sandbox_config::FilesystemConfig;

    use crate::{MountKind, prepare_rootfs};

    #[test]
    fn prepares_rootfs_layout_and_mounts() {
        let artifact_dir = unique_dir("rootfs");
        let config = FilesystemConfig::default();

        let plan = prepare_rootfs(&config, &artifact_dir).expect("rootfs scaffold should build");

        assert!(plan.layout.root.exists());
        assert!(plan.layout.host_work_dir.exists());
        assert!(plan.layout.root.join("work").exists());
        assert!(plan.layout.root.join("tmp").exists());
        assert!(
            plan.mounts
                .iter()
                .any(|mount| mount.kind == MountKind::Tmpfs)
        );
        assert!(
            plan.mounts
                .iter()
                .any(|mount| mount.kind == MountKind::BindReadWrite)
        );
    }

    #[test]
    fn rejects_disabled_rootfs() {
        let artifact_dir = unique_dir("disabled");
        let config = FilesystemConfig {
            enable_rootfs: false,
            ..FilesystemConfig::default()
        };

        let err = prepare_rootfs(&config, &artifact_dir).expect_err("rootfs scaffold should fail");
        assert!(err.to_string().contains("enable_rootfs"));
    }

    fn unique_dir(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("sandbox-mount-{prefix}-{stamp}"))
    }
}
