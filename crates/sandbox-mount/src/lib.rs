use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsRuntime {
    pub plan: RootfsPlan,
    pub namespace_entered: bool,
    pub mounts_applied: bool,
    pub chroot_applied: bool,
}

pub fn cleanup_rootfs_artifacts(plan: &RootfsPlan) -> Result<()> {
    cleanup_path(&plan.layout.root, "removing stale rootfs directory")?;
    cleanup_path(
        &plan.layout.host_work_dir,
        "removing stale host work directory",
    )?;
    cleanup_path(
        &plan.layout.host_tmp_dir,
        "removing stale host tmp directory",
    )?;
    Ok(())
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

    let empty_plan = RootfsPlan {
        layout: layout.clone(),
        mounts: Vec::new(),
    };
    cleanup_rootfs_artifacts(&empty_plan)?;
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

    for source in &config.executable_bind_paths {
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

pub fn enter_mount_namespace() -> Result<()> {
    let result = unsafe { libc::unshare(libc::CLONE_NEWNS) };
    if result == -1 {
        return Err(SandboxError::io(
            "entering mount namespace",
            std::io::Error::last_os_error(),
        ));
    }

    mount_raw(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
        "making root mount private",
    )?;

    Ok(())
}

pub fn apply_rootfs(plan: &RootfsPlan, include_proc_mount: bool) -> Result<()> {
    for mount in &plan.mounts {
        if !include_proc_mount && mount.kind == MountKind::Proc {
            continue;
        }
        apply_mount(plan, mount)?;
    }
    Ok(())
}

pub fn chroot_into_rootfs(plan: &RootfsPlan, cwd: Option<&Path>) -> Result<()> {
    let root = c_path(&plan.layout.root)?;
    let slash = cstring("/")?;

    let chroot_result = unsafe { libc::chroot(root.as_ptr()) };
    if chroot_result == -1 {
        return Err(SandboxError::io(
            "changing root directory",
            std::io::Error::last_os_error(),
        ));
    }

    let chdir_root_result = unsafe { libc::chdir(slash.as_ptr()) };
    if chdir_root_result == -1 {
        return Err(SandboxError::io(
            "changing current directory to new root",
            std::io::Error::last_os_error(),
        ));
    }

    if let Some(cwd) = cwd {
        let cwd = c_path(cwd)?;
        let chdir_result = unsafe { libc::chdir(cwd.as_ptr()) };
        if chdir_result == -1 {
            return Err(SandboxError::io(
                "changing current directory inside rootfs",
                std::io::Error::last_os_error(),
            ));
        }
    }

    Ok(())
}

pub fn setup_rootfs(
    config: &FilesystemConfig,
    artifact_dir: &Path,
    cwd: Option<&Path>,
) -> Result<RootfsRuntime> {
    let plan = prepare_rootfs(config, artifact_dir)?;

    let mut runtime = RootfsRuntime {
        plan,
        namespace_entered: false,
        mounts_applied: false,
        chroot_applied: false,
    };

    if config.enter_mount_namespace {
        enter_mount_namespace()?;
        runtime.namespace_entered = true;
    }
    if config.apply_mounts {
        apply_rootfs(&runtime.plan, !config.enter_pid_namespace)?;
        runtime.mounts_applied = true;
    }
    if config.chroot_to_rootfs {
        chroot_into_rootfs(&runtime.plan, cwd)?;
        runtime.chroot_applied = true;
    }

    Ok(runtime)
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

pub fn mount_proc_in_rootfs(plan: &RootfsPlan) -> Result<()> {
    if let Some(proc_dir) = &plan.layout.sandbox_proc_dir {
        let mount = MountPlanEntry {
            kind: MountKind::Proc,
            source: None,
            target: proc_dir.clone(),
            flags: vec!["nosuid".into(), "nodev".into(), "noexec".into()],
        };
        apply_mount(plan, &mount)?;
    }

    Ok(())
}

fn cleanup_path(path: &Path, context: &'static str) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(SandboxError::io(context, err)),
    }
}

fn materialize_mount_target(root: &Path, sandbox_path: &Path) -> Result<()> {
    let target = host_mount_target(root, sandbox_path)?;
    fs::create_dir_all(&target)
        .map_err(|err| SandboxError::io("creating rootfs mount target", err))?;
    Ok(())
}

fn host_mount_target(root: &Path, sandbox_path: &Path) -> Result<PathBuf> {
    let relative = relative_sandbox_path(sandbox_path)?;
    Ok(root.join(relative))
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

fn apply_mount(plan: &RootfsPlan, mount: &MountPlanEntry) -> Result<()> {
    let target = host_mount_target(&plan.layout.root, &mount.target)?;
    match mount.kind {
        MountKind::BindReadOnly => {
            let source = mount.source.as_ref().ok_or_else(|| {
                SandboxError::internal("bind mount plan entry is missing its source path")
            })?;
            mount_raw(
                Some(source),
                &target,
                None,
                libc::MS_BIND | libc::MS_REC,
                None,
                "creating recursive bind mount",
            )?;
            mount_raw(
                None,
                &target,
                None,
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                None,
                "remounting bind mount as read only",
            )?;
        }
        MountKind::BindReadWrite => {
            let source = mount.source.as_ref().ok_or_else(|| {
                SandboxError::internal("bind mount plan entry is missing its source path")
            })?;
            mount_raw(
                Some(source),
                &target,
                None,
                libc::MS_BIND | libc::MS_REC,
                None,
                "creating writable recursive bind mount",
            )?;
        }
        MountKind::Tmpfs => {
            mount_raw(
                Some(Path::new("tmpfs")),
                &target,
                Some("tmpfs"),
                libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
                None,
                "mounting tmpfs",
            )?;
        }
        MountKind::Proc => {
            mount_raw(
                Some(Path::new("proc")),
                &target,
                Some("proc"),
                libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
                None,
                "mounting procfs",
            )?;
        }
    }

    Ok(())
}

fn mount_raw(
    source: Option<&Path>,
    target: &Path,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
    context: &'static str,
) -> Result<()> {
    let source = match source {
        Some(path) => Some(c_path(path)?),
        None => None,
    };
    let target = c_path(target)?;
    let fstype = match fstype {
        Some(value) => Some(cstring(value)?),
        None => None,
    };
    let data = match data {
        Some(value) => Some(cstring(value)?),
        None => None,
    };

    let result = unsafe {
        libc::mount(
            source
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            target.as_ptr(),
            fstype
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            flags,
            data.as_ref().map_or(std::ptr::null(), |value| {
                value.as_ptr() as *const libc::c_void
            }),
        )
    };
    if result == -1 {
        return Err(SandboxError::io(context, std::io::Error::last_os_error()));
    }

    Ok(())
}

fn c_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        SandboxError::config(format!(
            "path contains an interior NUL byte: {}",
            path.display()
        ))
    })
}

fn cstring(value: &str) -> Result<CString> {
    CString::new(value)
        .map_err(|_| SandboxError::config(format!("string contains an interior NUL byte: {value}")))
}

pub fn roadmap() -> &'static str {
    "M2 scaffold: build minimal rootfs, execute mount namespace setup, and manage rootfs lifecycle."
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use sandbox_config::FilesystemConfig;

    use crate::{
        MountKind, RootfsPlan, cleanup_rootfs_artifacts, host_mount_target, prepare_rootfs,
    };

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
    fn includes_executable_bind_paths_in_mount_plan() {
        let artifact_dir = unique_dir("executable-binds");
        let config = FilesystemConfig {
            executable_bind_paths: vec![PathBuf::from("/bin"), PathBuf::from("/usr/bin")],
            ..FilesystemConfig::default()
        };

        let plan = prepare_rootfs(&config, &artifact_dir).expect("rootfs scaffold should build");

        assert!(
            plan.mounts
                .iter()
                .any(|mount| mount.source.as_deref() == Some(Path::new("/bin")))
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

    #[test]
    fn resolves_host_mount_target_under_rootfs() {
        let host_target = host_mount_target(Path::new("/sandbox/rootfs"), Path::new("/usr/lib"))
            .expect("host target should resolve");

        assert_eq!(host_target, PathBuf::from("/sandbox/rootfs/usr/lib"));
    }

    #[test]
    fn cleans_up_existing_rootfs_artifacts() {
        let artifact_dir = unique_dir("cleanup");
        let plan = RootfsPlan {
            layout: super::RootfsLayout {
                root: artifact_dir.join("rootfs"),
                host_work_dir: artifact_dir.join("work"),
                host_tmp_dir: artifact_dir.join("tmp"),
                sandbox_work_dir: PathBuf::from("/work"),
                sandbox_tmp_dir: PathBuf::from("/tmp"),
                sandbox_proc_dir: Some(PathBuf::from("/proc")),
            },
            mounts: Vec::new(),
        };
        fs::create_dir_all(plan.layout.root.join("stale")).expect("stale rootfs should exist");
        fs::create_dir_all(plan.layout.host_work_dir.join("stale"))
            .expect("stale work dir should exist");

        cleanup_rootfs_artifacts(&plan).expect("cleanup should succeed");

        assert!(!plan.layout.root.exists());
        assert!(!plan.layout.host_work_dir.exists());
    }

    fn unique_dir(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("sandbox-mount-{prefix}-{stamp}"))
    }
}
