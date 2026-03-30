use std::fs::{self, File};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandbox_config::ExecutionConfig;
use sandbox_core::{ExecutionResult, ExecutionStatus, ResourceUsage, Result, SandboxError};
use sandbox_mount::{RootfsPlan, mount_proc_in_rootfs, prepare_rootfs, setup_rootfs};
use tracing::{info, warn};

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub argv_override: Option<Vec<String>>,
    pub artifact_dir: Option<PathBuf>,
}

pub fn run(config: &ExecutionConfig, options: &RunOptions) -> Result<ExecutionResult> {
    if !cfg!(target_os = "linux") {
        return Err(SandboxError::UnsupportedPlatform(
            "the current scaffold only supports Linux",
        ));
    }

    config.validate()?;

    let command = options
        .argv_override
        .clone()
        .unwrap_or_else(|| config.process.argv.clone());
    if command.is_empty() {
        return Err(SandboxError::config("resolved command must not be empty"));
    }

    let artifact_dir = options
        .artifact_dir
        .clone()
        .or_else(|| config.io.artifact_dir.clone())
        .unwrap_or_else(default_artifact_dir);
    fs::create_dir_all(&artifact_dir)
        .map_err(|err| SandboxError::io("creating artifact directory", err))?;

    if config.filesystem.enable_rootfs {
        let rootfs_plan = prepare_rootfs(&config.filesystem, &artifact_dir)?;
        info!(
            root = %rootfs_plan.layout.root.display(),
            mounts = rootfs_plan.mount_count(),
            "prepared rootfs scaffold"
        );
    }

    ensure_namespace_support(&config)?;

    let stdout_path = resolve_output_path(
        &artifact_dir,
        config.io.stdout_path.as_deref(),
        "stdout.log",
    );
    let stderr_path = resolve_output_path(
        &artifact_dir,
        config.io.stderr_path.as_deref(),
        "stderr.log",
    );
    create_parent_dir(&stdout_path)?;
    create_parent_dir(&stderr_path)?;

    let stdout = File::create(&stdout_path)
        .map_err(|err| SandboxError::io("opening stdout output file", err))?;
    let stderr = File::create(&stderr_path)
        .map_err(|err| SandboxError::io("opening stderr output file", err))?;
    let stdin = open_stdin(config.io.stdin_path.as_deref())?;

    let mut process = Command::new(&command[0]);
    process.args(&command[1..]);
    process.stdin(stdin);
    process.stdout(Stdio::from(stdout));
    process.stderr(Stdio::from(stderr));

    let rootfs_cwd = rootfs_cwd(config);
    if !config.filesystem.chroot_to_rootfs {
        if let Some(cwd) = &config.process.cwd {
            process.current_dir(cwd);
        }
    }
    if config.process.clear_env {
        process.env_clear();
    }
    for (key, value) in config.parsed_env()? {
        process.env(key, value);
    }

    unsafe {
        let filesystem = config.filesystem.clone();
        let artifact_dir = artifact_dir.clone();
        let rootfs_cwd = rootfs_cwd.clone();
        let outside_uid = libc::geteuid() as u32;
        let outside_gid = libc::getegid() as u32;
        process.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if filesystem.enter_user_namespace {
                enter_user_namespace(&filesystem, outside_uid, outside_gid).map_err(|err| {
                    let _ = fs::write(
                        artifact_dir.join("rootfs-preexec-error.log"),
                        format!("enter_user_namespace failed: {err}"),
                    );
                    err
                })?;
                drop_capabilities().map_err(|err| {
                    let _ = fs::write(
                        artifact_dir.join("rootfs-preexec-error.log"),
                        format!("drop_capabilities failed: {err}"),
                    );
                    err
                })?;
            }
            if filesystem.enable_rootfs && filesystem.enter_mount_namespace {
                enter_optional_namespaces(&filesystem)?;
                let runtime = setup_rootfs(&filesystem, &artifact_dir, rootfs_cwd.as_deref())
                    .map_err(|err| {
                        let _ = fs::write(
                            artifact_dir.join("rootfs-preexec-error.log"),
                            err.to_string(),
                        );
                        std::io::Error::other(err)
                    })?;
                if filesystem.enter_pid_namespace {
                    enter_pid_namespace_for_exec(
                        filesystem.mount_proc.then_some(&runtime.plan),
                        &artifact_dir,
                    )?;
                }
            }
            Ok(())
        });
    }

    info!(command = ?command, artifact_dir = %artifact_dir.display(), "spawning sandbox payload");
    let preexec_log = artifact_dir.join("rootfs-preexec-error.log");
    let _ = fs::remove_file(&preexec_log);
    let mut child = process.spawn().map_err(|err| {
        let detail = fs::read_to_string(&preexec_log)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| err.to_string());
        SandboxError::Spawn(detail)
    })?;
    let wall_limit = Duration::from_millis(config.limits.wall_time_ms);
    let wait_outcome = wait_for_exit(&mut child, wall_limit)?;

    let status = classify_status(wait_outcome.timed_out, &wait_outcome.exit_status);
    let term_signal = wait_outcome.exit_status.signal();
    let exit_code = wait_outcome.exit_status.code();

    Ok(ExecutionResult {
        command,
        exit_code,
        term_signal,
        usage: ResourceUsage {
            cpu_time_ms: None,
            wall_time_ms: wait_outcome.elapsed.as_millis() as u64,
            memory_peak_bytes: None,
        },
        stdout_path,
        stderr_path,
        status,
    })
}

fn rootfs_cwd(config: &ExecutionConfig) -> Option<PathBuf> {
    if !config.filesystem.chroot_to_rootfs {
        return config.process.cwd.clone();
    }

    match &config.process.cwd {
        Some(cwd) if cwd.is_absolute() => Some(cwd.clone()),
        Some(cwd) => Some(config.filesystem.work_dir.join(cwd)),
        None => Some(config.filesystem.work_dir.clone()),
    }
}

fn ensure_namespace_support(config: &ExecutionConfig) -> Result<()> {
    let support = probe_namespace_support();
    if config.filesystem.enter_user_namespace && !support.user_namespace {
        return Err(SandboxError::capability_unavailable(
            "user_namespace",
            support
                .user_reason
                .unwrap_or_else(|| "unknown user namespace error".to_string()),
        ));
    }
    if config.filesystem.enter_mount_namespace && !support.mount_namespace {
        return Err(SandboxError::capability_unavailable(
            "mount_namespace",
            support
                .mount_reason
                .unwrap_or_else(|| "unknown mount namespace error".to_string()),
        ));
    }
    if config.filesystem.enter_pid_namespace && !support.pid_namespace {
        return Err(SandboxError::capability_unavailable(
            "pid_namespace",
            support
                .pid_reason
                .unwrap_or_else(|| "unknown pid namespace error".to_string()),
        ));
    }
    if config.filesystem.enter_network_namespace && !support.network_namespace {
        return Err(SandboxError::capability_unavailable(
            "network_namespace",
            support
                .network_reason
                .unwrap_or_else(|| "unknown network namespace error".to_string()),
        ));
    }
    if config.filesystem.enter_ipc_namespace && !support.ipc_namespace {
        return Err(SandboxError::capability_unavailable(
            "ipc_namespace",
            support
                .ipc_reason
                .unwrap_or_else(|| "unknown ipc namespace error".to_string()),
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, Default)]
struct NamespaceSupport {
    user_namespace: bool,
    user_reason: Option<String>,
    mount_namespace: bool,
    mount_reason: Option<String>,
    pid_namespace: bool,
    pid_reason: Option<String>,
    network_namespace: bool,
    network_reason: Option<String>,
    ipc_namespace: bool,
    ipc_reason: Option<String>,
}

fn probe_namespace_support() -> NamespaceSupport {
    let user_probe = probe_unshare_support(libc::CLONE_NEWUSER);
    let mount_probe = probe_unshare_support(libc::CLONE_NEWNS);
    let pid_probe = probe_unshare_support(libc::CLONE_NEWPID);
    let network_probe = probe_unshare_support(libc::CLONE_NEWNET);
    let ipc_probe = probe_unshare_support(libc::CLONE_NEWIPC);

    NamespaceSupport {
        user_namespace: user_probe.is_ok(),
        user_reason: user_probe.err(),
        mount_namespace: mount_probe.is_ok(),
        mount_reason: mount_probe.err(),
        pid_namespace: pid_probe.is_ok(),
        pid_reason: pid_probe.err(),
        network_namespace: network_probe.is_ok(),
        network_reason: network_probe.err(),
        ipc_namespace: ipc_probe.is_ok(),
        ipc_reason: ipc_probe.err(),
    }
}

fn probe_unshare_support(flag: libc::c_int) -> std::result::Result<(), String> {
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        return Err(format!(
            "fork failed while probing namespace support: {}",
            std::io::Error::last_os_error()
        ));
    }

    if pid == 0 {
        let result = unsafe { libc::unshare(flag) };
        let code = if result == -1 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(1)
        } else {
            0
        };
        unsafe { libc::_exit(code.min(255)) }
    }

    let status = waitpid_status(pid)?;
    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        if code == 0 {
            return Ok(());
        }
        return Err(format!(
            "{} failed with errno {} ({})",
            namespace_name(flag),
            code,
            std::io::Error::from_raw_os_error(code)
        ));
    }

    Err(format!(
        "{} probe did not exit normally",
        namespace_name(flag)
    ))
}

fn enter_pid_namespace_for_exec(
    proc_plan: Option<&RootfsPlan>,
    artifact_dir: &Path,
) -> std::io::Result<()> {
    let result = unsafe { libc::unshare(libc::CLONE_NEWPID) };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }

    let pid = unsafe { libc::fork() };
    if pid == -1 {
        return Err(std::io::Error::last_os_error());
    }

    if pid == 0 {
        if let Some(plan) = proc_plan {
            mount_proc_in_rootfs(plan).map_err(|err| {
                let _ = fs::write(
                    artifact_dir.join("rootfs-preexec-error.log"),
                    err.to_string(),
                );
                std::io::Error::other(err)
            })?;
        }
        return Ok(());
    }

    relay_child_exit_status(pid)
}

fn relay_child_exit_status(pid: libc::pid_t) -> ! {
    let status = match waitpid_status(pid) {
        Ok(status) => status,
        Err(message) => {
            let _ = writeln_stderr(&message);
            unsafe { libc::_exit(1) }
        }
    };

    if libc::WIFEXITED(status) {
        unsafe { libc::_exit(libc::WEXITSTATUS(status)) }
    }

    if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::kill(libc::getpid(), signal);
            libc::_exit(128 + signal);
        }
    }

    unsafe { libc::_exit(1) }
}

fn waitpid_status(pid: libc::pid_t) -> std::result::Result<libc::c_int, String> {
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("waitpid failed: {err}"));
        }
        return Ok(status);
    }
}

fn namespace_name(flag: libc::c_int) -> &'static str {
    match flag {
        libc::CLONE_NEWUSER => "user namespace probe",
        libc::CLONE_NEWNS => "mount namespace probe",
        libc::CLONE_NEWPID => "pid namespace probe",
        libc::CLONE_NEWNET => "network namespace probe",
        libc::CLONE_NEWIPC => "ipc namespace probe",
        _ => "namespace probe",
    }
}

fn enter_user_namespace(
    filesystem: &sandbox_config::FilesystemConfig,
    outside_uid: u32,
    outside_gid: u32,
) -> std::io::Result<()> {
    let result = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }

    configure_user_namespace_identity(filesystem, outside_uid, outside_gid)?;

    let setgid_result = unsafe { libc::setgid(filesystem.inside_gid) };
    if setgid_result == -1 {
        return Err(std::io::Error::other(format!(
            "setgid({}) failed: {}",
            filesystem.inside_gid,
            std::io::Error::last_os_error()
        )));
    }

    let setuid_result = unsafe { libc::setuid(filesystem.inside_uid) };
    if setuid_result == -1 {
        return Err(std::io::Error::other(format!(
            "setuid({}) failed: {}",
            filesystem.inside_uid,
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

fn drop_capabilities() -> std::io::Result<()> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(err);
        }
    }

    Ok(())
}

fn configure_user_namespace_identity(
    filesystem: &sandbox_config::FilesystemConfig,
    parent_outside_uid: u32,
    parent_outside_gid: u32,
) -> std::io::Result<()> {
    let outside_uid = filesystem.outside_uid.unwrap_or(parent_outside_uid);
    let outside_gid = filesystem.outside_gid.unwrap_or(parent_outside_gid);

    if filesystem.deny_setgroups {
        fs::write("/proc/self/setgroups", "deny")
            .or_else(ignore_missing_setgroups_file)
            .map_err(|err| {
                std::io::Error::other(format!("writing /proc/self/setgroups failed: {err}"))
            })?;
    }

    fs::write(
        "/proc/self/uid_map",
        format!("{} {} 1\n", filesystem.inside_uid, outside_uid),
    )
    .map_err(|err| {
        std::io::Error::other(format!(
            "writing /proc/self/uid_map failed for inside={} outside={}: {err}",
            filesystem.inside_uid, outside_uid
        ))
    })?;
    fs::write(
        "/proc/self/gid_map",
        format!("{} {} 1\n", filesystem.inside_gid, outside_gid),
    )
    .map_err(|err| {
        std::io::Error::other(format!(
            "writing /proc/self/gid_map failed for inside={} outside={}: {err}",
            filesystem.inside_gid, outside_gid
        ))
    })?;

    Ok(())
}

fn ignore_missing_setgroups_file(err: std::io::Error) -> std::io::Result<()> {
    if err.kind() == std::io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(err)
    }
}

fn enter_optional_namespaces(filesystem: &sandbox_config::FilesystemConfig) -> std::io::Result<()> {
    if filesystem.enter_network_namespace {
        enter_single_namespace(libc::CLONE_NEWNET)?;
    }
    if filesystem.enter_ipc_namespace {
        enter_single_namespace(libc::CLONE_NEWIPC)?;
    }

    Ok(())
}

fn enter_single_namespace(flag: libc::c_int) -> std::io::Result<()> {
    let result = unsafe { libc::unshare(flag) };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn writeln_stderr(message: &str) -> std::io::Result<()> {
    use std::io::Write;

    let mut stderr = std::io::stderr().lock();
    writeln!(stderr, "{message}")
}

fn open_stdin(path: Option<&Path>) -> Result<Stdio> {
    match path {
        Some(path) => {
            let file = File::open(path)
                .map_err(|err| SandboxError::io("opening stdin input file", err))?;
            Ok(Stdio::from(file))
        }
        None => Ok(Stdio::null()),
    }
}

fn create_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| SandboxError::io("creating artifact parent directory", err))?;
    }
    Ok(())
}

fn resolve_output_path(base: &Path, configured: Option<&Path>, default_name: &str) -> PathBuf {
    match configured {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => base.join(path),
        None => base.join(default_name),
    }
}

fn default_artifact_dir() -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    PathBuf::from(".sandbox-runs").join(format!("run-{millis}"))
}

struct WaitOutcome {
    exit_status: ExitStatus,
    elapsed: Duration,
    timed_out: bool,
}

fn wait_for_exit(child: &mut Child, wall_limit: Duration) -> Result<WaitOutcome> {
    let pid = child.id() as i32;
    let start = Instant::now();

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| SandboxError::io("waiting for child process", err))?
        {
            return Ok(WaitOutcome {
                exit_status: status,
                elapsed: start.elapsed(),
                timed_out: false,
            });
        }

        if start.elapsed() >= wall_limit {
            warn!(
                pid,
                wall_limit_ms = wall_limit.as_millis(),
                "wall clock limit exceeded"
            );
            terminate_process_group(pid);
            let status = child
                .wait()
                .map_err(|err| SandboxError::io("collecting timed out child process", err))?;
            return Ok(WaitOutcome {
                exit_status: status,
                elapsed: start.elapsed(),
                timed_out: true,
            });
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn terminate_process_group(pid: i32) {
    send_signal_to_group(pid, libc::SIGTERM);
    thread::sleep(Duration::from_millis(100));
    send_signal_to_group(pid, libc::SIGKILL);
}

fn send_signal_to_group(pid: i32, signal: i32) {
    let result = unsafe { libc::killpg(pid, signal) };
    if result == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            warn!(pid, signal, error = %err, "failed to signal process group");
        }
    }
}

fn classify_status(timed_out: bool, exit_status: &ExitStatus) -> ExecutionStatus {
    if timed_out {
        ExecutionStatus::WallTimeLimitExceeded
    } else if exit_status.success() {
        ExecutionStatus::Ok
    } else {
        ExecutionStatus::RuntimeError
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use sandbox_config::ExecutionConfig;
    use sandbox_core::{ExecutionStatus, SandboxError};
    use sandbox_testkit::Scenario;

    use crate::{RunOptions, probe_namespace_support, rootfs_cwd, run};

    #[test]
    fn executes_simple_command() {
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [limits]
                wall_time_ms = 1000
            "#,
        )
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("echo")),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert_eq!(
            std::fs::read_to_string(result.stdout_path).unwrap(),
            "hello\n"
        );
    }

    #[test]
    fn times_out_long_running_command() {
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "sleep 1"]

                [limits]
                wall_time_ms = 50
            "#,
        )
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("timeout")),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::WallTimeLimitExceeded);
    }

    #[test]
    fn prepares_rootfs_scaffold_before_execution() {
        let artifact_dir = unique_artifact_dir("rootfs");
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [limits]
                wall_time_ms = 1000

                [filesystem]
                enable_rootfs = true
            "#,
        )
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir.clone()),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert!(artifact_dir.join("rootfs").exists());
        assert!(artifact_dir.join("rootfs/work").exists());
        assert!(artifact_dir.join("rootfs/tmp").exists());
        assert!(artifact_dir.join("rootfs/proc").exists());
        assert!(artifact_dir.join("work").exists());
    }

    #[test]
    fn keeps_running_with_default_rootfs_flags() {
        let artifact_dir = unique_artifact_dir("default-rootfs");
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [limits]
                wall_time_ms = 1000

                [filesystem]
                enable_rootfs = true
            "#,
        )
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
    }

    #[test]
    fn resolves_chroot_cwd_from_relative_process_cwd() {
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]
                cwd = "job"

                [filesystem]
                enable_rootfs = true
                chroot_to_rootfs = false
            "#,
        )
        .expect("config should parse");

        let regular_cwd = rootfs_cwd(&config).expect("cwd should resolve");
        assert_eq!(regular_cwd, PathBuf::from("job"));

        let chroot_config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]
                cwd = "job"

                [filesystem]
                enable_rootfs = true
                enter_user_namespace = true
                enter_mount_namespace = true
                apply_mounts = true
                chroot_to_rootfs = true
                work_dir = "/work"
            "#,
        )
        .expect("config should parse");

        let chroot_cwd = rootfs_cwd(&chroot_config).expect("cwd should resolve");
        assert_eq!(chroot_cwd, PathBuf::from("/work/job"));
    }

    #[test]
    fn reports_capability_error_when_mount_namespace_is_unavailable() {
        let support = probe_namespace_support();
        if support.mount_namespace {
            return;
        }

        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [filesystem]
                enable_rootfs = true
                enter_user_namespace = true
                enter_mount_namespace = true
            "#,
        )
        .expect("config should parse");

        let err = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("unsupported-mount")),
            },
        )
        .expect_err("run should fail");

        match err {
            SandboxError::CapabilityUnavailable { capability, .. } => {
                assert_eq!(capability, "mount_namespace");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn reports_capability_error_when_user_namespace_is_unavailable() {
        let support = probe_namespace_support();
        if support.user_namespace {
            return;
        }

        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [filesystem]
                enable_rootfs = true
                enter_user_namespace = true
            "#,
        )
        .expect("config should parse");

        let err = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("unsupported-user")),
            },
        )
        .expect_err("run should fail");

        match err {
            SandboxError::CapabilityUnavailable { capability, .. } => {
                assert_eq!(capability, "user_namespace");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn reports_capability_error_when_network_namespace_is_unavailable() {
        let support = probe_namespace_support();
        if !support.mount_namespace || support.network_namespace {
            return;
        }

        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [filesystem]
                enable_rootfs = true
                enter_mount_namespace = true
                enter_network_namespace = true
            "#,
        )
        .expect("config should parse");

        let err = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("unsupported-network")),
            },
        )
        .expect_err("run should fail");

        match err {
            SandboxError::CapabilityUnavailable { capability, .. } => {
                assert_eq!(capability, "network_namespace");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn reports_capability_error_when_ipc_namespace_is_unavailable() {
        let support = probe_namespace_support();
        if !support.mount_namespace || support.ipc_namespace {
            return;
        }

        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [filesystem]
                enable_rootfs = true
                enter_mount_namespace = true
                enter_ipc_namespace = true
            "#,
        )
        .expect("config should parse");

        let err = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("unsupported-ipc")),
            },
        )
        .expect_err("run should fail");

        match err {
            SandboxError::CapabilityUnavailable { capability, .. } => {
                assert_eq!(capability, "ipc_namespace");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    #[ignore = "requires mount namespace and chroot privileges in the test environment"]
    fn can_write_inside_sandbox_workdir_when_mounts_are_enabled() {
        let support = probe_namespace_support();
        if !support.user_namespace || !support.mount_namespace || !support.pid_namespace {
            return;
        }
        let artifact_dir = unique_artifact_dir("workdir-probe");
        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "{script}"]

                [limits]
                wall_time_ms = 1000

                [filesystem]
                enable_rootfs = true
                enter_user_namespace = true
                enter_mount_namespace = true
                enter_pid_namespace = true
                apply_mounts = true
                chroot_to_rootfs = true
                work_dir = "/work"
                tmp_dir = "/tmp"
                executable_bind_paths = ["/bin", "/usr/bin"]
            "#,
            script = Scenario::WorkDirWriteProbe.shell_snippet()
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir.clone()),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert!(artifact_dir.join("work/probe.txt").exists());
    }

    #[test]
    #[ignore = "requires mount namespace and chroot privileges in the test environment"]
    fn hides_host_file_after_chroot() {
        let support = probe_namespace_support();
        if !support.user_namespace || !support.mount_namespace || !support.pid_namespace {
            return;
        }
        let artifact_dir = unique_artifact_dir("host-visibility");
        fs::create_dir_all(&artifact_dir).expect("artifact dir should exist");
        fs::write(artifact_dir.join("host-secret.txt"), "secret").expect("host file should exist");

        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "{script}"]

                [limits]
                wall_time_ms = 1000

                [filesystem]
                enable_rootfs = true
                enter_user_namespace = true
                enter_mount_namespace = true
                enter_pid_namespace = true
                apply_mounts = true
                chroot_to_rootfs = true
                work_dir = "/work"
                tmp_dir = "/tmp"
                executable_bind_paths = ["/bin", "/usr/bin"]
            "#,
            script = Scenario::HostVisibilityProbe.shell_snippet()
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
    }

    #[test]
    #[ignore = "requires mount namespace and chroot privileges in the test environment"]
    fn mounts_minimal_proc_inside_rootfs() {
        let support = probe_namespace_support();
        if !support.user_namespace || !support.mount_namespace || !support.pid_namespace {
            return;
        }
        let artifact_dir = unique_artifact_dir("proc-visibility");
        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "{script}"]

                [limits]
                wall_time_ms = 1000

                [filesystem]
                enable_rootfs = true
                enter_user_namespace = true
                enter_mount_namespace = true
                enter_pid_namespace = true
                apply_mounts = true
                chroot_to_rootfs = true
                work_dir = "/work"
                tmp_dir = "/tmp"
                mount_proc = true
                executable_bind_paths = ["/bin", "/usr/bin"]
            "#,
            script = Scenario::ProcVisibilityProbe.shell_snippet()
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
    }

    #[test]
    #[ignore = "requires mount, pid, network, and chroot privileges in the test environment"]
    fn isolates_network_namespace_view() {
        let support = probe_namespace_support();
        if !support.user_namespace
            || !support.mount_namespace
            || !support.pid_namespace
            || !support.network_namespace
        {
            return;
        }
        let artifact_dir = unique_artifact_dir("network-isolation");
        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "{script}"]

                [limits]
                wall_time_ms = 1000

                [filesystem]
                enable_rootfs = true
                enter_user_namespace = true
                enter_mount_namespace = true
                enter_pid_namespace = true
                enter_network_namespace = true
                apply_mounts = true
                chroot_to_rootfs = true
                work_dir = "/work"
                tmp_dir = "/tmp"
                mount_proc = true
                executable_bind_paths = ["/bin", "/usr/bin"]
            "#,
            script = Scenario::NetworkIsolationProbe.shell_snippet()
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
    }

    #[test]
    #[ignore = "requires mount, pid, ipc, and chroot privileges in the test environment"]
    fn isolates_ipc_namespace_view() {
        let support = probe_namespace_support();
        if !support.user_namespace
            || !support.mount_namespace
            || !support.pid_namespace
            || !support.ipc_namespace
        {
            return;
        }
        let artifact_dir = unique_artifact_dir("ipc-isolation");
        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "{script}"]

                [limits]
                wall_time_ms = 1000

                [filesystem]
                enable_rootfs = true
                enter_user_namespace = true
                enter_mount_namespace = true
                enter_pid_namespace = true
                enter_ipc_namespace = true
                apply_mounts = true
                chroot_to_rootfs = true
                work_dir = "/work"
                tmp_dir = "/tmp"
                mount_proc = true
                executable_bind_paths = ["/bin", "/usr/bin"]
            "#,
            script = Scenario::IpcIsolationProbe.shell_snippet()
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
    }

    #[test]
    #[ignore = "requires user namespace support in the test environment"]
    fn enters_user_namespace_before_running_payload() {
        let support = probe_namespace_support();
        if !support.user_namespace {
            return;
        }

        let artifact_dir = unique_artifact_dir("userns");
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/usr/bin/id", "-u"]

                [limits]
                wall_time_ms = 1000

                [filesystem]
                enable_rootfs = true
                enter_user_namespace = true
            "#,
        )
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
    }

    #[test]
    #[ignore = "requires user namespace support in the test environment"]
    fn applies_user_namespace_uid_gid_mapping() {
        let support = probe_namespace_support();
        if !support.user_namespace {
            return;
        }

        let artifact_dir = unique_artifact_dir("userns-mapping");
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "id -u && id -g"]

                [limits]
                wall_time_ms = 1000

                [filesystem]
                enable_rootfs = true
                enter_user_namespace = true
                inside_uid = 0
                inside_gid = 0
                executable_bind_paths = ["/bin", "/usr/bin"]
            "#,
        )
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        let mut lines = stdout.lines();
        assert_eq!(lines.next(), Some("0"));
        assert_eq!(lines.next(), Some("0"));
    }

    fn unique_artifact_dir(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("sandbox-{prefix}-{stamp}"))
    }
}
