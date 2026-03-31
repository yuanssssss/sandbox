use std::fs::{self, File, OpenOptions};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandbox_cgroup::{CgroupManager, CgroupPlan};
use sandbox_config::ExecutionConfig;
use sandbox_core::{ExecutionResult, ExecutionStatus, ResourceUsage, Result, SandboxError};
use sandbox_mount::{
    RootfsPlan, apply_rootfs, chroot_into_rootfs, enter_mount_namespace, mount_proc_in_rootfs,
    prepare_rootfs,
};
use sandbox_seccomp::install as install_seccomp;
use tracing::{info, warn};

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub argv_override: Option<Vec<String>>,
    pub artifact_dir: Option<PathBuf>,
    pub cgroup_root_override: Option<PathBuf>,
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

    let artifact_dir = planned_artifact_dir(config, options);
    info!(
        target: "sandbox_audit",
        audit_stage = "run_start",
        command = ?command,
        artifact_dir = %artifact_dir.display(),
        wall_time_ms = config.limits.wall_time_ms,
        cpu_time_ms = config.limits.cpu_time_ms,
        memory_bytes = config.limits.memory_bytes,
        max_processes = config.limits.max_processes,
        seccomp_profile = ?config.security.seccomp_profile,
        "sandbox audit"
    );
    fs::create_dir_all(&artifact_dir)
        .map_err(|err| SandboxError::io("creating artifact directory", err))?;

    let rootfs_plan = if config.filesystem.enable_rootfs {
        let rootfs_plan = prepare_rootfs(&config.filesystem, &artifact_dir)?;
        info!(
            root = %rootfs_plan.layout.root.display(),
            mounts = rootfs_plan.mount_count(),
            "prepared rootfs scaffold"
        );
        info!(
            target: "sandbox_audit",
            audit_stage = "rootfs_prepared",
            root = %rootfs_plan.layout.root.display(),
            mount_count = rootfs_plan.mount_count(),
            work_dir = %rootfs_plan.layout.sandbox_work_dir.display(),
            tmp_dir = %rootfs_plan.layout.sandbox_tmp_dir.display(),
            output_dir = ?rootfs_plan.layout.sandbox_output_dir,
            "sandbox audit"
        );
        Some(rootfs_plan)
    } else {
        None
    };

    ensure_namespace_support(&config)?;

    let mut cgroup_binding = prepare_cgroup_context(config, &artifact_dir, options)?;

    let result = (|| -> Result<ExecutionResult> {
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
        assert_path_is_within(&artifact_dir, &stdout_path)?;
        assert_path_is_within(&artifact_dir, &stderr_path)?;
        create_parent_dir(&stdout_path)?;
        create_parent_dir(&stderr_path)?;

        let stdout = File::create(&stdout_path)
            .map_err(|err| SandboxError::io("opening stdout output file", err))?;
        let stderr = File::create(&stderr_path)
            .map_err(|err| SandboxError::io("opening stderr output file", err))?;
        let stdin = open_stdin(config.io.stdin_path.as_deref())?;
        let preexec_log_path = artifact_dir.join("rootfs-preexec-error.log");
        let preexec_log = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&preexec_log_path)
            .map_err(|err| SandboxError::io("opening pre-exec diagnostics log", err))?;

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
            let security = config.security.clone();
            let artifact_dir = artifact_dir.clone();
            let rootfs_cwd = rootfs_cwd.clone();
            let outside_uid = libc::geteuid() as u32;
            let outside_gid = libc::getegid() as u32;
            let command_for_preexec = command.clone();
            let mut preexec_log = preexec_log;
            let rootfs_plan = rootfs_plan.clone();
            process.pre_exec(move || {
                log_preexec_stage(
                    &mut preexec_log,
                    "pre_exec_start",
                    Some(format!(
                        "euid={} egid={} outside_uid={} outside_gid={}",
                        libc::geteuid(),
                        libc::getegid(),
                        outside_uid,
                        outside_gid
                    )),
                );
                log_preexec_stage(&mut preexec_log, "setsid", None);
                if libc::setsid() == -1 {
                    log_preexec_error(
                        &mut preexec_log,
                        "setsid",
                        &std::io::Error::last_os_error().to_string(),
                    );
                    return Err(std::io::Error::last_os_error());
                }
                if filesystem.enter_user_namespace {
                    log_preexec_stage(&mut preexec_log, "enter_user_namespace", None);
                    enter_user_namespace(&filesystem, outside_uid, outside_gid).map_err(|err| {
                        log_preexec_error(
                            &mut preexec_log,
                            "enter_user_namespace",
                            &err.to_string(),
                        );
                        err
                    })?;
                }
                if filesystem.enable_rootfs && filesystem.enter_mount_namespace {
                    log_preexec_stage(&mut preexec_log, "enter_optional_namespaces", None);
                    enter_optional_namespaces(&filesystem).map_err(|err| {
                        log_preexec_error(
                            &mut preexec_log,
                            "enter_optional_namespaces",
                            &err.to_string(),
                        );
                        err
                    })?;
                    let plan = if let Some(plan) = rootfs_plan.as_ref() {
                        plan
                    } else {
                        let err = std::io::Error::other(
                            "rootfs enabled but prepared rootfs plan missing",
                        );
                        log_preexec_error(
                            &mut preexec_log,
                            "reuse_prepared_rootfs",
                            &err.to_string(),
                        );
                        return Err(err);
                    };
                    log_preexec_stage(
                        &mut preexec_log,
                        "reuse_prepared_rootfs",
                        Some(format!(
                            "root={} mount_count={}",
                            plan.layout.root.display(),
                            plan.mount_count()
                        )),
                    );
                    log_preexec_stage(&mut preexec_log, "enter_mount_namespace", None);
                    enter_mount_namespace().map_err(|err| {
                        log_preexec_error(
                            &mut preexec_log,
                            "enter_mount_namespace",
                            &err.to_string(),
                        );
                        std::io::Error::other(err)
                    })?;
                    if filesystem.apply_mounts {
                        log_preexec_stage(&mut preexec_log, "apply_rootfs", None);
                        apply_rootfs(&plan, !filesystem.enter_pid_namespace).map_err(|err| {
                            log_preexec_error(&mut preexec_log, "apply_rootfs", &err.to_string());
                            std::io::Error::other(err)
                        })?;
                    }
                    if filesystem.enter_pid_namespace {
                        log_preexec_stage(&mut preexec_log, "enter_pid_namespace_for_exec", None);
                        enter_pid_namespace_for_exec(
                            filesystem.mount_proc.then_some(&plan),
                            &artifact_dir,
                            &mut preexec_log,
                        )
                        .map_err(|err| {
                            log_preexec_error(
                                &mut preexec_log,
                                "enter_pid_namespace_for_exec",
                                &err.to_string(),
                            );
                            err
                        })?;
                    }
                    if filesystem.chroot_to_rootfs {
                        log_preexec_stage(
                            &mut preexec_log,
                            "chroot_into_rootfs",
                            rootfs_cwd
                                .as_ref()
                                .map(|cwd| format!("cwd={}", cwd.display())),
                        );
                        chroot_into_rootfs(&plan, rootfs_cwd.as_deref()).map_err(|err| {
                            log_preexec_error(
                                &mut preexec_log,
                                "chroot_into_rootfs",
                                &err.to_string(),
                            );
                            std::io::Error::other(err)
                        })?;
                    }
                }
                if filesystem.enter_user_namespace && filesystem.drop_capabilities {
                    log_preexec_stage(&mut preexec_log, "drop_capabilities", None);
                    drop_capabilities().map_err(|err| {
                        log_preexec_error(&mut preexec_log, "drop_capabilities", &err.to_string());
                        err
                    })?;
                }
                log_preexec_stage(
                    &mut preexec_log,
                    "install_seccomp",
                    Some(format!("profile={:?}", security.seccomp_profile)),
                );
                install_seccomp(security.seccomp_profile).map_err(|err| {
                    let io_err = std::io::Error::other(err.to_string());
                    log_preexec_error(&mut preexec_log, "install_seccomp", &err.to_string());
                    io_err
                })?;
                log_preexec_stage(
                    &mut preexec_log,
                    "ready_to_exec",
                    Some(format!("command={:?}", command_for_preexec)),
                );
                Ok(())
            });
        }

        info!(
            target: "sandbox_audit",
            audit_stage = "seccomp_configured",
            seccomp_profile = ?config.security.seccomp_profile,
            "sandbox audit"
        );
        info!(
            command = ?command,
            artifact_dir = %artifact_dir.display(),
            "spawning sandbox payload"
        );
        let mut child = process.spawn().map_err(|err| {
            let detail = fs::read_to_string(&preexec_log_path)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(|diagnostics| format!("{diagnostics}\nspawn error: {err}"))
                .unwrap_or_else(|| err.to_string());
            SandboxError::Spawn(detail)
        })?;
        let _ = fs::remove_file(&preexec_log_path);
        info!(
            target: "sandbox_audit",
            audit_stage = "payload_spawned",
            pid = child.id(),
            stdout_path = %stdout_path.display(),
            stderr_path = %stderr_path.display(),
            "sandbox audit"
        );
        if let Some(binding) = &cgroup_binding {
            binding
                .manager
                .attach_pid(&binding.plan, child.id())
                .map_err(|err| {
                    cleanup_child_process_group(&mut child);
                    err
                })?;
        }
        let wall_limit = Duration::from_millis(config.limits.wall_time_ms);
        let wait_outcome = wait_for_exit(
            &mut child,
            wall_limit,
            config.limits.cpu_time_ms,
            cgroup_binding.as_ref(),
        )
        .map_err(|err| {
            cleanup_child_process_group(&mut child);
            err
        })?;

        let finalized_cgroup = {
            let result = finalize_cgroup(
                cgroup_binding.as_ref(),
                wait_outcome.elapsed,
                config.limits.cpu_time_ms,
            );
            cgroup_binding = None;
            result?
        };
        let status = classify_status(
            wait_outcome.timed_out,
            wait_outcome.cpu_timed_out
                || finalized_cgroup
                    .as_ref()
                    .is_some_and(|value| value.cpu_limit_exceeded),
            &wait_outcome.exit_status,
            finalized_cgroup
                .as_ref()
                .is_some_and(|value| value.memory_limit_exceeded),
        );
        let term_signal = wait_outcome.exit_status.signal();
        let exit_code = wait_outcome.exit_status.code();
        let usage = finalized_cgroup
            .map(|value| value.usage)
            .unwrap_or_else(|| ResourceUsage {
                cpu_time_ms: None,
                wall_time_ms: wait_outcome.elapsed.as_millis() as u64,
                memory_peak_bytes: None,
            });
        info!(
            target: "sandbox_audit",
            audit_stage = "run_finished",
            status = ?status,
            exit_code,
            term_signal,
            wall_time_ms = usage.wall_time_ms,
            cpu_time_ms = usage.cpu_time_ms,
            memory_peak_bytes = usage.memory_peak_bytes,
            "sandbox audit"
        );

        Ok(ExecutionResult {
            command,
            exit_code,
            term_signal,
            usage,
            stdout_path,
            stderr_path,
            status,
        })
    })();

    if let Some(binding) = cgroup_binding.take() {
        cleanup_cgroup_after_error(&binding);
    }

    result
}

#[derive(Debug, Clone)]
struct CgroupBinding {
    manager: CgroupManager,
    plan: CgroupPlan,
}

#[derive(Debug, Clone)]
struct FinalizedCgroup {
    usage: ResourceUsage,
    cpu_limit_exceeded: bool,
    memory_limit_exceeded: bool,
}

fn prepare_cgroup_context(
    config: &ExecutionConfig,
    artifact_dir: &Path,
    options: &RunOptions,
) -> Result<Option<CgroupBinding>> {
    if !should_enable_cgroup(config) {
        return Ok(None);
    }

    let manager = match &options.cgroup_root_override {
        Some(path) => CgroupManager::new(path.clone()),
        None => CgroupManager::probe_v2_root()?,
    };
    let plan = CgroupPlan::new(cgroup_scope_name(artifact_dir), config.resource_limits());
    manager.apply_limits(&plan)?;
    let cgroup_path = plan.path_under(manager.root());
    info!(
        target: "sandbox_audit",
        audit_stage = "cgroup_prepared",
        cgroup_path = %cgroup_path.display(),
        cpu_time_ms = plan.limits.cpu_time_ms,
        memory_bytes = plan.limits.memory_bytes,
        max_processes = plan.limits.max_processes,
        "sandbox audit"
    );

    Ok(Some(CgroupBinding { manager, plan }))
}

fn should_enable_cgroup(config: &ExecutionConfig) -> bool {
    config.limits.cpu_time_ms.is_some()
        || config.limits.memory_bytes.is_some()
        || config.limits.max_processes.is_some()
}

pub fn cgroup_scope_name(artifact_dir: &Path) -> String {
    artifact_dir
        .file_name()
        .and_then(|value| value.to_str())
        .map(ToOwned::to_owned)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("sandbox-{stamp}")
        })
}

fn finalize_cgroup(
    cgroup_binding: Option<&CgroupBinding>,
    elapsed: Duration,
    cpu_time_limit_ms: Option<u64>,
) -> Result<Option<FinalizedCgroup>> {
    let wall_time_ms = elapsed.as_millis() as u64;
    let Some(binding) = cgroup_binding else {
        return Ok(None);
    };

    let stats = binding.manager.read_usage(&binding.plan);
    let cleanup_result = binding.manager.cleanup(&binding.plan);
    let stats = stats?;
    cleanup_result?;
    let cpu_limit_exceeded = cpu_time_limit_ms.is_some_and(|limit_ms| {
        stats
            .cpu_time_usec
            .is_some_and(|observed| observed >= limit_ms.saturating_mul(1_000))
    });
    let memory_limit_exceeded =
        stats.memory_events_oom.unwrap_or(0) > 0 || stats.memory_events_oom_kill.unwrap_or(0) > 0;
    let usage = stats.into_resource_usage(wall_time_ms);
    info!(
        target: "sandbox_audit",
        audit_stage = "cgroup_finalized",
        cgroup_path = %binding.plan.path_under(binding.manager.root()).display(),
        cpu_time_ms = usage.cpu_time_ms,
        wall_time_ms = usage.wall_time_ms,
        memory_peak_bytes = usage.memory_peak_bytes,
        cpu_limit_exceeded,
        memory_limit_exceeded,
        "sandbox audit"
    );
    Ok(Some(FinalizedCgroup {
        usage,
        cpu_limit_exceeded,
        memory_limit_exceeded,
    }))
}

pub fn rootfs_cwd(config: &ExecutionConfig) -> Option<PathBuf> {
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
pub struct NamespaceSupport {
    pub user_namespace: bool,
    pub user_reason: Option<String>,
    pub mount_namespace: bool,
    pub mount_reason: Option<String>,
    pub pid_namespace: bool,
    pub pid_reason: Option<String>,
    pub network_namespace: bool,
    pub network_reason: Option<String>,
    pub ipc_namespace: bool,
    pub ipc_reason: Option<String>,
}

pub fn probe_namespace_support() -> NamespaceSupport {
    let user_probe = probe_user_namespace_support();
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

fn probe_user_namespace_support() -> std::result::Result<(), String> {
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        return Err(format!(
            "fork failed while probing namespace support: {}",
            std::io::Error::last_os_error()
        ));
    }

    if pid == 0 {
        let outside_uid = unsafe { libc::geteuid() } as u32;
        let outside_gid = unsafe { libc::getegid() } as u32;
        let code = match probe_user_namespace_identity_mapping(outside_uid, outside_gid) {
            Ok(()) => 0,
            Err(err) => err.raw_os_error().unwrap_or(1),
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
            namespace_name(libc::CLONE_NEWUSER),
            code,
            std::io::Error::from_raw_os_error(code)
        ));
    }

    Err("user namespace probe did not exit normally".to_string())
}

fn probe_user_namespace_identity_mapping(
    outside_uid: u32,
    outside_gid: u32,
) -> std::io::Result<()> {
    let result = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }

    if let Err(err) = fs::write("/proc/self/setgroups", "deny") {
        if err.kind() != std::io::ErrorKind::NotFound
            && err.kind() != std::io::ErrorKind::PermissionDenied
        {
            return Err(err);
        }
    }

    fs::write("/proc/self/uid_map", format!("0 {outside_uid} 1\n"))?;
    fs::write("/proc/self/gid_map", format!("0 {outside_gid} 1\n"))?;

    let setgid_result = unsafe { libc::setgid(0) };
    if setgid_result == -1 {
        return Err(std::io::Error::last_os_error());
    }

    let setuid_result = unsafe { libc::setuid(0) };
    if setuid_result == -1 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
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
    _artifact_dir: &Path,
    preexec_log: &mut File,
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
            log_preexec_stage(preexec_log, "mount_proc_in_rootfs", None);
            mount_proc_in_rootfs(plan).map_err(|err| {
                log_preexec_error(preexec_log, "mount_proc_in_rootfs", &err.to_string());
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
    set_no_new_privs()?;
    drop_capability_bounding_set()?;
    clear_capability_sets()?;
    Ok(())
}

fn set_no_new_privs() -> std::io::Result<()> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(err);
        }
    }

    Ok(())
}

fn drop_capability_bounding_set() -> std::io::Result<()> {
    for cap in 0..=read_cap_last_cap() {
        let result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if result == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINVAL) {
                return Ok(());
            }
            return Err(std::io::Error::other(format!(
                "dropping capability {cap} from bounding set failed: {err}"
            )));
        }
    }

    Ok(())
}

fn clear_capability_sets() -> std::io::Result<()> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    #[repr(C)]
    struct UserCapHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    struct UserCapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let mut header = UserCapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        UserCapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        UserCapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    let result = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut UserCapHeader,
            data.as_ptr(),
        )
    };
    if result == -1 {
        return Err(std::io::Error::other(format!(
            "clearing effective/permitted/inheritable capabilities failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

fn read_cap_last_cap() -> u32 {
    fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(63)
}

fn configure_user_namespace_identity(
    filesystem: &sandbox_config::FilesystemConfig,
    parent_outside_uid: u32,
    parent_outside_gid: u32,
) -> std::io::Result<()> {
    let outside_uid = filesystem.outside_uid.unwrap_or(parent_outside_uid);
    let outside_gid = filesystem.outside_gid.unwrap_or(parent_outside_gid);

    if filesystem.deny_setgroups {
        match fs::write("/proc/self/setgroups", "deny") {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(err) => {
                return Err(std::io::Error::other(format!(
                    "writing /proc/self/setgroups failed: {err}"
                )));
            }
        }
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

fn log_preexec_stage(log: &mut File, stage: &str, detail: Option<String>) {
    let mut message = format!("stage: {stage}");
    if let Some(detail) = detail {
        message.push_str(" | ");
        message.push_str(&detail);
    }
    let _ = write_preexec_log_line(log, &message);
}

fn log_preexec_error(log: &mut File, stage: &str, detail: &str) {
    let _ = write_preexec_log_line(log, &format!("error: {stage} | {detail}"));
}

fn write_preexec_log_line(log: &mut File, line: &str) -> std::io::Result<()> {
    use std::io::Write;

    writeln!(log, "{line}")?;
    log.flush()
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

pub fn planned_artifact_dir(config: &ExecutionConfig, options: &RunOptions) -> PathBuf {
    options
        .artifact_dir
        .clone()
        .or_else(|| config.io.artifact_dir.clone())
        .unwrap_or_else(default_artifact_dir)
}

fn default_artifact_dir() -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    PathBuf::from(".sandbox-runs").join(format!("run-{millis}"))
}

fn assert_path_is_within(base: &Path, path: &Path) -> Result<()> {
    if !path.starts_with(base) {
        return Err(SandboxError::config(format!(
            "configured path must stay within artifact directory: {}",
            path.display()
        )));
    }
    Ok(())
}

struct WaitOutcome {
    exit_status: ExitStatus,
    elapsed: Duration,
    timed_out: bool,
    cpu_timed_out: bool,
}

fn wait_for_exit(
    child: &mut Child,
    wall_limit: Duration,
    cpu_time_limit_ms: Option<u64>,
    cgroup_binding: Option<&CgroupBinding>,
) -> Result<WaitOutcome> {
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
                cpu_timed_out: false,
            });
        }

        if let Some(observed_cpu_time_usec) =
            check_cpu_time_limit_exceeded(cgroup_binding, cpu_time_limit_ms)?
        {
            warn!(
                pid,
                cpu_time_limit_ms, observed_cpu_time_usec, "cpu time limit exceeded"
            );
            info!(
                target: "sandbox_audit",
                audit_stage = "termination_reason",
                pid,
                reason = "cpu_time_limit_exceeded",
                observed_cpu_time_usec,
                cpu_time_limit_ms,
                "sandbox audit"
            );
            terminate_process_group(pid);
            let status = child
                .wait()
                .map_err(|err| SandboxError::io("collecting cpu-limited child process", err))?;
            return Ok(WaitOutcome {
                exit_status: status,
                elapsed: start.elapsed(),
                timed_out: false,
                cpu_timed_out: true,
            });
        }

        if start.elapsed() >= wall_limit {
            warn!(
                pid,
                wall_limit_ms = wall_limit.as_millis(),
                "wall clock limit exceeded"
            );
            info!(
                target: "sandbox_audit",
                audit_stage = "termination_reason",
                pid,
                reason = "wall_time_limit_exceeded",
                wall_time_limit_ms = wall_limit.as_millis(),
                "sandbox audit"
            );
            terminate_process_group(pid);
            let status = child
                .wait()
                .map_err(|err| SandboxError::io("collecting timed out child process", err))?;
            return Ok(WaitOutcome {
                exit_status: status,
                elapsed: start.elapsed(),
                timed_out: true,
                cpu_timed_out: false,
            });
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn check_cpu_time_limit_exceeded(
    cgroup_binding: Option<&CgroupBinding>,
    cpu_time_limit_ms: Option<u64>,
) -> Result<Option<u64>> {
    let Some(limit_ms) = cpu_time_limit_ms else {
        return Ok(None);
    };
    let Some(binding) = cgroup_binding else {
        return Ok(None);
    };

    let limit_usec = limit_ms.saturating_mul(1_000);
    let observed = binding.manager.read_cpu_time_usec(&binding.plan)?;
    Ok(observed.filter(|value| *value >= limit_usec))
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

fn cleanup_child_process_group(child: &mut Child) {
    terminate_process_group(child.id() as i32);
    let _ = child.wait();
}

fn cleanup_cgroup_after_error(binding: &CgroupBinding) {
    if let Err(err) = binding.manager.cleanup(&binding.plan) {
        warn!(
            target: "sandbox_audit",
            audit_stage = "cleanup_error",
            cleanup_target = "cgroup",
            cgroup_path = %binding.plan.path_under(binding.manager.root()).display(),
            error = %err,
            "failed to clean up cgroup after run error"
        );
    }
}

fn classify_status(
    timed_out: bool,
    cpu_timed_out: bool,
    exit_status: &ExitStatus,
    memory_limit_exceeded: bool,
) -> ExecutionStatus {
    if timed_out {
        ExecutionStatus::WallTimeLimitExceeded
    } else if cpu_timed_out {
        ExecutionStatus::TimeLimitExceeded
    } else if memory_limit_exceeded {
        ExecutionStatus::MemoryLimitExceeded
    } else if exit_status.success() {
        ExecutionStatus::Ok
    } else {
        ExecutionStatus::RuntimeError
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use sandbox_cgroup::{CgroupManager, CgroupPlan};
    use sandbox_config::ExecutionConfig;
    use sandbox_core::{ExecutionStatus, SandboxError};
    use sandbox_testkit::{MaliciousScenario, ResourceScenario, Scenario, SeccompScenario};
    use tracing::dispatcher::Dispatch;
    use tracing_subscriber::fmt::MakeWriter;

    use crate::{RunOptions, cgroup_scope_name, probe_namespace_support, rootfs_cwd, run};

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
                cgroup_root_override: None,
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
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::WallTimeLimitExceeded);
    }

    #[test]
    fn emits_structured_audit_events_for_run_lifecycle() {
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [limits]
                wall_time_ms = 1000
            "#,
        )
        .expect("config should parse");
        let artifact_dir = unique_artifact_dir("audit-lifecycle");
        let logs = capture_logs(|| {
            run(
                &config,
                &RunOptions {
                    argv_override: None,
                    artifact_dir: Some(artifact_dir),
                    cgroup_root_override: None,
                },
            )
            .expect("command should run")
        });

        assert!(logs.contains("audit_stage=\"run_start\""));
        assert!(logs.contains("audit_stage=\"rootfs_prepared\""));
        assert!(logs.contains("audit_stage=\"seccomp_configured\""));
        assert!(logs.contains("audit_stage=\"payload_spawned\""));
        assert!(logs.contains("audit_stage=\"run_finished\""));
    }

    #[test]
    fn emits_structured_audit_events_for_cgroup_lifecycle() {
        let artifact_dir = unique_artifact_dir("audit-cgroup");
        let cgroup_root = unique_artifact_dir("audit-cgroup-root");
        fs::create_dir_all(&cgroup_root).expect("cgroup root should exist");
        fs::write(cgroup_root.join("cgroup.controllers"), "memory pids cpu\n")
            .expect("controllers should exist");
        let cgroup_dir = cgroup_root.join(cgroup_scope_name(&artifact_dir));

        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "printf 'usage_usec 7000\n' > {cpu_stat}; printf '4096\n' > {memory_current}; printf '16384\n' > {memory_peak}; printf '2\n' > {pids_current}"]

                [limits]
                wall_time_ms = 1000
                memory_bytes = 16384
                max_processes = 8
            "#,
            cpu_stat = shell_single_quote(&cgroup_dir.join("cpu.stat")),
            memory_current = shell_single_quote(&cgroup_dir.join("memory.current")),
            memory_peak = shell_single_quote(&cgroup_dir.join("memory.peak")),
            pids_current = shell_single_quote(&cgroup_dir.join("pids.current")),
        ))
        .expect("config should parse");

        let logs = capture_logs(|| {
            run(
                &config,
                &RunOptions {
                    argv_override: None,
                    artifact_dir: Some(artifact_dir),
                    cgroup_root_override: Some(cgroup_root),
                },
            )
            .expect("command should run")
        });

        assert!(logs.contains("audit_stage=\"cgroup_prepared\""));
        assert!(logs.contains("audit_stage=\"cgroup_finalized\""));
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
                cgroup_root_override: None,
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
    #[ignore = "requires user and mount namespace support in the test environment"]
    fn reuses_prepared_rootfs_plan_inside_pre_exec() {
        let support = probe_namespace_support();
        if !support.user_namespace || !support.mount_namespace {
            return;
        }

        let artifact_dir = unique_artifact_dir("rootfs-reuse");
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]
                cwd = "/work"

                [limits]
                wall_time_ms = 1000

                [filesystem]
                enable_rootfs = true
                enter_user_namespace = true
                enter_mount_namespace = true
                apply_mounts = true
                chroot_to_rootfs = true
                mount_proc = false
                work_dir = "/work"
                tmp_dir = "/tmp"
                executable_bind_paths = ["/bin", "/usr/bin"]
            "#,
        )
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir.clone()),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert_eq!(fs::read_to_string(result.stdout_path).unwrap(), "hello\n");
        assert!(artifact_dir.join("rootfs").exists());
        assert!(!artifact_dir.join("rootfs-preexec-error.log").exists());
    }

    #[test]
    fn rejects_output_paths_outside_artifact_dir() {
        let artifact_dir = unique_artifact_dir("output-guard");
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [limits]
                wall_time_ms = 1000

                [io]
                stdout_path = "/tmp/escaped-stdout.log"
            "#,
        )
        .expect("config should parse");

        let err = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
                cgroup_root_override: None,
            },
        )
        .expect_err("run should fail");

        assert!(
            err.to_string()
                .contains("configured path must stay within artifact directory")
        );
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
                cgroup_root_override: None,
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
        if !support.user_namespace || support.mount_namespace {
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
                cgroup_root_override: None,
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
                cgroup_root_override: None,
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
                cgroup_root_override: None,
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
                cgroup_root_override: None,
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
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert!(artifact_dir.join("work/probe.txt").exists());
    }

    #[test]
    #[ignore = "requires mount namespace and chroot privileges in the test environment"]
    fn keeps_readonly_input_immutable_and_allows_writable_output_dir() {
        let support = probe_namespace_support();
        if !support.user_namespace || !support.mount_namespace || !support.pid_namespace {
            return;
        }
        let artifact_dir = unique_artifact_dir("io-policy");
        let input_dir = artifact_dir.join("inputs");
        fs::create_dir_all(&input_dir).expect("input dir should exist");
        let input_file = input_dir.join("input.txt");
        fs::write(&input_file, "seed").expect("input file should exist");
        let readonly_probe = MaliciousScenario::ReadonlyInputTamper.argv();
        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "{readonly_probe} && {output_probe}"]

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
                readonly_bind_paths = ["{host_input_file}"]
                output_dir = "/output"
                executable_bind_paths = ["/bin", "/usr/bin"]
            "#,
            readonly_probe = readonly_probe[2],
            output_probe = Scenario::WritableOutputProbe.shell_snippet(),
            host_input_file = input_file.display(),
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir.clone()),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert_eq!(
            fs::read_to_string(&input_file).expect("input file should remain readable"),
            "seed"
        );
        assert_eq!(
            fs::read_to_string(artifact_dir.join("outputs/result.txt"))
                .expect("output file should exist"),
            "result"
        );
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
        let script = MaliciousScenario::HostFilesystemEscape.argv();

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
            script = script[2]
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
                cgroup_root_override: None,
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
        let script = MaliciousScenario::ProcInfoLeakProbe.argv();
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
            script = script[2]
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
                cgroup_root_override: None,
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
                cgroup_root_override: None,
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
                cgroup_root_override: None,
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
                cgroup_root_override: None,
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
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        let mut lines = stdout.lines();
        assert_eq!(lines.next(), Some("0"));
        assert_eq!(lines.next(), Some("0"));
    }

    #[test]
    #[ignore = "requires user namespace support in the test environment"]
    fn drops_capabilities_after_namespace_setup() {
        let support = probe_namespace_support();
        if !support.user_namespace {
            return;
        }

        let artifact_dir = unique_artifact_dir("caps-drop");
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "grep '^NoNewPrivs:' /proc/self/status && grep '^CapEff:' /proc/self/status && grep '^CapPrm:' /proc/self/status && grep '^CapInh:' /proc/self/status && grep '^CapBnd:' /proc/self/status"]

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
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        assert!(stdout.contains("NoNewPrivs:\t1"));
        assert!(stdout.contains("CapEff:\t0000000000000000"));
        assert!(stdout.contains("CapPrm:\t0000000000000000"));
        assert!(stdout.contains("CapInh:\t0000000000000000"));
        assert!(stdout.contains("CapBnd:\t0000000000000000"));
    }

    #[test]
    fn strict_seccomp_profile_blocks_socket_creation() {
        let argv = format!("{:?}", MaliciousScenario::StrictSocketCreation.argv());
        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = {argv}

                [security]
                seccomp_profile = "strict"
            "#,
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("seccomp-strict-socket")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        assert_eq!(stdout.trim(), "1");
    }

    #[test]
    fn installs_default_seccomp_filter() {
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "grep '^Seccomp:' /proc/self/status && grep '^NoNewPrivs:' /proc/self/status"]
            "#,
        )
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("seccomp-default")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        assert!(stdout.contains("Seccomp:\t2"));
        assert!(stdout.contains("NoNewPrivs:\t1"));
    }

    #[test]
    fn default_seccomp_profile_blocks_ptrace_in_supervisor_flow() {
        let argv = format!("{:?}", MaliciousScenario::DefaultPtraceProbe.argv());
        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = {argv}
            "#,
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("seccomp-default-ptrace")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        let mut lines = stdout.lines();
        assert_eq!(lines.next(), Some("-1"));
        assert_eq!(lines.next(), Some("1"));
    }

    #[test]
    #[ignore = "compat ptrace allow semantics are covered reliably in sandbox-seccomp tests"]
    fn compat_seccomp_profile_allows_ptrace_in_supervisor_flow() {
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/usr/bin/python3", "-c", "import ctypes; libc = ctypes.CDLL(None, use_errno=True); result = libc.ptrace(0, 0, None, 0); err = ctypes.get_errno(); print(result); print(err); raise SystemExit(0 if result == 0 else 1)"]

                [security]
                seccomp_profile = "compat"
            "#,
        )
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("seccomp-compat-ptrace")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        let mut lines = stdout.lines();
        assert_eq!(lines.next(), Some("0"));
        assert_eq!(lines.next(), Some("0"));
    }

    #[test]
    fn default_seccomp_profile_keeps_shell_runtime_compatible() {
        let config = seccomp_runtime_config(SeccompScenario::ShellRuntime, Some("default"));

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("seccomp-default-shell-runtime")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        assert_eq!(stdout.trim(), "shell-ok");
    }

    #[test]
    fn default_seccomp_profile_keeps_python_runtime_compatible() {
        let config = seccomp_runtime_config(SeccompScenario::PythonRuntime, Some("default"));

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("seccomp-default-python-runtime")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        assert_eq!(stdout.trim(), "b7ad5674");
    }

    #[test]
    fn compat_seccomp_profile_keeps_python_runtime_compatible() {
        let config = seccomp_runtime_config(SeccompScenario::PythonRuntime, Some("compat"));

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("seccomp-compat-python-runtime")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        assert_eq!(stdout.trim(), "b7ad5674");
    }

    #[test]
    fn strict_seccomp_profile_keeps_python_runtime_compatible() {
        let config = seccomp_runtime_config(SeccompScenario::PythonRuntime, Some("strict"));

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("seccomp-strict-python-runtime")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        assert_eq!(stdout.trim(), "b7ad5674");
    }

    #[test]
    fn strict_seccomp_profile_keeps_shell_runtime_compatible() {
        let config = seccomp_runtime_config(SeccompScenario::ShellRuntime, Some("strict"));

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("seccomp-strict-shell-runtime")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        assert_eq!(stdout.trim(), "shell-ok");
    }

    #[test]
    fn reads_cgroup_usage_and_cleans_up_when_limits_are_enabled() {
        let artifact_dir = unique_artifact_dir("cgroup-usage");
        let cgroup_root = unique_artifact_dir("cgroup-root");
        fs::create_dir_all(&cgroup_root).expect("cgroup root should exist");
        fs::write(cgroup_root.join("cgroup.controllers"), "memory pids cpu\n")
            .expect("controllers should exist");
        let cgroup_dir = cgroup_root.join(cgroup_scope_name(&artifact_dir));

        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "printf 'usage_usec 7000\n' > {cpu_stat}; printf '4096\n' > {memory_current}; printf '16384\n' > {memory_peak}; printf '2\n' > {pids_current}"]

                [limits]
                wall_time_ms = 1000
                memory_bytes = 16384
                max_processes = 8
            "#,
            cpu_stat = shell_single_quote(&cgroup_dir.join("cpu.stat")),
            memory_current = shell_single_quote(&cgroup_dir.join("memory.current")),
            memory_peak = shell_single_quote(&cgroup_dir.join("memory.peak")),
            pids_current = shell_single_quote(&cgroup_dir.join("pids.current")),
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
                cgroup_root_override: Some(cgroup_root),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert_eq!(result.usage.cpu_time_ms, Some(7));
        assert_eq!(result.usage.memory_peak_bytes, Some(16_384));
        assert!(
            !cgroup_dir.exists(),
            "cgroup directory should be cleaned up"
        );
    }

    #[test]
    fn cleans_up_cgroup_when_setup_fails_after_creation() {
        let artifact_dir = unique_artifact_dir("cgroup-setup-cleanup");
        let cgroup_root = unique_artifact_dir("cgroup-setup-cleanup-root");
        fs::create_dir_all(&cgroup_root).expect("cgroup root should exist");
        fs::write(cgroup_root.join("cgroup.controllers"), "memory pids cpu\n")
            .expect("controllers should exist");
        let cgroup_dir = cgroup_root.join(cgroup_scope_name(&artifact_dir));

        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [limits]
                wall_time_ms = 1000
                memory_bytes = 4096

                [io]
                stdout_path = "/tmp/escaped-stdout.log"
            "#,
        )
        .expect("config should parse");

        let err = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
                cgroup_root_override: Some(cgroup_root),
            },
        )
        .expect_err("run should fail");

        assert!(
            err.to_string()
                .contains("configured path must stay within artifact directory")
        );
        assert!(
            !cgroup_dir.exists(),
            "cgroup directory should be cleaned up after setup failure"
        );
    }

    #[test]
    fn cleans_up_cgroup_when_spawn_fails_after_creation() {
        let artifact_dir = unique_artifact_dir("cgroup-spawn-cleanup");
        let cgroup_root = unique_artifact_dir("cgroup-spawn-cleanup-root");
        fs::create_dir_all(&cgroup_root).expect("cgroup root should exist");
        fs::write(cgroup_root.join("cgroup.controllers"), "memory pids cpu\n")
            .expect("controllers should exist");
        let cgroup_dir = cgroup_root.join(cgroup_scope_name(&artifact_dir));

        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/definitely-missing-sandbox-command"]

                [limits]
                wall_time_ms = 1000
                memory_bytes = 4096
            "#,
        )
        .expect("config should parse");

        let err = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
                cgroup_root_override: Some(cgroup_root),
            },
        )
        .expect_err("run should fail");

        match err {
            SandboxError::Spawn(_) => {}
            other => panic!("unexpected error: {other}"),
        }
        assert!(
            !cgroup_dir.exists(),
            "cgroup directory should be cleaned up after spawn failure"
        );
    }

    #[test]
    fn kills_spawned_process_group_and_cleans_up_cgroup_when_waiting_fails() {
        let artifact_dir = unique_artifact_dir("wait-error-cleanup");
        let cgroup_root = unique_artifact_dir("wait-error-cleanup-root");
        fs::create_dir_all(&cgroup_root).expect("cgroup root should exist");
        fs::write(cgroup_root.join("cgroup.controllers"), "memory pids cpu\n")
            .expect("controllers should exist");
        let cgroup_dir = cgroup_root.join(cgroup_scope_name(&artifact_dir));
        let shell_pid_path = artifact_dir.join("shell.pid");
        let worker_pid_path = artifact_dir.join("worker.pid");

        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "printf '%s\n' $$ > {shell_pid}; /bin/sleep 5 & child=$!; printf '%s\n' \"$child\" > {worker_pid}; printf 'usage_usec nope\n' > {cpu_stat}; wait \"$child\""]

                [limits]
                wall_time_ms = 5000
                cpu_time_ms = 100
            "#,
            shell_pid = shell_single_quote(&shell_pid_path),
            worker_pid = shell_single_quote(&worker_pid_path),
            cpu_stat = shell_single_quote(&cgroup_dir.join("cpu.stat")),
        ))
        .expect("config should parse");

        let err = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
                cgroup_root_override: Some(cgroup_root),
            },
        )
        .expect_err("run should fail");

        assert!(
            err.to_string().contains("invalid cgroup key/value entry"),
            "unexpected error: {err}"
        );
        let shell_pid =
            read_pid_with_retry(&shell_pid_path).expect("shell pid should be recorded before exit");
        let worker_pid = read_pid_with_retry(&worker_pid_path)
            .expect("worker pid should be recorded before cleanup");
        assert!(
            wait_for_process_exit(shell_pid, Duration::from_secs(1)),
            "shell process should be terminated on wait error"
        );
        assert!(
            wait_for_process_exit(worker_pid, Duration::from_secs(1)),
            "child process should be terminated on wait error"
        );
        assert!(
            !cgroup_dir.exists(),
            "cgroup directory should be cleaned up after wait failure"
        );
    }

    #[test]
    fn reports_capability_error_when_cgroup_v2_root_is_unavailable() {
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [limits]
                wall_time_ms = 1000
                memory_bytes = 4096
            "#,
        )
        .expect("config should parse");

        let err = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("cgroup-unavailable")),
                cgroup_root_override: Some(unique_artifact_dir("missing-cgroup-root")),
            },
        )
        .expect_err("run should fail");

        match err {
            SandboxError::CapabilityUnavailable { capability, .. } => {
                assert_eq!(capability, "cgroup_v2");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn maps_memory_events_to_memory_limit_exceeded_status() {
        let artifact_dir = unique_artifact_dir("cgroup-memory-status");
        let cgroup_root = unique_artifact_dir("cgroup-memory-root");
        fs::create_dir_all(&cgroup_root).expect("cgroup root should exist");
        fs::write(cgroup_root.join("cgroup.controllers"), "memory pids cpu\n")
            .expect("controllers should exist");
        let cgroup_dir = cgroup_root.join(cgroup_scope_name(&artifact_dir));

        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "printf 'usage_usec 12000\n' > {cpu_stat}; printf '8192\n' > {memory_current}; printf '32768\n' > {memory_peak}; printf '0\n' > {pids_current}; printf 'low 0\nhigh 0\nmax 1\noom 1\noom_kill 1\n' > {memory_events}; exit 137"]

                [limits]
                wall_time_ms = 1000
                memory_bytes = 32768
            "#,
            cpu_stat = shell_single_quote(&cgroup_dir.join("cpu.stat")),
            memory_current = shell_single_quote(&cgroup_dir.join("memory.current")),
            memory_peak = shell_single_quote(&cgroup_dir.join("memory.peak")),
            pids_current = shell_single_quote(&cgroup_dir.join("pids.current")),
            memory_events = shell_single_quote(&cgroup_dir.join("memory.events")),
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
                cgroup_root_override: Some(cgroup_root),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::MemoryLimitExceeded);
        assert_eq!(result.exit_code, Some(137));
        assert_eq!(result.usage.cpu_time_ms, Some(12));
        assert_eq!(result.usage.memory_peak_bytes, Some(32_768));
    }

    #[test]
    fn maps_cpu_usage_to_time_limit_exceeded_status() {
        let artifact_dir = unique_artifact_dir("cgroup-cpu-status");
        let cgroup_root = unique_artifact_dir("cgroup-cpu-root");
        fs::create_dir_all(&cgroup_root).expect("cgroup root should exist");
        fs::write(cgroup_root.join("cgroup.controllers"), "memory pids cpu\n")
            .expect("controllers should exist");
        let cgroup_dir = cgroup_root.join(cgroup_scope_name(&artifact_dir));

        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "printf 'usage_usec 45000\n' > {cpu_stat}; exit 0"]

                [limits]
                wall_time_ms = 1000
                cpu_time_ms = 40
            "#,
            cpu_stat = shell_single_quote(&cgroup_dir.join("cpu.stat")),
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
                cgroup_root_override: Some(cgroup_root),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::TimeLimitExceeded);
        assert_eq!(result.usage.cpu_time_ms, Some(45));
        assert!(
            !cgroup_dir.exists(),
            "cgroup directory should be cleaned up"
        );
    }

    #[test]
    fn keeps_ok_status_when_cpu_usage_stays_within_limit() {
        let artifact_dir = unique_artifact_dir("cgroup-cpu-ok");
        let cgroup_root = unique_artifact_dir("cgroup-cpu-ok-root");
        fs::create_dir_all(&cgroup_root).expect("cgroup root should exist");
        fs::write(cgroup_root.join("cgroup.controllers"), "memory pids cpu\n")
            .expect("controllers should exist");
        let cgroup_dir = cgroup_root.join(cgroup_scope_name(&artifact_dir));

        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "printf 'usage_usec 25000\n' > {cpu_stat}; exit 0"]

                [limits]
                wall_time_ms = 1000
                cpu_time_ms = 40
            "#,
            cpu_stat = shell_single_quote(&cgroup_dir.join("cpu.stat")),
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
                cgroup_root_override: Some(cgroup_root),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert_eq!(result.usage.cpu_time_ms, Some(25));
    }

    #[test]
    fn keeps_ok_status_when_memory_usage_stays_within_limit() {
        let artifact_dir = unique_artifact_dir("cgroup-memory-ok");
        let cgroup_root = unique_artifact_dir("cgroup-memory-ok-root");
        fs::create_dir_all(&cgroup_root).expect("cgroup root should exist");
        fs::write(cgroup_root.join("cgroup.controllers"), "memory pids cpu\n")
            .expect("controllers should exist");
        let cgroup_dir = cgroup_root.join(cgroup_scope_name(&artifact_dir));

        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "printf 'usage_usec 8000\n' > {cpu_stat}; printf '4096\n' > {memory_current}; printf '12288\n' > {memory_peak}; printf '1\n' > {pids_current}; printf 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n' > {memory_events}; exit 0"]

                [limits]
                wall_time_ms = 1000
                memory_bytes = 16384
            "#,
            cpu_stat = shell_single_quote(&cgroup_dir.join("cpu.stat")),
            memory_current = shell_single_quote(&cgroup_dir.join("memory.current")),
            memory_peak = shell_single_quote(&cgroup_dir.join("memory.peak")),
            pids_current = shell_single_quote(&cgroup_dir.join("pids.current")),
            memory_events = shell_single_quote(&cgroup_dir.join("memory.events")),
        ))
        .expect("config should parse");

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(artifact_dir),
                cgroup_root_override: Some(cgroup_root),
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        assert_eq!(result.usage.cpu_time_ms, Some(8));
        assert_eq!(result.usage.memory_peak_bytes, Some(12_288));
    }

    #[test]
    #[ignore = "requires writable cgroup v2 support in the test environment"]
    fn enforces_pids_max_against_fork_attempts() {
        if !supports_writable_cgroup_v2() {
            return;
        }

        let config = resource_scenario_config(
            ResourceScenario::ForkBombProbe,
            "wall_time_ms = 1000\nmax_processes = 1",
        );

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("cgroup-pids-deny")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        assert_eq!(stdout.trim(), "11");
    }

    #[test]
    #[ignore = "requires writable cgroup v2 support in the test environment"]
    fn allows_small_process_tree_within_pids_max_limit() {
        if !supports_writable_cgroup_v2() {
            return;
        }

        let config = resource_scenario_config(
            ResourceScenario::SmallProcessTree,
            "wall_time_ms = 1000\nmax_processes = 4",
        );

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("cgroup-pids-allow")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        assert_eq!(stdout.trim(), "True");
    }

    #[test]
    #[ignore = "requires writable cgroup v2 support in the test environment"]
    fn enforces_real_cpu_time_limit_with_busy_loop() {
        if !supports_writable_cgroup_v2() {
            return;
        }

        let config = resource_scenario_config(
            ResourceScenario::CpuBusyLoop,
            "wall_time_ms = 3000\ncpu_time_ms = 100",
        );

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("cgroup-cpu-busy-loop")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::TimeLimitExceeded);
        assert!(result.usage.cpu_time_ms.is_some());
    }

    #[test]
    #[ignore = "requires writable cgroup v2 support in the test environment"]
    fn allows_real_cpu_bound_workload_within_limit() {
        if !supports_writable_cgroup_v2() {
            return;
        }

        let config = resource_scenario_config(
            ResourceScenario::CpuBoundSuccess,
            "wall_time_ms = 3000\ncpu_time_ms = 1000",
        );

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("cgroup-cpu-allow")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        assert_eq!(stdout.trim(), "True");
        assert!(result.usage.cpu_time_ms.is_some());
    }

    #[test]
    #[ignore = "requires writable cgroup v2 support in the test environment"]
    fn maps_real_memory_max_oom_to_memory_limit_exceeded() {
        if !supports_writable_cgroup_v2() {
            return;
        }

        let config = resource_scenario_config(
            ResourceScenario::MemoryBomb,
            "wall_time_ms = 3000\nmemory_bytes = 8388608",
        );

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("cgroup-memory-oom")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::MemoryLimitExceeded);
        assert!(result.usage.memory_peak_bytes.is_some());
    }

    #[test]
    #[ignore = "requires writable cgroup v2 support in the test environment"]
    fn allows_real_memory_allocation_within_limit() {
        if !supports_writable_cgroup_v2() {
            return;
        }

        let config = resource_scenario_config(
            ResourceScenario::MemoryWithinLimit,
            "wall_time_ms = 3000\nmemory_bytes = 16777216",
        );

        let result = run(
            &config,
            &RunOptions {
                argv_override: None,
                artifact_dir: Some(unique_artifact_dir("cgroup-memory-allow")),
                cgroup_root_override: None,
            },
        )
        .expect("command should run");

        assert_eq!(result.status, ExecutionStatus::Ok);
        let stdout = fs::read_to_string(result.stdout_path).expect("stdout should exist");
        assert_eq!(stdout.trim(), "1048576");
        assert!(result.usage.memory_peak_bytes.is_some());
    }

    fn resource_scenario_config(scenario: ResourceScenario, limits_body: &str) -> ExecutionConfig {
        let argv = format!("{:?}", scenario.argv());
        ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = {argv}

                [limits]
                {limits_body}
            "#
        ))
        .expect("config should parse")
    }

    fn seccomp_runtime_config(
        scenario: SeccompScenario,
        seccomp_profile: Option<&str>,
    ) -> ExecutionConfig {
        let argv = format!("{:?}", scenario.argv());
        let security = seccomp_profile
            .map(|profile| format!("\n[security]\nseccomp_profile = \"{profile}\"\n"))
            .unwrap_or_default();
        ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = {argv}
                {security}
            "#
        ))
        .expect("config should parse")
    }

    fn unique_artifact_dir(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("sandbox-{prefix}-{stamp}"))
    }

    fn shell_single_quote(path: &Path) -> String {
        format!("'{}'", path.display())
    }

    fn supports_writable_cgroup_v2() -> bool {
        let Ok(manager) = CgroupManager::probe_v2_root() else {
            return false;
        };
        let plan = CgroupPlan::new("sandbox-supervisor-cgroup-probe", Default::default());
        if manager.apply_limits(&plan).is_err() {
            return false;
        }
        let _ = manager.cleanup(&plan);
        true
    }

    fn read_pid_with_retry(path: &Path) -> Option<i32> {
        for _ in 0..100 {
            if let Ok(raw) = fs::read_to_string(path) {
                if let Ok(pid) = raw.trim().parse::<i32>() {
                    return Some(pid);
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        None
    }

    fn wait_for_process_exit(pid: i32, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if !process_exists(pid) {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }

        !process_exists(pid)
    }

    fn process_exists(pid: i32) -> bool {
        let result = unsafe { libc::kill(pid, 0) };
        if result == 0 {
            return true;
        }

        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    fn capture_logs<T>(f: impl FnOnce() -> T) -> String {
        let writer = SharedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer.clone())
            .with_ansi(false)
            .without_time()
            .with_target(true)
            .finish();
        let dispatch = Dispatch::new(subscriber);
        tracing::dispatcher::with_default(&dispatch, f);
        writer.contents()
    }

    #[derive(Clone, Default)]
    struct SharedWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedWriter {
        fn contents(&self) -> String {
            String::from_utf8(self.buffer.lock().expect("buffer should lock").clone())
                .expect("logs should be utf8")
        }
    }

    impl<'a> MakeWriter<'a> for SharedWriter {
        type Writer = SharedWriterGuard;

        fn make_writer(&'a self) -> Self::Writer {
            SharedWriterGuard {
                buffer: self.buffer.clone(),
            }
        }
    }

    struct SharedWriterGuard {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl std::io::Write for SharedWriterGuard {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buffer
                .lock()
                .expect("buffer should lock")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
