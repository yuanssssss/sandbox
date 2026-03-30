use std::fs::{self, File};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandbox_config::ExecutionConfig;
use sandbox_core::{ExecutionResult, ExecutionStatus, ResourceUsage, Result, SandboxError};
use sandbox_mount::{prepare_rootfs, setup_rootfs};
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
        process.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if filesystem.enable_rootfs && filesystem.enter_mount_namespace {
                let _runtime = setup_rootfs(&filesystem, &artifact_dir, rootfs_cwd.as_deref())
                    .map_err(|err| {
                        let _ = fs::write(
                            artifact_dir.join("rootfs-preexec-error.log"),
                            err.to_string(),
                        );
                        std::io::Error::other(err)
                    })?;
            }
            Ok(())
        });
    }

    info!(command = ?command, artifact_dir = %artifact_dir.display(), "spawning sandbox payload");
    let mut child = process
        .spawn()
        .map_err(|err| SandboxError::Spawn(err.to_string()))?;
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
    use sandbox_core::ExecutionStatus;
    use sandbox_testkit::Scenario;

    use crate::{RunOptions, rootfs_cwd, run};

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
    #[ignore = "requires mount namespace and chroot privileges in the test environment"]
    fn can_write_inside_sandbox_workdir_when_mounts_are_enabled() {
        let artifact_dir = unique_artifact_dir("workdir-probe");
        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "{script}"]

                [limits]
                wall_time_ms = 1000

                [filesystem]
                enable_rootfs = true
                enter_mount_namespace = true
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
                enter_mount_namespace = true
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
        let artifact_dir = unique_artifact_dir("proc-visibility");
        let config = ExecutionConfig::from_toml_str(&format!(
            r#"
                [process]
                argv = ["/bin/sh", "-c", "{script}"]

                [limits]
                wall_time_ms = 1000

                [filesystem]
                enable_rootfs = true
                enter_mount_namespace = true
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

    fn unique_artifact_dir(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("sandbox-{prefix}-{stamp}"))
    }
}
