use std::path::PathBuf;
use std::process;

use anyhow::{Context, Error as AnyhowError, Result as AnyhowResult};
use clap::{Parser, Subcommand, ValueEnum};
use sandbox_config::ExecutionConfig;
use sandbox_core::{ExecutionResult, ExecutionStatus, SandboxError};
use sandbox_supervisor::{RunOptions, run};
use serde::Serialize;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "sandbox-cli")]
#[command(about = "Rust sandbox scaffold CLI")]
struct Cli {
    #[arg(long, global = true, default_value = "info")]
    log_level: String,
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Pretty)]
    log_format: LogFormat,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogFormat {
    Pretty,
    Json,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Run(RunArgs),
    Validate(ValidateArgs),
}

#[derive(Debug, Parser)]
struct RunArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    artifact_dir: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ResultFormat::Pretty)]
    result_format: ResultFormat,
    #[arg(long, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[derive(Debug, Parser)]
struct ValidateArgs {
    #[arg(long)]
    config: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ResultFormat {
    Pretty,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CliErrorCategory {
    Configuration,
    CapabilityUnavailable,
    PermissionIsolation,
    Io,
    Spawn,
    Timeout,
    Cleanup,
    UnsupportedPlatform,
    Internal,
}

impl CliErrorCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::CapabilityUnavailable => "capability_unavailable",
            Self::PermissionIsolation => "permission_isolation",
            Self::Io => "io",
            Self::Spawn => "spawn",
            Self::Timeout => "timeout",
            Self::Cleanup => "cleanup",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::Internal => "internal",
        }
    }

    fn exit_code(self) -> i32 {
        match self {
            Self::Configuration => 2,
            Self::Timeout => 3,
            Self::CapabilityUnavailable
            | Self::PermissionIsolation
            | Self::Io
            | Self::Spawn
            | Self::Cleanup
            | Self::UnsupportedPlatform
            | Self::Internal => 4,
        }
    }

    fn default_summary(self) -> &'static str {
        match self {
            Self::Configuration => "Invalid sandbox configuration",
            Self::CapabilityUnavailable => "Required sandbox capability is unavailable",
            Self::PermissionIsolation => "Permission isolation setup failed",
            Self::Io => "Sandbox I/O operation failed",
            Self::Spawn => "Sandbox payload could not be started",
            Self::Timeout => "Sandbox run timed out",
            Self::Cleanup => "Sandbox cleanup did not finish cleanly",
            Self::UnsupportedPlatform => "Sandbox is unsupported on this platform",
            Self::Internal => "Sandbox internal error",
        }
    }

    fn default_suggestion(self) -> &'static str {
        match self {
            Self::Configuration => {
                "Fix the config file or CLI arguments, then rerun `sandbox-cli validate`."
            }
            Self::CapabilityUnavailable => {
                "Enable the required host capability or disable the related sandbox feature."
            }
            Self::PermissionIsolation => {
                "Check namespace, UID/GID mapping, and privilege-related sandbox settings."
            }
            Self::Io => {
                "Check referenced files, directories, and artifact path permissions before retrying."
            }
            Self::Spawn => {
                "Verify the executable path, bind mounts, working directory, and pre-exec sandbox setup."
            }
            Self::Timeout => "Increase the time limit or reduce the payload runtime.",
            Self::Cleanup => {
                "Inspect audit logs and remove leftover sandbox artifacts before retrying."
            }
            Self::UnsupportedPlatform => "Run this sandbox on a supported Linux host.",
            Self::Internal => {
                "Inspect stderr and audit logs; if the issue persists, treat it as a sandbox bug."
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct CliErrorReport {
    operation: &'static str,
    category: CliErrorCategory,
    summary: String,
    detail: String,
    suggestion: String,
    exit_code: i32,
    causes: Vec<String>,
    #[serde(skip_serializing)]
    output_format: ResultFormat,
}

fn main() {
    let exit_code = match try_main() {
        Ok(code) => code,
        Err(report) => {
            print_cli_error_report(&report);
            report.exit_code
        }
    };

    process::exit(exit_code);
}

fn try_main() -> std::result::Result<i32, CliErrorReport> {
    let cli = Cli::parse();
    let error_format = cli_error_format(&cli);
    init_tracing(&cli).map_err(|err| build_error_report("startup", &err, error_format))?;

    match cli.command {
        Commands::Run(args) => run_command(args),
        Commands::Validate(args) => validate_command(args),
    }
}

fn cli_error_format(cli: &Cli) -> ResultFormat {
    match &cli.command {
        Commands::Run(args) => args.result_format,
        Commands::Validate(_) => ResultFormat::Pretty,
    }
}

fn init_tracing(cli: &Cli) -> AnyhowResult<()> {
    let env_filter = EnvFilter::try_new(&cli.log_level)
        .with_context(|| format!("invalid log filter `{}`", cli.log_level))?;
    let builder = tracing_subscriber::fmt().with_env_filter(env_filter);

    match cli.log_format {
        LogFormat::Pretty => builder.pretty().init(),
        LogFormat::Json => builder.json().init(),
    }

    Ok(())
}

fn run_command(args: RunArgs) -> std::result::Result<i32, CliErrorReport> {
    let config = ExecutionConfig::load(&args.config)
        .with_context(|| format!("failed to load config from {}", args.config.display()))
        .map_err(|err| build_error_report("run", &err, args.result_format))?;
    let result = run(
        &config,
        &RunOptions {
            argv_override: if args.command.is_empty() {
                None
            } else {
                Some(args.command)
            },
            artifact_dir: args.artifact_dir,
            cgroup_root_override: None,
        },
    )
    .with_context(|| {
        format!(
            "failed to execute sandbox run for {}",
            args.config.display()
        )
    })
    .map_err(|err| build_error_report("run", &err, args.result_format))?;

    match args.result_format {
        ResultFormat::Pretty => print_pretty_result(&result),
        ResultFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .expect("serializing execution result should succeed")
        ),
    }
    Ok(result.status.process_exit_code())
}

fn validate_command(args: ValidateArgs) -> std::result::Result<i32, CliErrorReport> {
    let config = ExecutionConfig::load(&args.config)
        .with_context(|| format!("failed to load config from {}", args.config.display()))
        .map_err(|err| build_error_report("validate", &err, ResultFormat::Pretty))?;

    print_validate_summary(&config, &args.config);
    Ok(0)
}

fn print_pretty_result(result: &ExecutionResult) {
    println!("{}", render_pretty_result(result));
}

fn print_validate_summary(config: &ExecutionConfig, config_path: &PathBuf) {
    let limits = config.resource_limits();
    let filesystem = &config.filesystem;

    println!("config: ok");
    println!("config_path: {}", config_path.display());
    println!("command: {:?}", config.process.argv);
    println!(
        "cwd: {}",
        config
            .process
            .cwd
            .as_ref()
            .map(|value| value.display().to_string())
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!("clear_env: {}", config.process.clear_env);
    println!("env_entries: {}", config.process.env.len());
    println!("wall_time_ms: {}", limits.wall_time_ms);
    println!("cpu_time_ms: {}", format_optional_u64(limits.cpu_time_ms));
    println!("memory_bytes: {}", format_optional_u64(limits.memory_bytes));
    println!(
        "max_processes: {}",
        format_optional_u64(limits.max_processes)
    );
    println!("cgroup_limits_enabled: {}", cgroup_limits_enabled(&limits));
    println!("seccomp_profile: {:?}", config.security.seccomp_profile);
    println!("rootfs_enabled: {}", filesystem.enable_rootfs);
    println!("mount_proc: {}", filesystem.mount_proc);
    println!("drop_capabilities: {}", filesystem.drop_capabilities);
    println!("chroot_to_rootfs: {}", filesystem.chroot_to_rootfs);
    println!("enter_user_namespace: {}", filesystem.enter_user_namespace);
    println!(
        "enter_mount_namespace: {}",
        filesystem.enter_mount_namespace
    );
    println!("enter_pid_namespace: {}", filesystem.enter_pid_namespace);
    println!(
        "enter_network_namespace: {}",
        filesystem.enter_network_namespace
    );
    println!("enter_ipc_namespace: {}", filesystem.enter_ipc_namespace);
    println!("apply_mounts: {}", filesystem.apply_mounts);
    println!("work_dir: {}", filesystem.work_dir.display());
    println!("tmp_dir: {}", filesystem.tmp_dir.display());
    println!(
        "output_dir: {}",
        filesystem
            .output_dir
            .as_ref()
            .map(|value| value.display().to_string())
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!(
        "artifact_dir: {}",
        config
            .io
            .artifact_dir
            .as_ref()
            .map(|value| value.display().to_string())
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!(
        "executable_bind_paths: {}",
        if filesystem.executable_bind_paths.is_empty() {
            "[]".to_string()
        } else {
            filesystem
                .executable_bind_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!(
        "readonly_bind_paths: {}",
        if filesystem.readonly_bind_paths.is_empty() {
            "[]".to_string()
        } else {
            filesystem
                .readonly_bind_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
}

fn status_label(status: &ExecutionStatus) -> &'static str {
    match status {
        ExecutionStatus::Ok => "ok",
        ExecutionStatus::TimeLimitExceeded => "time_limit_exceeded",
        ExecutionStatus::WallTimeLimitExceeded => "wall_time_limit_exceeded",
        ExecutionStatus::MemoryLimitExceeded => "memory_limit_exceeded",
        ExecutionStatus::OutputLimitExceeded => "output_limit_exceeded",
        ExecutionStatus::RuntimeError => "runtime_error",
        ExecutionStatus::SandboxError => "sandbox_error",
    }
}

fn run_outcome_label(status: &ExecutionStatus) -> &'static str {
    match status {
        ExecutionStatus::Ok => "success",
        ExecutionStatus::RuntimeError => "payload_runtime_failure",
        ExecutionStatus::TimeLimitExceeded
        | ExecutionStatus::WallTimeLimitExceeded
        | ExecutionStatus::MemoryLimitExceeded
        | ExecutionStatus::OutputLimitExceeded => "sandbox_limit_enforced",
        ExecutionStatus::SandboxError => "sandbox_failure",
    }
}

fn run_summary(result: &ExecutionResult) -> String {
    match result.status {
        ExecutionStatus::Ok => "payload completed successfully".to_string(),
        ExecutionStatus::RuntimeError => {
            if let Some(exit_code) = result.exit_code {
                format!("payload exited with non-zero status {exit_code}")
            } else if let Some(signal) = result.term_signal {
                format!("payload terminated by signal {signal}")
            } else {
                "payload exited with a runtime failure".to_string()
            }
        }
        ExecutionStatus::TimeLimitExceeded => {
            "payload exceeded the configured CPU time limit".to_string()
        }
        ExecutionStatus::WallTimeLimitExceeded => {
            "payload exceeded the configured wall-clock time limit".to_string()
        }
        ExecutionStatus::MemoryLimitExceeded => {
            "payload exceeded the configured memory limit".to_string()
        }
        ExecutionStatus::OutputLimitExceeded => {
            "payload exceeded the configured output limit".to_string()
        }
        ExecutionStatus::SandboxError => {
            "sandbox failed after the payload had already started".to_string()
        }
    }
}

fn run_suggestion(status: &ExecutionStatus) -> Option<&'static str> {
    match status {
        ExecutionStatus::Ok => None,
        ExecutionStatus::RuntimeError => {
            Some("Inspect the payload stderr/stdout artifacts to debug the program itself.")
        }
        ExecutionStatus::TimeLimitExceeded
        | ExecutionStatus::WallTimeLimitExceeded
        | ExecutionStatus::MemoryLimitExceeded
        | ExecutionStatus::OutputLimitExceeded => Some(
            "Inspect the artifact logs and adjust the sandbox limits if this payload is expected to succeed.",
        ),
        ExecutionStatus::SandboxError => {
            Some("Inspect stderr and audit logs to debug the sandbox itself.")
        }
    }
}

fn render_pretty_result(result: &ExecutionResult) -> String {
    let mut lines = vec![
        format!("status: {}", status_label(&result.status)),
        format!("outcome: {}", run_outcome_label(&result.status)),
        format!("summary: {}", run_summary(result)),
        format!("command: {:?}", result.command),
        format!("exit_code: {}", format_optional_i32(result.exit_code)),
        format!("term_signal: {}", format_optional_i32(result.term_signal)),
        format!("wall_time_ms: {}", result.usage.wall_time_ms),
        format!(
            "cpu_time_ms: {}",
            format_optional_u64(result.usage.cpu_time_ms)
        ),
        format!(
            "memory_peak_bytes: {}",
            format_optional_u64(result.usage.memory_peak_bytes)
        ),
        format!("stdout: {}", result.stdout_path.display()),
        format!("stderr: {}", result.stderr_path.display()),
    ];

    if let Some(suggestion) = run_suggestion(&result.status) {
        lines.insert(3, format!("suggestion: {suggestion}"));
    }

    lines.join("\n")
}

fn print_cli_error_report(report: &CliErrorReport) {
    match report.output_format {
        ResultFormat::Pretty => eprintln!("{}", render_pretty_error_report(report)),
        ResultFormat::Json => eprintln!(
            "{}",
            serde_json::to_string_pretty(report)
                .expect("serializing cli error report should succeed")
        ),
    }
}

fn render_pretty_error_report(report: &CliErrorReport) -> String {
    let mut lines = vec![
        format!("error: {}", report.summary),
        format!("operation: {}", report.operation),
        format!("category: {}", report.category.as_str()),
        format!("detail: {}", report.detail),
        format!("suggestion: {}", report.suggestion),
        format!("exit_code: {}", report.exit_code),
    ];

    for (index, cause) in report.causes.iter().enumerate() {
        lines.push(format!("cause_{}: {}", index + 1, cause));
    }

    lines.join("\n")
}

fn build_error_report(
    operation: &'static str,
    error: &AnyhowError,
    output_format: ResultFormat,
) -> CliErrorReport {
    let causes = collect_error_causes(error);
    let (category, detail) = match find_sandbox_error(error) {
        Some(sandbox_error) => (
            classify_sandbox_error(sandbox_error),
            sandbox_error.to_string(),
        ),
        None if operation == "startup" => (CliErrorCategory::Configuration, error.to_string()),
        None => (CliErrorCategory::Internal, error.to_string()),
    };

    CliErrorReport {
        operation,
        category,
        summary: category.default_summary().to_string(),
        detail,
        suggestion: category.default_suggestion().to_string(),
        exit_code: category.exit_code(),
        causes,
        output_format,
    }
}

fn collect_error_causes(error: &AnyhowError) -> Vec<String> {
    let mut causes = Vec::new();
    for cause in error.chain() {
        let rendered = cause.to_string();
        if causes.last() != Some(&rendered) {
            causes.push(rendered);
        }
    }
    causes
}

fn find_sandbox_error(error: &AnyhowError) -> Option<&SandboxError> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<SandboxError>())
}

fn classify_sandbox_error(error: &SandboxError) -> CliErrorCategory {
    match error {
        SandboxError::Config(_) => CliErrorCategory::Configuration,
        SandboxError::CapabilityUnavailable { .. } => CliErrorCategory::CapabilityUnavailable,
        SandboxError::Permission(_) => CliErrorCategory::PermissionIsolation,
        SandboxError::Io { .. } => CliErrorCategory::Io,
        SandboxError::Spawn(_) => CliErrorCategory::Spawn,
        SandboxError::Timeout { .. } => CliErrorCategory::Timeout,
        SandboxError::Cleanup(_) => CliErrorCategory::Cleanup,
        SandboxError::UnsupportedPlatform(_) => CliErrorCategory::UnsupportedPlatform,
        SandboxError::Internal(_) => CliErrorCategory::Internal,
    }
}

fn cgroup_limits_enabled(limits: &sandbox_core::ResourceLimits) -> bool {
    limits.cpu_time_ms.is_some() || limits.memory_bytes.is_some() || limits.max_processes.is_some()
}

fn format_optional_u64(value: Option<u64>) -> String {
    value
        .map(|current| current.to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

fn format_optional_i32(value: Option<i32>) -> String {
    value
        .map(|current| current.to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use std::path::PathBuf;

    use super::{
        CliErrorCategory, ResultFormat, build_error_report, cgroup_limits_enabled,
        format_optional_i32, format_optional_u64, print_validate_summary,
        render_pretty_error_report, render_pretty_result, run_outcome_label, status_label,
    };
    use sandbox_config::ExecutionConfig;
    use sandbox_core::{
        ExecutionResult, ExecutionStatus, ResourceLimits, ResourceUsage, SandboxError,
    };

    #[test]
    fn formats_missing_numeric_fields_as_na() {
        assert_eq!(format_optional_u64(None), "n/a");
        assert_eq!(format_optional_i32(None), "n/a");
    }

    #[test]
    fn exposes_human_readable_status_labels() {
        assert_eq!(status_label(&ExecutionStatus::Ok), "ok");
        assert_eq!(
            status_label(&ExecutionStatus::MemoryLimitExceeded),
            "memory_limit_exceeded"
        );
        assert_eq!(
            status_label(&ExecutionStatus::WallTimeLimitExceeded),
            "wall_time_limit_exceeded"
        );
        assert_eq!(
            run_outcome_label(&ExecutionStatus::RuntimeError),
            "payload_runtime_failure"
        );
    }

    #[test]
    fn enables_cgroup_summary_when_cpu_limit_is_present() {
        let limits = ResourceLimits {
            cpu_time_ms: Some(250),
            wall_time_ms: 1000,
            memory_bytes: None,
            max_processes: None,
        };

        assert!(cgroup_limits_enabled(&limits));
    }

    #[test]
    fn validate_summary_covers_security_and_cgroup_flags() {
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [limits]
                wall_time_ms = 1000
                memory_bytes = 4096
                max_processes = 8

                [security]
                seccomp_profile = "compat"

                [filesystem]
                enable_rootfs = true
                enter_user_namespace = true
                enter_mount_namespace = true
                enter_pid_namespace = true
                apply_mounts = true
                chroot_to_rootfs = true
                mount_proc = true
            "#,
        )
        .expect("config should parse");

        print_validate_summary(&config, &PathBuf::from("configs/test.toml"));
    }

    #[test]
    fn classifies_configuration_errors_for_user_reports() {
        let err = Err::<(), _>(SandboxError::config("process.argv must not be empty"))
            .with_context(|| "failed to load config from configs/bad.toml")
            .expect_err("error should be returned");

        let report = build_error_report("validate", &err, ResultFormat::Pretty);

        assert_eq!(report.category, CliErrorCategory::Configuration);
        assert_eq!(report.exit_code, 2);
        assert!(report.detail.contains("configuration error"));
        assert!(
            report
                .causes
                .iter()
                .any(|cause| cause.contains("failed to load config"))
        );
    }

    #[test]
    fn classifies_capability_errors_for_user_reports() {
        let err = anyhow::Error::new(SandboxError::capability_unavailable(
            "mount_namespace",
            "operation not permitted",
        ));

        let report = build_error_report("run", &err, ResultFormat::Json);

        assert_eq!(report.category, CliErrorCategory::CapabilityUnavailable);
        assert_eq!(report.exit_code, 4);
        assert!(report.detail.contains("mount_namespace"));
    }

    #[test]
    fn renders_pretty_error_report_with_guidance() {
        let err = anyhow::Error::new(SandboxError::Spawn("No such file or directory".into()));

        let report = build_error_report("run", &err, ResultFormat::Pretty);
        let rendered = render_pretty_error_report(&report);

        assert!(rendered.contains("error: Sandbox payload could not be started"));
        assert!(rendered.contains("category: spawn"));
        assert!(rendered.contains("suggestion: Verify the executable path"));
        assert!(rendered.contains("cause_1: failed to spawn process"));
    }

    #[test]
    fn serializes_json_error_reports_with_category_and_operation() {
        let err = anyhow::Error::new(SandboxError::capability_unavailable(
            "cgroup_v2",
            "missing controller file",
        ));

        let report = build_error_report("run", &err, ResultFormat::Json);
        let rendered =
            serde_json::to_string(&report).expect("serializing error report should succeed");

        assert!(rendered.contains("\"operation\":\"run\""));
        assert!(rendered.contains("\"category\":\"capability_unavailable\""));
        assert!(rendered.contains("\"exit_code\":4"));
    }

    #[test]
    fn pretty_result_highlights_runtime_failures() {
        let rendered = render_pretty_result(&ExecutionResult {
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 42".to_string(),
            ],
            exit_code: Some(42),
            term_signal: None,
            usage: ResourceUsage {
                cpu_time_ms: None,
                wall_time_ms: 15,
                memory_peak_bytes: None,
            },
            stdout_path: PathBuf::from("/tmp/stdout.log"),
            stderr_path: PathBuf::from("/tmp/stderr.log"),
            status: ExecutionStatus::RuntimeError,
        });

        assert!(rendered.contains("outcome: payload_runtime_failure"));
        assert!(rendered.contains("summary: payload exited with non-zero status 42"));
        assert!(rendered.contains("suggestion: Inspect the payload stderr/stdout artifacts"));
    }
}
