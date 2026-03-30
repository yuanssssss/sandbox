use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sandbox_config::ExecutionConfig;
use sandbox_core::{ExecutionResult, ExecutionStatus};
use sandbox_supervisor::{RunOptions, run};
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli)?;

    match cli.command {
        Commands::Run(args) => run_command(args),
        Commands::Validate(args) => validate_command(args),
    }
}

fn init_tracing(cli: &Cli) -> Result<()> {
    let env_filter = EnvFilter::try_new(&cli.log_level)
        .with_context(|| format!("invalid log filter `{}`", cli.log_level))?;
    let builder = tracing_subscriber::fmt().with_env_filter(env_filter);

    match cli.log_format {
        LogFormat::Pretty => builder.pretty().init(),
        LogFormat::Json => builder.json().init(),
    }

    Ok(())
}

fn run_command(args: RunArgs) -> Result<()> {
    let config = ExecutionConfig::load(&args.config)
        .with_context(|| format!("failed to load config from {}", args.config.display()))?;
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
    )?;

    match args.result_format {
        ResultFormat::Pretty => print_pretty_result(&result),
        ResultFormat::Json => println!("{}", serde_json::to_string_pretty(&result)?),
    }
    std::process::exit(result.status.process_exit_code());
}

fn validate_command(args: ValidateArgs) -> Result<()> {
    let config = ExecutionConfig::load(&args.config)
        .with_context(|| format!("failed to load config from {}", args.config.display()))?;

    print_validate_summary(&config, &args.config);
    Ok(())
}

fn print_pretty_result(result: &ExecutionResult) {
    println!("status: {}", status_label(&result.status));
    println!("command: {:?}", result.command);
    println!("exit_code: {}", format_optional_i32(result.exit_code));
    println!("term_signal: {}", format_optional_i32(result.term_signal));
    println!("wall_time_ms: {}", result.usage.wall_time_ms);
    println!(
        "cpu_time_ms: {}",
        format_optional_u64(result.usage.cpu_time_ms)
    );
    println!(
        "memory_peak_bytes: {}",
        format_optional_u64(result.usage.memory_peak_bytes)
    );
    println!("stdout: {}", result.stdout_path.display());
    println!("stderr: {}", result.stderr_path.display());
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
    use std::path::PathBuf;

    use super::{
        cgroup_limits_enabled, format_optional_i32, format_optional_u64, print_validate_summary,
        status_label,
    };
    use sandbox_config::ExecutionConfig;
    use sandbox_core::{ExecutionStatus, ResourceLimits};

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
}
