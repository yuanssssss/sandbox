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
    let limits = config.resource_limits();

    println!(
        "config OK\ncommand: {:?}\nwall_time_ms: {}\ncpu_time_ms: {:?}\nmemory_bytes: {:?}\nmax_processes: {:?}",
        config.process.argv,
        limits.wall_time_ms,
        limits.cpu_time_ms,
        limits.memory_bytes,
        limits.max_processes
    );
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
    use super::{format_optional_i32, format_optional_u64, status_label};
    use sandbox_core::ExecutionStatus;

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
}
