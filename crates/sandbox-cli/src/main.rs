use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sandbox_config::ExecutionConfig;
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
    #[arg(long, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[derive(Debug, Parser)]
struct ValidateArgs {
    #[arg(long)]
    config: PathBuf,
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

    println!("{}", serde_json::to_string_pretty(&result)?);
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
