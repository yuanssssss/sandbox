use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process;

use anyhow::{Context, Error as AnyhowError, Result as AnyhowResult};
use clap::{Parser, Subcommand, ValueEnum};
use sandbox_cgroup::{CgroupManager, CgroupPlan};
use sandbox_config::ExecutionConfig;
use sandbox_core::{
    CompilationResult, CompilationStatus, ExecutionResult, ExecutionStatus, SandboxError,
};
use sandbox_protocol::{ProtocolServerOptions, serve_with_options as serve_protocol};
use sandbox_supervisor::{
    CompileOptions, NamespaceSupport, RunOptions, cgroup_scope_name, compile, planned_artifact_dir,
    probe_namespace_support, rootfs_cwd, run,
};
use serde::{Deserialize, Serialize};
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
    Compile(CompileArgs),
    Run(RunArgs),
    Validate(ValidateArgs),
    Inspect(InspectArgs),
    Debug(DebugArgs),
    Serve(ServeArgs),
}

#[derive(Debug, Parser)]
struct CompileArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    source_dir: Option<PathBuf>,
    #[arg(long)]
    output_dir: Option<PathBuf>,
    #[arg(long)]
    artifact_dir: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ResultFormat::Pretty)]
    result_format: ResultFormat,
    #[arg(long, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
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

#[derive(Debug, Parser)]
struct InspectArgs {
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
struct DebugArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    artifact_dir: Option<PathBuf>,
    #[arg(long, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[derive(Debug, Parser)]
struct ServeArgs {
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: SocketAddr,
    #[arg(long)]
    server_config: Option<PathBuf>,
    #[arg(long)]
    auth_token: Option<String>,
    #[arg(long)]
    read_auth_token: Option<String>,
    #[arg(long)]
    write_auth_token: Option<String>,
    #[arg(long)]
    max_request_body_bytes: Option<usize>,
    #[arg(long)]
    max_concurrent_requests: Option<usize>,
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

#[derive(Debug, Serialize)]
struct InspectReport {
    operation: &'static str,
    config_path: PathBuf,
    artifact_dir: PathBuf,
    artifact_dir_source: &'static str,
    command: Vec<String>,
    command_override_applied: bool,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    stdout_within_artifact_dir: bool,
    stderr_within_artifact_dir: bool,
    process_cwd: Option<PathBuf>,
    sandbox_cwd: Option<PathBuf>,
    cgroup: InspectCgroup,
    filesystem: InspectFilesystem,
    host_support: InspectHostSupport,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct InspectCgroup {
    enabled: bool,
    root: Option<PathBuf>,
    scope_name: Option<String>,
    path: Option<PathBuf>,
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct InspectFilesystem {
    rootfs_enabled: bool,
    rootfs_dir: Option<PathBuf>,
    host_work_dir: Option<PathBuf>,
    host_tmp_dir: Option<PathBuf>,
    host_output_dir: Option<PathBuf>,
    sandbox_work_dir: PathBuf,
    sandbox_tmp_dir: PathBuf,
    sandbox_output_dir: Option<PathBuf>,
    readonly_inputs: Vec<InspectBinding>,
    executable_bind_paths: Vec<PathBuf>,
    runtime_bind_paths: Vec<PathBuf>,
}

#[derive(Debug, Serialize)]
struct InspectBinding {
    source: PathBuf,
    target: PathBuf,
}

#[derive(Debug, Serialize)]
struct InspectHostSupport {
    user_namespace: InspectSupportFlag,
    mount_namespace: InspectSupportFlag,
    pid_namespace: InspectSupportFlag,
    network_namespace: InspectSupportFlag,
    ipc_namespace: InspectSupportFlag,
}

#[derive(Debug, Serialize)]
struct InspectSupportFlag {
    requested: bool,
    available: bool,
    reason: Option<String>,
}

#[cfg(test)]
#[derive(Debug, Serialize)]
struct DebugReport {
    inspect: InspectReport,
    result: Option<ExecutionResult>,
    error: Option<CliErrorReport>,
    exit_code: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ProtocolServerFileConfig {
    auth_token: Option<String>,
    auth_token_env: Option<String>,
    auth_token_file: Option<PathBuf>,
    read_auth_token: Option<String>,
    read_auth_token_env: Option<String>,
    read_auth_token_file: Option<PathBuf>,
    write_auth_token: Option<String>,
    write_auth_token_env: Option<String>,
    write_auth_token_file: Option<PathBuf>,
    max_request_body_bytes: Option<usize>,
    max_concurrent_requests: Option<usize>,
}

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("creating tokio runtime should succeed");
    let exit_code = match runtime.block_on(try_main()) {
        Ok(code) => code,
        Err(report) => {
            print_cli_error_report(&report);
            report.exit_code
        }
    };

    process::exit(exit_code);
}

async fn try_main() -> std::result::Result<i32, CliErrorReport> {
    let cli = Cli::parse();
    let error_format = cli_error_format(&cli);
    init_tracing(&cli).map_err(|err| build_error_report("startup", &err, error_format))?;

    match cli.command {
        Commands::Compile(args) => compile_command(args),
        Commands::Run(args) => run_command(args),
        Commands::Validate(args) => validate_command(args),
        Commands::Inspect(args) => inspect_command(args),
        Commands::Debug(args) => debug_command(args),
        Commands::Serve(args) => serve_command(args).await,
    }
}

fn cli_error_format(cli: &Cli) -> ResultFormat {
    match &cli.command {
        Commands::Compile(args) => args.result_format,
        Commands::Run(args) => args.result_format,
        Commands::Inspect(args) => args.result_format,
        Commands::Validate(_) | Commands::Debug(_) | Commands::Serve(_) => ResultFormat::Pretty,
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

fn load_server_file_config(path: &Path) -> AnyhowResult<ProtocolServerFileConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read server config from {}", path.display()))?;
    toml::from_str(&raw)
        .with_context(|| format!("failed to parse server config from {}", path.display()))
}

fn resolve_server_auth_token(
    cli_auth_token: Option<String>,
    file_config: &ProtocolServerFileConfig,
) -> AnyhowResult<Option<String>> {
    if cli_auth_token.is_some() {
        return Ok(cli_auth_token);
    }
    if file_config.auth_token.is_some() {
        return Ok(file_config.auth_token.clone());
    }
    if let Some(path) = file_config.auth_token_file.as_ref() {
        let token = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read auth token file {}", path.display()))?;
        return Ok(Some(token.trim().to_string()));
    }
    if let Some(env_name) = file_config.auth_token_env.as_deref() {
        return Ok(std::env::var(env_name).ok());
    }

    Ok(std::env::var("SANDBOX_PROTOCOL_AUTH_TOKEN").ok())
}

fn resolve_token_source(
    cli_value: Option<String>,
    file_value: &Option<String>,
    file_path: Option<&PathBuf>,
    file_env: Option<&str>,
    fallback_env: Option<&str>,
) -> AnyhowResult<Option<String>> {
    if cli_value.is_some() {
        return Ok(cli_value);
    }
    if file_value.is_some() {
        return Ok(file_value.clone());
    }
    if let Some(path) = file_path {
        let token = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read auth token file {}", path.display()))?;
        return Ok(Some(token.trim().to_string()));
    }
    if let Some(env_name) = file_env {
        return Ok(std::env::var(env_name).ok());
    }
    if let Some(env_name) = fallback_env {
        return Ok(std::env::var(env_name).ok());
    }

    Ok(None)
}

fn resolve_server_options(
    args: &ServeArgs,
    file_config: &ProtocolServerFileConfig,
) -> AnyhowResult<ProtocolServerOptions> {
    let max_request_body_bytes = args
        .max_request_body_bytes
        .or(file_config.max_request_body_bytes)
        .unwrap_or(1024 * 1024);
    if max_request_body_bytes == 0 {
        anyhow::bail!("max_request_body_bytes must be greater than 0");
    }

    let max_concurrent_requests = args
        .max_concurrent_requests
        .or(file_config.max_concurrent_requests)
        .unwrap_or(32);
    if max_concurrent_requests == 0 {
        anyhow::bail!("max_concurrent_requests must be greater than 0");
    }

    Ok(ProtocolServerOptions {
        auth_token: resolve_server_auth_token(args.auth_token.clone(), file_config)?,
        read_auth_token: resolve_token_source(
            args.read_auth_token.clone(),
            &file_config.read_auth_token,
            file_config.read_auth_token_file.as_ref(),
            file_config.read_auth_token_env.as_deref(),
            Some("SANDBOX_PROTOCOL_READ_AUTH_TOKEN"),
        )?,
        write_auth_token: resolve_token_source(
            args.write_auth_token.clone(),
            &file_config.write_auth_token,
            file_config.write_auth_token_file.as_ref(),
            file_config.write_auth_token_env.as_deref(),
            Some("SANDBOX_PROTOCOL_WRITE_AUTH_TOKEN"),
        )?,
        max_request_body_bytes,
        max_concurrent_requests,
    })
}

fn compile_command(args: CompileArgs) -> std::result::Result<i32, CliErrorReport> {
    let config = ExecutionConfig::load(&args.config)
        .with_context(|| format!("failed to load config from {}", args.config.display()))
        .map_err(|err| build_error_report("compile", &err, args.result_format))?;
    let result = execute_compile(
        &config,
        &args.config,
        args.source_dir,
        args.output_dir,
        args.artifact_dir,
        args.command,
        "compile",
        args.result_format,
    )?;

    match args.result_format {
        ResultFormat::Pretty => print_pretty_compilation_result(&result),
        ResultFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .expect("serializing compilation result should succeed")
        ),
    }

    Ok(result.status.process_exit_code())
}

fn run_command(args: RunArgs) -> std::result::Result<i32, CliErrorReport> {
    let config = ExecutionConfig::load(&args.config)
        .with_context(|| format!("failed to load config from {}", args.config.display()))
        .map_err(|err| build_error_report("run", &err, args.result_format))?;
    let result = execute_run(
        &config,
        &args.config,
        args.artifact_dir,
        args.command,
        "run",
        args.result_format,
    )?;

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

fn inspect_command(args: InspectArgs) -> std::result::Result<i32, CliErrorReport> {
    let config = ExecutionConfig::load(&args.config)
        .with_context(|| format!("failed to load config from {}", args.config.display()))
        .map_err(|err| build_error_report("inspect", &err, args.result_format))?;
    let report = build_inspect_report(
        "inspect",
        &args.config,
        &config,
        args.artifact_dir,
        args.command,
    );

    match args.result_format {
        ResultFormat::Pretty => println!("{}", render_pretty_inspect_report(&report)),
        ResultFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .expect("serializing inspect report should succeed")
        ),
    }

    Ok(0)
}

fn debug_command(args: DebugArgs) -> std::result::Result<i32, CliErrorReport> {
    let config = ExecutionConfig::load(&args.config)
        .with_context(|| format!("failed to load config from {}", args.config.display()))
        .map_err(|err| build_error_report("debug", &err, ResultFormat::Pretty))?;
    let inspect = build_inspect_report(
        "debug",
        &args.config,
        &config,
        args.artifact_dir.clone(),
        args.command.clone(),
    );
    println!("{}", render_pretty_inspect_report(&inspect));
    println!();

    match execute_run(
        &config,
        &args.config,
        args.artifact_dir,
        args.command,
        "debug",
        ResultFormat::Pretty,
    ) {
        Ok(result) => {
            let exit_code = result.status.process_exit_code();
            println!("{}", render_pretty_result(&result));
            println!();
            println!("debug_exit_code: {exit_code}");
            Ok(exit_code)
        }
        Err(error) => {
            let exit_code = error.exit_code;
            eprintln!("{}", render_pretty_error_report(&error));
            eprintln!();
            eprintln!("debug_exit_code: {exit_code}");
            Ok(exit_code)
        }
    }
}

async fn serve_command(args: ServeArgs) -> std::result::Result<i32, CliErrorReport> {
    let file_config = match args.server_config.as_deref() {
        Some(path) => load_server_file_config(path)
            .map_err(|err| build_error_report("serve", &err, ResultFormat::Pretty))?,
        None => ProtocolServerFileConfig::default(),
    };
    let options = resolve_server_options(&args, &file_config)
        .map_err(|err| build_error_report("serve", &err, ResultFormat::Pretty))?;

    serve_protocol(args.listen, options)
        .await
        .with_context(|| format!("failed to serve sandbox protocol on {}", args.listen))
        .map_err(|err| build_error_report("serve", &err, ResultFormat::Pretty))?;
    Ok(0)
}

fn execute_compile(
    config: &ExecutionConfig,
    config_path: &Path,
    source_dir: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    artifact_dir: Option<PathBuf>,
    command: Vec<String>,
    operation: &'static str,
    error_format: ResultFormat,
) -> std::result::Result<CompilationResult, CliErrorReport> {
    compile(
        config,
        &CompileOptions {
            argv_override: command_override(command),
            artifact_dir,
            cgroup_root_override: None,
            source_dir,
            output_dir,
        },
    )
    .with_context(|| {
        format!(
            "failed to execute sandbox compile for {}",
            config_path.display()
        )
    })
    .map_err(|err| build_error_report(operation, &err, error_format))
}

fn execute_run(
    config: &ExecutionConfig,
    config_path: &Path,
    artifact_dir: Option<PathBuf>,
    command: Vec<String>,
    operation: &'static str,
    error_format: ResultFormat,
) -> std::result::Result<ExecutionResult, CliErrorReport> {
    run(
        config,
        &RunOptions {
            argv_override: command_override(command),
            artifact_dir,
            cgroup_root_override: None,
        },
    )
    .with_context(|| {
        format!(
            "failed to execute sandbox run for {}",
            config_path.display()
        )
    })
    .map_err(|err| build_error_report(operation, &err, error_format))
}

fn build_inspect_report(
    operation: &'static str,
    config_path: &Path,
    config: &ExecutionConfig,
    artifact_dir_override: Option<PathBuf>,
    command: Vec<String>,
) -> InspectReport {
    let command_override_applied = !command.is_empty();
    let artifact_dir_source = if artifact_dir_override.is_some() {
        "cli_override"
    } else if config.io.artifact_dir.is_some() {
        "config"
    } else {
        "auto"
    };
    let run_options = RunOptions {
        argv_override: command_override(command.clone()),
        artifact_dir: artifact_dir_override,
        cgroup_root_override: None,
    };
    let artifact_dir = planned_artifact_dir(config, &run_options);
    let resolved_command = run_options
        .argv_override
        .clone()
        .unwrap_or_else(|| config.process.argv.clone());
    let stdout_path = resolve_cli_output_path(
        &artifact_dir,
        config.io.stdout_path.as_deref(),
        "stdout.log",
    );
    let stderr_path = resolve_cli_output_path(
        &artifact_dir,
        config.io.stderr_path.as_deref(),
        "stderr.log",
    );
    let stdout_within_artifact_dir = stdout_path.starts_with(&artifact_dir);
    let stderr_within_artifact_dir = stderr_path.starts_with(&artifact_dir);
    let namespace_support = probe_namespace_support();
    let readonly_inputs = inspect_readonly_inputs(&config.filesystem.readonly_bind_paths);
    let cgroup = inspect_cgroup(config, &artifact_dir);
    let filesystem = inspect_filesystem(config, &artifact_dir, readonly_inputs);
    let host_support = inspect_host_support(config, &namespace_support);
    let mut warnings = Vec::new();

    if !stdout_path.starts_with(&artifact_dir) {
        warnings.push(format!(
            "stdout path escapes artifact directory: {}",
            stdout_path.display()
        ));
    }
    if !stderr_path.starts_with(&artifact_dir) {
        warnings.push(format!(
            "stderr path escapes artifact directory: {}",
            stderr_path.display()
        ));
    }
    if cgroup.enabled && cgroup.root.is_none() {
        warnings.push(
            cgroup
                .detail
                .clone()
                .unwrap_or_else(|| "cgroup v2 is required but unavailable".to_string()),
        );
    }
    extend_namespace_warnings(config, &namespace_support, &mut warnings);
    extend_readonly_collision_warnings(&filesystem.readonly_inputs, &mut warnings);

    InspectReport {
        operation,
        config_path: config_path.to_path_buf(),
        artifact_dir,
        artifact_dir_source,
        command: resolved_command,
        command_override_applied,
        stdout_path: stdout_path.clone(),
        stderr_path: stderr_path.clone(),
        stdout_within_artifact_dir,
        stderr_within_artifact_dir,
        process_cwd: config.process.cwd.clone(),
        sandbox_cwd: rootfs_cwd(config),
        cgroup,
        filesystem,
        host_support,
        warnings,
    }
}

fn inspect_cgroup(config: &ExecutionConfig, artifact_dir: &Path) -> InspectCgroup {
    if !cgroup_limits_enabled(&config.resource_limits()) {
        return InspectCgroup {
            enabled: false,
            root: None,
            scope_name: None,
            path: None,
            detail: None,
        };
    }

    let scope_name = cgroup_scope_name(artifact_dir);
    match CgroupManager::probe_v2_root() {
        Ok(manager) => {
            let plan = CgroupPlan::new(scope_name.clone(), config.resource_limits());
            InspectCgroup {
                enabled: true,
                root: Some(manager.root().to_path_buf()),
                scope_name: Some(scope_name),
                path: Some(plan.path_under(manager.root())),
                detail: None,
            }
        }
        Err(err) => InspectCgroup {
            enabled: true,
            root: None,
            scope_name: Some(scope_name),
            path: None,
            detail: Some(err.to_string()),
        },
    }
}

fn inspect_filesystem(
    config: &ExecutionConfig,
    artifact_dir: &Path,
    readonly_inputs: Vec<InspectBinding>,
) -> InspectFilesystem {
    let rootfs_enabled = config.filesystem.enable_rootfs;
    let rootfs_dir = rootfs_enabled.then(|| {
        config
            .filesystem
            .rootfs_dir
            .clone()
            .unwrap_or_else(|| artifact_dir.join("rootfs"))
    });
    let host_work_dir = rootfs_enabled.then(|| artifact_dir.join("work"));
    let host_tmp_dir = rootfs_enabled.then(|| artifact_dir.join("tmp"));
    let host_output_dir = rootfs_enabled
        .then(|| {
            config
                .filesystem
                .output_dir
                .as_ref()
                .map(|_| artifact_dir.join("outputs"))
        })
        .flatten();

    InspectFilesystem {
        rootfs_enabled,
        rootfs_dir,
        host_work_dir,
        host_tmp_dir,
        host_output_dir,
        sandbox_work_dir: config.filesystem.work_dir.clone(),
        sandbox_tmp_dir: config.filesystem.tmp_dir.clone(),
        sandbox_output_dir: config.filesystem.output_dir.clone(),
        readonly_inputs,
        executable_bind_paths: config.filesystem.executable_bind_paths.clone(),
        runtime_bind_paths: config.filesystem.runtime_bind_paths.clone(),
    }
}

fn inspect_host_support(
    config: &ExecutionConfig,
    support: &NamespaceSupport,
) -> InspectHostSupport {
    InspectHostSupport {
        user_namespace: inspect_support_flag(
            config.filesystem.enter_user_namespace,
            support.user_namespace,
            support.user_reason.clone(),
        ),
        mount_namespace: inspect_support_flag(
            config.filesystem.enter_mount_namespace,
            support.mount_namespace,
            support.mount_reason.clone(),
        ),
        pid_namespace: inspect_support_flag(
            config.filesystem.enter_pid_namespace,
            support.pid_namespace,
            support.pid_reason.clone(),
        ),
        network_namespace: inspect_support_flag(
            config.filesystem.enter_network_namespace,
            support.network_namespace,
            support.network_reason.clone(),
        ),
        ipc_namespace: inspect_support_flag(
            config.filesystem.enter_ipc_namespace,
            support.ipc_namespace,
            support.ipc_reason.clone(),
        ),
    }
}

fn inspect_support_flag(
    requested: bool,
    available: bool,
    reason: Option<String>,
) -> InspectSupportFlag {
    InspectSupportFlag {
        requested,
        available,
        reason,
    }
}

fn inspect_readonly_inputs(paths: &[PathBuf]) -> Vec<InspectBinding> {
    paths
        .iter()
        .map(|source| InspectBinding {
            source: source.clone(),
            target: readonly_input_target(source),
        })
        .collect()
}

fn readonly_input_target(source: &Path) -> PathBuf {
    let name = source
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("unknown"));
    Path::new("/inputs").join(name)
}

fn extend_namespace_warnings(
    config: &ExecutionConfig,
    support: &NamespaceSupport,
    warnings: &mut Vec<String>,
) {
    maybe_push_namespace_warning(
        warnings,
        "user namespace",
        config.filesystem.enter_user_namespace,
        support.user_namespace,
        support.user_reason.as_deref(),
    );
    maybe_push_namespace_warning(
        warnings,
        "mount namespace",
        config.filesystem.enter_mount_namespace,
        support.mount_namespace,
        support.mount_reason.as_deref(),
    );
    maybe_push_namespace_warning(
        warnings,
        "pid namespace",
        config.filesystem.enter_pid_namespace,
        support.pid_namespace,
        support.pid_reason.as_deref(),
    );
    maybe_push_namespace_warning(
        warnings,
        "network namespace",
        config.filesystem.enter_network_namespace,
        support.network_namespace,
        support.network_reason.as_deref(),
    );
    maybe_push_namespace_warning(
        warnings,
        "ipc namespace",
        config.filesystem.enter_ipc_namespace,
        support.ipc_namespace,
        support.ipc_reason.as_deref(),
    );
}

fn maybe_push_namespace_warning(
    warnings: &mut Vec<String>,
    label: &str,
    requested: bool,
    available: bool,
    reason: Option<&str>,
) {
    if requested && !available {
        let detail = reason.unwrap_or("unknown error");
        warnings.push(format!("{label} is requested but unavailable: {detail}"));
    }
}

fn extend_readonly_collision_warnings(bindings: &[InspectBinding], warnings: &mut Vec<String>) {
    let mut counts = BTreeMap::new();
    for binding in bindings {
        *counts.entry(binding.target.clone()).or_insert(0usize) += 1;
    }

    for (target, count) in counts {
        if count > 1 {
            warnings.push(format!(
                "multiple readonly inputs resolve to the same sandbox path: {}",
                target.display()
            ));
        }
    }
}

fn command_override(command: Vec<String>) -> Option<Vec<String>> {
    if command.is_empty() {
        None
    } else {
        Some(command)
    }
}

fn resolve_cli_output_path(base: &Path, configured: Option<&Path>, default_name: &str) -> PathBuf {
    match configured {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => base.join(path),
        None => base.join(default_name),
    }
}

fn print_pretty_result(result: &ExecutionResult) {
    println!("{}", render_pretty_result(result));
}

fn print_pretty_compilation_result(result: &CompilationResult) {
    println!("{}", render_pretty_compilation_result(result));
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

fn compilation_status_label(status: &CompilationStatus) -> &'static str {
    match status {
        CompilationStatus::Ok => "ok",
        CompilationStatus::CompilationFailed => "compilation_failed",
        CompilationStatus::TimeLimitExceeded => "time_limit_exceeded",
        CompilationStatus::WallTimeLimitExceeded => "wall_time_limit_exceeded",
        CompilationStatus::MemoryLimitExceeded => "memory_limit_exceeded",
        CompilationStatus::OutputLimitExceeded => "output_limit_exceeded",
        CompilationStatus::SandboxError => "sandbox_error",
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

fn compile_outcome_label(status: &CompilationStatus) -> &'static str {
    match status {
        CompilationStatus::Ok => "success",
        CompilationStatus::CompilationFailed => "compile_failure",
        CompilationStatus::TimeLimitExceeded
        | CompilationStatus::WallTimeLimitExceeded
        | CompilationStatus::MemoryLimitExceeded
        | CompilationStatus::OutputLimitExceeded => "sandbox_limit_enforced",
        CompilationStatus::SandboxError => "sandbox_failure",
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

fn compile_summary(result: &CompilationResult) -> String {
    match result.status {
        CompilationStatus::Ok => {
            if result.outputs.is_empty() {
                "compile command completed successfully".to_string()
            } else {
                format!(
                    "compile command produced {} output file(s)",
                    result.outputs.len()
                )
            }
        }
        CompilationStatus::CompilationFailed => {
            if let Some(exit_code) = result.exit_code {
                format!("compiler exited with non-zero status {exit_code}")
            } else if let Some(signal) = result.term_signal {
                format!("compiler terminated by signal {signal}")
            } else {
                "compiler exited with a failure".to_string()
            }
        }
        CompilationStatus::TimeLimitExceeded => {
            "compiler exceeded the configured CPU time limit".to_string()
        }
        CompilationStatus::WallTimeLimitExceeded => {
            "compiler exceeded the configured wall-clock time limit".to_string()
        }
        CompilationStatus::MemoryLimitExceeded => {
            "compiler exceeded the configured memory limit".to_string()
        }
        CompilationStatus::OutputLimitExceeded => {
            "compiler exceeded the configured output limit".to_string()
        }
        CompilationStatus::SandboxError => {
            "sandbox failed after the compiler had already started".to_string()
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

fn compile_suggestion(status: &CompilationStatus) -> Option<&'static str> {
    match status {
        CompilationStatus::Ok => None,
        CompilationStatus::CompilationFailed => Some(
            "Inspect the compiler stdout/stderr artifacts and the source/output directories to debug the build.",
        ),
        CompilationStatus::TimeLimitExceeded
        | CompilationStatus::WallTimeLimitExceeded
        | CompilationStatus::MemoryLimitExceeded
        | CompilationStatus::OutputLimitExceeded => Some(
            "Inspect the artifact logs and adjust the sandbox limits if this compile is expected to succeed.",
        ),
        CompilationStatus::SandboxError => {
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
        format!("exit_code: {}", format_result_exit_code(result)),
        format!(
            "term_signal: {}",
            format_result_term_signal(result.term_signal)
        ),
        format!("wall_time_ms: {}", result.usage.wall_time_ms),
        format!(
            "cpu_time_ms: {}",
            format_result_measurement(result.usage.cpu_time_ms)
        ),
        format!(
            "memory_peak_bytes: {}",
            format_result_measurement(result.usage.memory_peak_bytes)
        ),
        format!("stdout: {}", result.stdout_path.display()),
        format!("stderr: {}", result.stderr_path.display()),
    ];

    if let Some(suggestion) = run_suggestion(&result.status) {
        lines.insert(3, format!("suggestion: {suggestion}"));
    }

    lines.join("\n")
}

fn render_pretty_compilation_result(result: &CompilationResult) -> String {
    let mut lines = vec![
        format!("status: {}", compilation_status_label(&result.status)),
        format!("outcome: {}", compile_outcome_label(&result.status)),
        format!("summary: {}", compile_summary(result)),
        format!("command: {:?}", result.command),
        format!("source_dir: {}", result.source_dir.display()),
        format!("output_dir: {}", result.output_dir.display()),
        format!("outputs: {}", format_output_paths(&result.outputs)),
        format!("exit_code: {}", format_compilation_exit_code(result)),
        format!(
            "term_signal: {}",
            format_result_term_signal(result.term_signal)
        ),
        format!("wall_time_ms: {}", result.usage.wall_time_ms),
        format!(
            "cpu_time_ms: {}",
            format_result_measurement(result.usage.cpu_time_ms)
        ),
        format!(
            "memory_peak_bytes: {}",
            format_result_measurement(result.usage.memory_peak_bytes)
        ),
        format!("stdout: {}", result.stdout_path.display()),
        format!("stderr: {}", result.stderr_path.display()),
    ];

    if let Some(suggestion) = compile_suggestion(&result.status) {
        lines.insert(3, format!("suggestion: {suggestion}"));
    }

    lines.join("\n")
}

fn render_pretty_inspect_report(report: &InspectReport) -> String {
    let mut lines = vec![
        format!("inspect: ok"),
        format!("operation: {}", report.operation),
        format!("config_path: {}", report.config_path.display()),
        format!("artifact_dir: {}", report.artifact_dir.display()),
        format!("artifact_dir_source: {}", report.artifact_dir_source),
        format!("command: {:?}", report.command),
        format!(
            "command_override_applied: {}",
            report.command_override_applied
        ),
        format!("stdout_path: {}", report.stdout_path.display()),
        format!("stderr_path: {}", report.stderr_path.display()),
        format!(
            "stdout_within_artifact_dir: {}",
            report.stdout_within_artifact_dir
        ),
        format!(
            "stderr_within_artifact_dir: {}",
            report.stderr_within_artifact_dir
        ),
        format!(
            "process_cwd: {}",
            report
                .process_cwd
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "sandbox_cwd: {}",
            report
                .sandbox_cwd
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!("cgroup_enabled: {}", report.cgroup.enabled),
        format!(
            "cgroup_root: {}",
            report
                .cgroup
                .root
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "cgroup_scope_name: {}",
            report.cgroup.scope_name.as_deref().unwrap_or("n/a")
        ),
        format!(
            "cgroup_path: {}",
            report
                .cgroup
                .path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "cgroup_detail: {}",
            report.cgroup.detail.as_deref().unwrap_or("n/a")
        ),
        format!("rootfs_enabled: {}", report.filesystem.rootfs_enabled),
        format!(
            "rootfs_dir: {}",
            report
                .filesystem
                .rootfs_dir
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "host_work_dir: {}",
            report
                .filesystem
                .host_work_dir
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "host_tmp_dir: {}",
            report
                .filesystem
                .host_tmp_dir
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "host_output_dir: {}",
            report
                .filesystem
                .host_output_dir
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "sandbox_work_dir: {}",
            report.filesystem.sandbox_work_dir.display()
        ),
        format!(
            "sandbox_tmp_dir: {}",
            report.filesystem.sandbox_tmp_dir.display()
        ),
        format!(
            "sandbox_output_dir: {}",
            report
                .filesystem
                .sandbox_output_dir
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "readonly_inputs: {}",
            format_readonly_inputs(&report.filesystem.readonly_inputs)
        ),
        format!(
            "namespace_user: {}",
            format_support_flag(&report.host_support.user_namespace)
        ),
        format!(
            "namespace_mount: {}",
            format_support_flag(&report.host_support.mount_namespace)
        ),
        format!(
            "namespace_pid: {}",
            format_support_flag(&report.host_support.pid_namespace)
        ),
        format!(
            "namespace_network: {}",
            format_support_flag(&report.host_support.network_namespace)
        ),
        format!(
            "namespace_ipc: {}",
            format_support_flag(&report.host_support.ipc_namespace)
        ),
    ];

    if report.warnings.is_empty() {
        lines.push("warnings: none".to_string());
    } else {
        lines.push(format!("warnings: {}", report.warnings.join(" | ")));
    }

    lines.join("\n")
}

#[cfg(test)]
fn render_pretty_debug_report(report: &DebugReport) -> String {
    let mut sections = vec![render_pretty_inspect_report(&report.inspect)];

    if let Some(result) = &report.result {
        sections.push(render_pretty_result(result));
    }
    if let Some(error) = &report.error {
        sections.push(render_pretty_error_report(error));
    }

    sections.push(format!("debug_exit_code: {}", report.exit_code));
    sections.join("\n\n")
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

fn format_readonly_inputs(bindings: &[InspectBinding]) -> String {
    if bindings.is_empty() {
        return "[]".to_string();
    }

    bindings
        .iter()
        .map(|binding| {
            format!(
                "{} -> {}",
                binding.source.display(),
                binding.target.display()
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_output_paths(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "[]".to_string();
    }

    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_support_flag(flag: &InspectSupportFlag) -> String {
    if flag.available {
        if flag.requested {
            "requested+available".to_string()
        } else {
            "available".to_string()
        }
    } else if flag.requested {
        format!(
            "requested+unavailable ({})",
            flag.reason.as_deref().unwrap_or("unknown error")
        )
    } else {
        format!(
            "unavailable ({})",
            flag.reason.as_deref().unwrap_or("unknown error")
        )
    }
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

fn format_result_exit_code(result: &ExecutionResult) -> String {
    match (result.exit_code, result.term_signal) {
        (Some(code), _) => code.to_string(),
        (None, Some(_)) => "none (terminated by signal)".to_string(),
        (None, None) => "none".to_string(),
    }
}

fn format_compilation_exit_code(result: &CompilationResult) -> String {
    match (result.exit_code, result.term_signal) {
        (Some(code), _) => code.to_string(),
        (None, Some(_)) => "none (terminated by signal)".to_string(),
        (None, None) => "none".to_string(),
    }
}

fn format_result_term_signal(value: Option<i32>) -> String {
    value
        .map(|current| current.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn format_result_measurement(value: Option<u64>) -> String {
    value
        .map(|current| current.to_string())
        .unwrap_or_else(|| "not collected".to_string())
}

fn format_optional_u64(value: Option<u64>) -> String {
    value
        .map(|current| current.to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

#[cfg(test)]
fn format_optional_i32(value: Option<i32>) -> String {
    value
        .map(|current| current.to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        CliErrorCategory, DebugReport, ProtocolServerFileConfig, ResultFormat, ServeArgs,
        build_error_report, build_inspect_report, cgroup_limits_enabled, compilation_status_label,
        compile_outcome_label, format_optional_i32, format_optional_u64, format_result_measurement,
        format_result_term_signal, load_server_file_config, print_validate_summary,
        render_pretty_compilation_result, render_pretty_debug_report, render_pretty_error_report,
        render_pretty_inspect_report, render_pretty_result, resolve_server_options,
        run_outcome_label, status_label,
    };
    use sandbox_config::ExecutionConfig;
    use sandbox_core::{
        CompilationResult, CompilationStatus, ExecutionResult, ExecutionStatus, ResourceLimits,
        ResourceUsage, SandboxError,
    };

    #[test]
    fn formats_missing_numeric_fields_as_na() {
        assert_eq!(format_optional_u64(None), "n/a");
        assert_eq!(format_optional_i32(None), "n/a");
        assert_eq!(format_result_term_signal(None), "none");
        assert_eq!(format_result_measurement(None), "not collected");
    }

    #[test]
    fn exposes_human_readable_status_labels() {
        assert_eq!(status_label(&ExecutionStatus::Ok), "ok");
        assert_eq!(
            compilation_status_label(&CompilationStatus::CompilationFailed),
            "compilation_failed"
        );
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
        assert_eq!(
            compile_outcome_label(&CompilationStatus::CompilationFailed),
            "compile_failure"
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
        assert!(rendered.contains("term_signal: none"));
        assert!(rendered.contains("cpu_time_ms: not collected"));
    }

    #[test]
    fn pretty_compilation_result_highlights_compile_failures() {
        let rendered = render_pretty_compilation_result(&CompilationResult {
            command: vec![
                "/usr/bin/cc".to_string(),
                "main.c".to_string(),
                "-o".to_string(),
                "build/main".to_string(),
            ],
            source_dir: PathBuf::from("/workspace/src"),
            output_dir: PathBuf::from("/workspace/build"),
            outputs: vec![PathBuf::from("/workspace/build/main")],
            exit_code: Some(1),
            term_signal: None,
            usage: ResourceUsage {
                cpu_time_ms: None,
                wall_time_ms: 23,
                memory_peak_bytes: None,
            },
            stdout_path: PathBuf::from("/tmp/compile.stdout"),
            stderr_path: PathBuf::from("/tmp/compile.stderr"),
            status: CompilationStatus::CompilationFailed,
        });

        assert!(rendered.contains("status: compilation_failed"));
        assert!(rendered.contains("outcome: compile_failure"));
        assert!(rendered.contains("summary: compiler exited with non-zero status 1"));
        assert!(rendered.contains("outputs: /workspace/build/main"));
        assert!(rendered.contains("suggestion: Inspect the compiler stdout/stderr artifacts"));
    }

    #[test]
    fn inspect_report_flags_duplicate_readonly_targets() {
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [limits]
                wall_time_ms = 1000
                memory_bytes = 4096

                [filesystem]
                readonly_bind_paths = ["/tmp/a/input.txt", "/tmp/b/input.txt"]
            "#,
        )
        .expect("config should parse");

        let report = build_inspect_report(
            "inspect",
            Path::new("configs/test.toml"),
            &config,
            Some(PathBuf::from("/tmp/inspect-artifacts")),
            Vec::new(),
        );

        assert_eq!(report.filesystem.readonly_inputs.len(), 2);
        assert!(
            report
                .filesystem
                .readonly_inputs
                .iter()
                .all(|binding| { binding.target == PathBuf::from("/inputs/input.txt") })
        );
        assert!(report.warnings.iter().any(|warning| {
            warning.contains("multiple readonly inputs resolve to the same sandbox path")
        }));
    }

    #[test]
    fn pretty_inspect_report_includes_derived_paths() {
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [limits]
                wall_time_ms = 1000
                memory_bytes = 4096

                [filesystem]
                output_dir = "/output"
            "#,
        )
        .expect("config should parse");

        let report = build_inspect_report(
            "inspect",
            Path::new("configs/test.toml"),
            &config,
            Some(PathBuf::from("/tmp/inspect-artifacts")),
            vec!["/bin/echo".to_string(), "override".to_string()],
        );
        let rendered = render_pretty_inspect_report(&report);

        assert!(rendered.contains("artifact_dir: /tmp/inspect-artifacts"));
        assert!(rendered.contains("stdout_path: /tmp/inspect-artifacts/stdout.log"));
        assert!(rendered.contains("host_output_dir: /tmp/inspect-artifacts/outputs"));
        assert!(rendered.contains("command_override_applied: true"));
    }

    #[test]
    fn pretty_debug_report_includes_error_section() {
        let config = ExecutionConfig::from_toml_str(
            r#"
                [process]
                argv = ["/bin/echo", "hello"]

                [limits]
                wall_time_ms = 1000
            "#,
        )
        .expect("config should parse");
        let inspect = build_inspect_report(
            "debug",
            Path::new("configs/test.toml"),
            &config,
            Some(PathBuf::from("/tmp/debug-artifacts")),
            Vec::new(),
        );
        let error = build_error_report(
            "debug",
            &anyhow::Error::new(SandboxError::Spawn("missing binary".into())),
            ResultFormat::Pretty,
        );

        let rendered = render_pretty_debug_report(&DebugReport {
            inspect,
            result: None,
            error: Some(error),
            exit_code: 4,
        });

        assert!(rendered.contains("inspect: ok"));
        assert!(rendered.contains("error: Sandbox payload could not be started"));
        assert!(rendered.contains("debug_exit_code: 4"));
    }

    fn unique_temp_path(prefix: &str, suffix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("sandbox-cli-{prefix}-{stamp}{suffix}"))
    }

    #[test]
    fn loads_server_file_config_from_toml() {
        let path = unique_temp_path("server-config", ".toml");
        fs::write(
            &path,
            r#"
auth_token_env = "SANDBOX_PROTOCOL_AUTH_TOKEN_TEST"
max_request_body_bytes = 2048
max_concurrent_requests = 7
"#,
        )
        .expect("server config should be written");

        let config = load_server_file_config(&path).expect("server config should load");
        assert_eq!(
            config.auth_token_env.as_deref(),
            Some("SANDBOX_PROTOCOL_AUTH_TOKEN_TEST")
        );
        assert_eq!(config.max_request_body_bytes, Some(2048));
        assert_eq!(config.max_concurrent_requests, Some(7));
    }

    #[test]
    fn resolve_server_options_prefers_cli_over_file_values() {
        let args = ServeArgs {
            listen: "127.0.0.1:3000".parse().unwrap(),
            server_config: Some(PathBuf::from("configs/protocol-server.toml")),
            auth_token: Some("cli-token".to_string()),
            read_auth_token: None,
            write_auth_token: None,
            max_request_body_bytes: Some(4096),
            max_concurrent_requests: Some(9),
        };
        let file_config = ProtocolServerFileConfig {
            auth_token: Some("file-token".to_string()),
            auth_token_env: Some("IGNORED_ENV".to_string()),
            auth_token_file: None,
            read_auth_token: None,
            read_auth_token_env: None,
            read_auth_token_file: None,
            write_auth_token: None,
            write_auth_token_env: None,
            write_auth_token_file: None,
            max_request_body_bytes: Some(2048),
            max_concurrent_requests: Some(5),
        };

        let options = resolve_server_options(&args, &file_config).expect("options should resolve");
        assert_eq!(options.auth_token.as_deref(), Some("cli-token"));
        assert_eq!(options.max_request_body_bytes, 4096);
        assert_eq!(options.max_concurrent_requests, 9);
    }

    #[test]
    fn resolve_server_options_reads_token_file_when_requested() {
        let token_path = unique_temp_path("server-token", ".txt");
        fs::write(&token_path, "file-token\n").expect("token file should be written");

        let args = ServeArgs {
            listen: "127.0.0.1:3000".parse().unwrap(),
            server_config: None,
            auth_token: None,
            read_auth_token: None,
            write_auth_token: None,
            max_request_body_bytes: None,
            max_concurrent_requests: None,
        };
        let file_config = ProtocolServerFileConfig {
            auth_token: None,
            auth_token_env: None,
            auth_token_file: Some(token_path),
            read_auth_token: None,
            read_auth_token_env: None,
            read_auth_token_file: None,
            write_auth_token: None,
            write_auth_token_env: None,
            write_auth_token_file: None,
            max_request_body_bytes: None,
            max_concurrent_requests: None,
        };

        let options = resolve_server_options(&args, &file_config).expect("options should resolve");
        assert_eq!(options.auth_token.as_deref(), Some("file-token"));
        assert_eq!(options.max_request_body_bytes, 1024 * 1024);
        assert_eq!(options.max_concurrent_requests, 32);
    }
}
