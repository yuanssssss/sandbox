use std::collections::{HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::Path as AxumPath;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use sandbox_config::ExecutionConfig;
use sandbox_core::{
    CompilationResult, CompilationStatus, ExecutionResult, ExecutionStatus, ResourceLimits,
    SandboxError,
};
use sandbox_supervisor::{
    CompileOptions, NamespaceSupport, RunOptions, compile, planned_artifact_dir,
    probe_namespace_support, run,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;

pub type BackendFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub trait ProtocolBackend: Send + Sync + 'static {
    fn health(&self) -> BackendFuture<HealthStatus>;
    fn capabilities(&self) -> BackendFuture<CapabilitiesResponse>;
    fn validate_config(
        &self,
        request: ValidateConfigRequest,
    ) -> BackendFuture<Result<ValidateConfigResponse, ProtocolError>>;
    fn compile(
        &self,
        request: CompilationRequest,
    ) -> BackendFuture<Result<CompilationReport, ProtocolError>> {
        Box::pin(async move {
            Err(ProtocolError::new(
                StatusCode::NOT_IMPLEMENTED,
                "compile_not_implemented",
                "compilation is not implemented by this backend",
                Some(request.request_id),
            ))
        })
    }
    fn execute(
        &self,
        request: ExecutionRequest,
    ) -> BackendFuture<Result<ExecutionReport, ProtocolError>>;
    fn execute_judge_job(
        &self,
        request: JudgeJobRequest,
    ) -> BackendFuture<Result<JudgeJobReport, ProtocolError>> {
        Box::pin(async move {
            Err(ProtocolError::new(
                StatusCode::NOT_IMPLEMENTED,
                "judge_job_not_implemented",
                "judge job execution is not implemented by this backend",
                Some(request.request_id),
            ))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub request_id: String,
    pub config: ExecutionConfig,
    #[serde(default)]
    pub command_override: Option<Vec<String>>,
    #[serde(default)]
    pub artifact_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub stage: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub request: ExecutionRequest,
    pub result: ExecutionResult,
    pub audit_events: Vec<AuditEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationRequest {
    pub request_id: String,
    pub config: ExecutionConfig,
    #[serde(default)]
    pub command_override: Option<Vec<String>>,
    #[serde(default)]
    pub artifact_dir: Option<PathBuf>,
    #[serde(default)]
    pub source_dir: Option<PathBuf>,
    #[serde(default)]
    pub output_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationReport {
    pub request: CompilationRequest,
    pub result: CompilationResult,
    pub audit_events: Vec<AuditEvent>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum JudgeStageName {
    Compile,
    Run,
    Checker,
}

impl JudgeStageName {
    fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Run => "run",
            Self::Checker => "checker",
        }
    }

    fn order(self) -> u8 {
        match self {
            Self::Compile => 0,
            Self::Run => 1,
            Self::Checker => 2,
        }
    }

    fn precedes(self, other: Self) -> bool {
        self.order() < other.order()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JudgeArtifactKind {
    Stdout,
    Stderr,
    OutputDirectory,
    File,
    Directory,
    Log,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JudgeArtifactRef {
    pub stage: JudgeStageName,
    pub artifact_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct JudgeStageInputs {
    #[serde(default)]
    pub stdin: Option<JudgeArtifactRef>,
    #[serde(default)]
    pub readonly_artifacts: Vec<JudgeArtifactRef>,
}

impl JudgeStageInputs {
    fn is_empty(&self) -> bool {
        self.stdin.is_none() && self.readonly_artifacts.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeStageRequest {
    pub config: ExecutionConfig,
    #[serde(default)]
    pub command_override: Option<Vec<String>>,
    #[serde(default)]
    pub artifact_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "JudgeStageInputs::is_empty")]
    pub inputs: JudgeStageInputs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeJobRequest {
    pub request_id: String,
    #[serde(default)]
    pub artifact_dir: Option<PathBuf>,
    #[serde(default)]
    pub compile: Option<JudgeStageRequest>,
    pub run: JudgeStageRequest,
    #[serde(default)]
    pub checker: Option<JudgeStageRequest>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JudgeStageStatus {
    Pending,
    Completed,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JudgeJobStatus {
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JudgeStageArtifact {
    pub name: String,
    pub kind: JudgeArtifactKind,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeStageReport {
    pub stage: JudgeStageName,
    pub request: JudgeStageRequest,
    pub status: JudgeStageStatus,
    #[serde(default)]
    pub artifact_dir: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ExecutionResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compilation_result: Option<CompilationResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<JudgeStageArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_events: Vec<AuditEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeJobReport {
    pub request: JudgeJobRequest,
    pub status: JudgeJobStatus,
    #[serde(default)]
    pub compile: Option<JudgeStageReport>,
    pub run: JudgeStageReport,
    #[serde(default)]
    pub checker: Option<JudgeStageReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_events: Vec<AuditEvent>,
}

impl JudgeJobRequest {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.request_id.trim().is_empty() {
            return Err(invalid_judge_job_request(
                &self.request_id,
                "request_id must not be empty",
            ));
        }

        if let Some(request) = self.compile.as_ref() {
            self.validate_stage_request(JudgeStageName::Compile, request)?;
        }
        self.validate_stage_request(JudgeStageName::Run, &self.run)?;
        if let Some(request) = self.checker.as_ref() {
            self.validate_stage_request(JudgeStageName::Checker, request)?;
        }

        Ok(())
    }

    fn stage_request(&self, stage: JudgeStageName) -> Option<&JudgeStageRequest> {
        match stage {
            JudgeStageName::Compile => self.compile.as_ref(),
            JudgeStageName::Run => Some(&self.run),
            JudgeStageName::Checker => self.checker.as_ref(),
        }
    }

    fn stage_defined(&self, stage: JudgeStageName) -> bool {
        self.stage_request(stage).is_some()
    }

    fn stage_artifact_dir(&self, stage: JudgeStageName) -> Option<PathBuf> {
        self.stage_request(stage)
            .and_then(|request| request.artifact_dir.clone())
            .or_else(|| {
                self.artifact_dir
                    .as_ref()
                    .map(|root| root.join(stage.as_str()))
            })
    }

    fn resolved_stage_artifact_dir(&self, stage: JudgeStageName) -> PathBuf {
        self.stage_artifact_dir(stage).unwrap_or_else(|| {
            let stage_request = self
                .stage_request(stage)
                .expect("resolved_stage_artifact_dir requires a defined stage");
            planned_artifact_dir(
                &stage_request.config,
                &RunOptions {
                    argv_override: stage_request.command_override.clone(),
                    artifact_dir: None,
                    cgroup_root_override: None,
                },
            )
        })
    }

    fn validate_stage_request(
        &self,
        stage: JudgeStageName,
        request: &JudgeStageRequest,
    ) -> Result<(), ProtocolError> {
        request.config.validate().map_err(|err| {
            let mut mapped = ProtocolError::from(err);
            mapped.request_id = Some(self.request_id.clone());
            mapped.message = format!("judge stage `{}`: {}", stage.as_str(), mapped.message);
            mapped
        })?;

        if let Some(command) = request.command_override.as_ref() {
            if command.is_empty() {
                return Err(invalid_judge_job_request(
                    &self.request_id,
                    format!(
                        "judge stage `{}` command_override must not be empty",
                        stage.as_str()
                    ),
                ));
            }
        }

        self.validate_stage_inputs(stage, &request.inputs)
    }

    fn validate_stage_inputs(
        &self,
        stage: JudgeStageName,
        inputs: &JudgeStageInputs,
    ) -> Result<(), ProtocolError> {
        if let Some(stdin) = inputs.stdin.as_ref() {
            self.validate_artifact_ref(stage, stdin)?;
        }
        for artifact in &inputs.readonly_artifacts {
            self.validate_artifact_ref(stage, artifact)?;
        }
        Ok(())
    }

    fn validate_artifact_ref(
        &self,
        current_stage: JudgeStageName,
        reference: &JudgeArtifactRef,
    ) -> Result<(), ProtocolError> {
        if !reference.stage.precedes(current_stage) {
            return Err(invalid_judge_job_request(
                &self.request_id,
                format!(
                    "judge stage `{}` can only reference artifacts from earlier stages",
                    current_stage.as_str()
                ),
            ));
        }

        if !self.stage_defined(reference.stage) {
            return Err(invalid_judge_job_request(
                &self.request_id,
                format!(
                    "judge stage `{}` references missing `{}` artifacts",
                    current_stage.as_str(),
                    reference.stage.as_str()
                ),
            ));
        }

        validate_relative_artifact_path(&self.request_id, current_stage, &reference.artifact_path)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTaskStatus {
    Accepted,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTaskAccepted {
    pub task_id: String,
    pub request_id: String,
    pub status: ExecutionTaskStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTaskResponse {
    pub task_id: String,
    pub request_id: String,
    pub status: ExecutionTaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<ExecutionReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub service: String,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            status: "ok".to_string(),
            service: "sandbox-protocol".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityStatus {
    pub available: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitiesResponse {
    pub user_namespace: CapabilityStatus,
    pub mount_namespace: CapabilityStatus,
    pub pid_namespace: CapabilityStatus,
    pub network_namespace: CapabilityStatus,
    pub ipc_namespace: CapabilityStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateConfigRequest {
    pub config: ExecutionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateConfigResponse {
    pub valid: bool,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProtocolError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub request_id: Option<String>,
}

impl ProtocolError {
    pub fn new(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        request_id: Option<String>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            request_id,
        }
    }
}

impl From<SandboxError> for ProtocolError {
    fn from(value: SandboxError) -> Self {
        match value {
            SandboxError::Config(message) => {
                Self::new(StatusCode::BAD_REQUEST, "configuration", message, None)
            }
            SandboxError::CapabilityUnavailable { capability, detail } => Self::new(
                StatusCode::CONFLICT,
                "capability_unavailable",
                format!("required sandbox capability `{capability}` is unavailable: {detail}"),
                None,
            ),
            SandboxError::Permission(message) => {
                Self::new(StatusCode::FORBIDDEN, "permission_isolation", message, None)
            }
            SandboxError::Io { context, source } => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "io",
                format!("I/O error while {context}: {source}"),
                None,
            ),
            SandboxError::Spawn(message) => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "spawn", message, None)
            }
            SandboxError::Timeout { wall_time_ms } => Self::new(
                StatusCode::REQUEST_TIMEOUT,
                "timeout",
                format!("sandbox timeout after {wall_time_ms}ms"),
                None,
            ),
            SandboxError::Cleanup(message) => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "cleanup", message, None)
            }
            SandboxError::UnsupportedPlatform(message) => Self::new(
                StatusCode::NOT_IMPLEMENTED,
                "unsupported_platform",
                message,
                None,
            ),
            SandboxError::Internal(message) => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message, None)
            }
        }
    }
}

impl IntoResponse for ProtocolError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            error: ErrorDetail {
                code: self.code.to_string(),
                message: self.message,
                request_id: self.request_id,
            },
        });
        (self.status, body).into_response()
    }
}

fn json_rejection_to_protocol_error(rejection: JsonRejection) -> ProtocolError {
    match rejection {
        JsonRejection::MissingJsonContentType(_) => ProtocolError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_content_type",
            "request content type must be application/json",
            None,
        ),
        JsonRejection::JsonSyntaxError(_) => ProtocolError::new(
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "request body contains invalid JSON",
            None,
        ),
        JsonRejection::JsonDataError(_) => ProtocolError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request body does not match the protocol schema",
            None,
        ),
        JsonRejection::BytesRejection(_) => ProtocolError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_body",
            "request body could not be read",
            None,
        ),
        _ => ProtocolError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request body could not be decoded",
            None,
        ),
    }
}

fn not_found_error() -> ProtocolError {
    ProtocolError::new(StatusCode::NOT_FOUND, "not_found", "route not found", None)
}

fn invalid_judge_job_request(request_id: &str, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        message,
        Some(request_id.to_string()),
    )
}

fn validate_relative_artifact_path(
    request_id: &str,
    stage: JudgeStageName,
    artifact_path: &Path,
) -> Result<(), ProtocolError> {
    if artifact_path.as_os_str().is_empty() {
        return Err(invalid_judge_job_request(
            request_id,
            format!(
                "judge stage `{}` artifact_path must not be empty",
                stage.as_str()
            ),
        ));
    }

    if artifact_path.is_absolute()
        || artifact_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(invalid_judge_job_request(
            request_id,
            format!(
                "judge stage `{}` artifact_path must stay within the referenced stage artifact root",
                stage.as_str()
            ),
        ));
    }

    Ok(())
}

fn method_not_allowed_error() -> ProtocolError {
    ProtocolError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "method not allowed for this route",
        None,
    )
}

fn task_not_found_error(task_id: &str) -> ProtocolError {
    ProtocolError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        format!("execution task `{task_id}` was not found"),
        None,
    )
}

fn build_judge_stage_artifacts(
    artifact_dir: Option<&Path>,
    stage_request: &JudgeStageRequest,
    result: &ExecutionResult,
) -> Vec<JudgeStageArtifact> {
    let mut artifacts = vec![
        JudgeStageArtifact {
            name: "stdout".to_string(),
            kind: JudgeArtifactKind::Stdout,
            path: result.stdout_path.clone(),
        },
        JudgeStageArtifact {
            name: "stderr".to_string(),
            kind: JudgeArtifactKind::Stderr,
            path: result.stderr_path.clone(),
        },
    ];

    if let (Some(artifact_dir), Some(_)) = (
        artifact_dir,
        stage_request.config.filesystem.output_dir.as_ref(),
    ) {
        artifacts.push(JudgeStageArtifact {
            name: "outputs".to_string(),
            kind: JudgeArtifactKind::OutputDirectory,
            path: artifact_dir.join("outputs"),
        });
    }

    artifacts
}

#[derive(Debug, Clone, Default)]
struct MaterializedStageInputs {
    stdin_path: Option<PathBuf>,
    readonly_bind_paths: Vec<PathBuf>,
}

fn stage_status_from_execution_status(status: &ExecutionStatus) -> JudgeStageStatus {
    match status {
        ExecutionStatus::Ok => JudgeStageStatus::Completed,
        ExecutionStatus::TimeLimitExceeded
        | ExecutionStatus::WallTimeLimitExceeded
        | ExecutionStatus::MemoryLimitExceeded
        | ExecutionStatus::OutputLimitExceeded
        | ExecutionStatus::RuntimeError
        | ExecutionStatus::SandboxError => JudgeStageStatus::Failed,
    }
}

fn stage_status_from_compilation_status(status: &CompilationStatus) -> JudgeStageStatus {
    match status {
        CompilationStatus::Ok => JudgeStageStatus::Completed,
        CompilationStatus::CompilationFailed
        | CompilationStatus::TimeLimitExceeded
        | CompilationStatus::WallTimeLimitExceeded
        | CompilationStatus::MemoryLimitExceeded
        | CompilationStatus::OutputLimitExceeded
        | CompilationStatus::SandboxError => JudgeStageStatus::Failed,
    }
}

fn judge_job_status_from_stage_reports(
    compile: Option<&JudgeStageReport>,
    run: &JudgeStageReport,
    checker: Option<&JudgeStageReport>,
) -> JudgeJobStatus {
    let compile_ok = compile
        .map(|report| report.status == JudgeStageStatus::Completed)
        .unwrap_or(true);
    let run_ok = run.status == JudgeStageStatus::Completed;
    let checker_ok = checker
        .map(|report| report.status == JudgeStageStatus::Completed)
        .unwrap_or(true);

    if compile_ok && run_ok && checker_ok {
        JudgeJobStatus::Completed
    } else {
        JudgeJobStatus::Failed
    }
}

fn stage_event(stage: JudgeStageName, suffix: &str, message: impl Into<String>) -> AuditEvent {
    AuditEvent {
        stage: format!("{}_{}", stage.as_str(), suffix),
        message: message.into(),
    }
}

fn resolved_execution_request(
    request_id: &str,
    stage_request: &JudgeStageRequest,
    artifact_dir: PathBuf,
    inputs: &MaterializedStageInputs,
) -> ExecutionRequest {
    let mut config = stage_request.config.clone();
    if let Some(stdin_path) = inputs.stdin_path.as_ref() {
        config.io.stdin_path = Some(stdin_path.clone());
    }
    if !inputs.readonly_bind_paths.is_empty() {
        config
            .filesystem
            .readonly_bind_paths
            .extend(inputs.readonly_bind_paths.iter().cloned());
    }

    ExecutionRequest {
        request_id: request_id.to_string(),
        config,
        command_override: stage_request.command_override.clone(),
        artifact_dir: Some(artifact_dir),
    }
}

fn resolved_compilation_request(
    request_id: &str,
    stage_request: &JudgeStageRequest,
    artifact_dir: PathBuf,
) -> CompilationRequest {
    let output_dir = if stage_request.config.filesystem.enable_rootfs {
        None
    } else {
        Some(artifact_dir.join("outputs"))
    };

    CompilationRequest {
        request_id: request_id.to_string(),
        config: stage_request.config.clone(),
        command_override: stage_request.command_override.clone(),
        artifact_dir: Some(artifact_dir),
        source_dir: None,
        output_dir,
    }
}

fn resolve_stage_artifact_source(
    request_id: &str,
    current_stage: JudgeStageName,
    reference: &JudgeArtifactRef,
    previous_stage_artifacts: &HashMap<JudgeStageName, PathBuf>,
) -> Result<PathBuf, ProtocolError> {
    let artifact_dir = previous_stage_artifacts
        .get(&reference.stage)
        .ok_or_else(|| {
            ProtocolError::new(
                StatusCode::CONFLICT,
                "missing_artifact",
                format!(
                    "judge stage `{}` cannot resolve artifacts for missing `{}` stage output",
                    current_stage.as_str(),
                    reference.stage.as_str()
                ),
                Some(request_id.to_string()),
            )
        })?;
    let source = artifact_dir.join(&reference.artifact_path);
    if !source.exists() {
        return Err(ProtocolError::new(
            StatusCode::CONFLICT,
            "missing_artifact",
            format!(
                "judge stage `{}` could not find referenced artifact `{}` from stage `{}`",
                current_stage.as_str(),
                reference.artifact_path.display(),
                reference.stage.as_str()
            ),
            Some(request_id.to_string()),
        ));
    }

    Ok(source)
}

fn copy_artifact_path(source: &Path, destination: &Path) -> Result<(), ProtocolError> {
    if source.is_dir() {
        fs::create_dir_all(destination).map_err(|err| {
            ProtocolError::from(SandboxError::io(
                "creating staged judge input directory",
                err,
            ))
        })?;
        for entry in fs::read_dir(source).map_err(|err| {
            ProtocolError::from(SandboxError::io("reading judge input directory", err))
        })? {
            let entry = entry.map_err(|err| {
                ProtocolError::from(SandboxError::io("reading judge input directory entry", err))
            })?;
            copy_artifact_path(&entry.path(), &destination.join(entry.file_name()))?;
        }
        return Ok(());
    }

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            ProtocolError::from(SandboxError::io("creating staged judge input parent", err))
        })?;
    }
    fs::copy(source, destination)
        .map_err(|err| ProtocolError::from(SandboxError::io("copying staged judge input", err)))?;
    Ok(())
}

fn materialize_stage_inputs(
    request_id: &str,
    current_stage: JudgeStageName,
    current_artifact_dir: &Path,
    inputs: &JudgeStageInputs,
    previous_stage_artifacts: &HashMap<JudgeStageName, PathBuf>,
) -> Result<MaterializedStageInputs, ProtocolError> {
    if inputs.stdin.is_none() && inputs.readonly_artifacts.is_empty() {
        return Ok(MaterializedStageInputs::default());
    }

    let staged_inputs_root = current_artifact_dir.join("stage-inputs");
    if staged_inputs_root.exists() {
        fs::remove_dir_all(&staged_inputs_root).map_err(|err| {
            ProtocolError::from(SandboxError::io("removing stale staged judge inputs", err))
        })?;
    }

    let mut stdin_path = None;
    let mut readonly_bind_paths = Vec::new();
    let mut readonly_roots_seen = HashSet::new();

    if let Some(reference) = inputs.stdin.as_ref() {
        let source = resolve_stage_artifact_source(
            request_id,
            current_stage,
            reference,
            previous_stage_artifacts,
        )?;
        let destination = staged_inputs_root
            .join(reference.stage.as_str())
            .join(&reference.artifact_path);
        copy_artifact_path(&source, &destination)?;
        stdin_path = Some(destination);
    }

    for reference in &inputs.readonly_artifacts {
        let source = resolve_stage_artifact_source(
            request_id,
            current_stage,
            reference,
            previous_stage_artifacts,
        )?;
        let root = staged_inputs_root.join(reference.stage.as_str());
        let destination = root.join(&reference.artifact_path);
        copy_artifact_path(&source, &destination)?;
        if readonly_roots_seen.insert(root.clone()) {
            readonly_bind_paths.push(root);
        }
    }

    Ok(MaterializedStageInputs {
        stdin_path,
        readonly_bind_paths,
    })
}

fn build_compilation_stage_artifacts(result: &CompilationResult) -> Vec<JudgeStageArtifact> {
    let mut artifacts = vec![
        JudgeStageArtifact {
            name: "stdout".to_string(),
            kind: JudgeArtifactKind::Stdout,
            path: result.stdout_path.clone(),
        },
        JudgeStageArtifact {
            name: "stderr".to_string(),
            kind: JudgeArtifactKind::Stderr,
            path: result.stderr_path.clone(),
        },
        JudgeStageArtifact {
            name: "outputs".to_string(),
            kind: JudgeArtifactKind::OutputDirectory,
            path: result.output_dir.clone(),
        },
    ];

    for output in &result.outputs {
        let name = output
            .strip_prefix(&result.output_dir)
            .ok()
            .map(|path| path.display().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| output.display().to_string());
        artifacts.push(JudgeStageArtifact {
            name,
            kind: JudgeArtifactKind::File,
            path: output.clone(),
        });
    }

    artifacts
}

fn failed_stage_report(
    stage: JudgeStageName,
    request: JudgeStageRequest,
    artifact_dir: PathBuf,
    error: ProtocolError,
) -> JudgeStageReport {
    JudgeStageReport {
        stage,
        request,
        status: JudgeStageStatus::Failed,
        artifact_dir: Some(artifact_dir),
        result: None,
        compilation_result: None,
        artifacts: Vec::new(),
        audit_events: vec![stage_event(
            stage,
            "failed",
            format!("stage failed before completion: {}", error.message),
        )],
        error: Some(error_detail_from_protocol_error(error, None)),
    }
}

fn skipped_stage_report(
    stage: JudgeStageName,
    request: JudgeStageRequest,
    artifact_dir: PathBuf,
    reason: impl Into<String>,
) -> JudgeStageReport {
    let reason = reason.into();
    JudgeStageReport {
        stage,
        request,
        status: JudgeStageStatus::Skipped,
        artifact_dir: Some(artifact_dir),
        result: None,
        compilation_result: None,
        artifacts: Vec::new(),
        audit_events: vec![stage_event(stage, "skipped", reason.clone())],
        error: Some(ErrorDetail {
            code: "stage_skipped".to_string(),
            message: reason,
            request_id: None,
        }),
    }
}

async fn execute_compile_stage<B: ProtocolBackend>(
    backend: &B,
    request_id: &str,
    stage_request: JudgeStageRequest,
    artifact_dir: PathBuf,
) -> JudgeStageReport {
    let compile_request =
        resolved_compilation_request(request_id, &stage_request, artifact_dir.clone());

    match backend.compile(compile_request).await {
        Ok(report) => {
            let stage_artifact_dir = report.request.artifact_dir.clone().or(Some(artifact_dir));
            JudgeStageReport {
                stage: JudgeStageName::Compile,
                request: stage_request,
                status: stage_status_from_compilation_status(&report.result.status),
                artifact_dir: stage_artifact_dir,
                result: None,
                compilation_result: Some(report.result.clone()),
                artifacts: build_compilation_stage_artifacts(&report.result),
                audit_events: report.audit_events,
                error: None,
            }
        }
        Err(error) => {
            failed_stage_report(JudgeStageName::Compile, stage_request, artifact_dir, error)
        }
    }
}

async fn execute_execution_stage<B: ProtocolBackend>(
    backend: &B,
    request_id: &str,
    stage: JudgeStageName,
    stage_request: JudgeStageRequest,
    artifact_dir: PathBuf,
    previous_stage_artifacts: &HashMap<JudgeStageName, PathBuf>,
) -> JudgeStageReport {
    let materialized_inputs = match materialize_stage_inputs(
        request_id,
        stage,
        &artifact_dir,
        &stage_request.inputs,
        previous_stage_artifacts,
    ) {
        Ok(value) => value,
        Err(error) => return failed_stage_report(stage, stage_request, artifact_dir, error),
    };
    let execution_request = resolved_execution_request(
        request_id,
        &stage_request,
        artifact_dir.clone(),
        &materialized_inputs,
    );

    match backend.execute(execution_request).await {
        Ok(report) => {
            let stage_artifact_dir = report.request.artifact_dir.clone().or(Some(artifact_dir));
            let artifacts = build_judge_stage_artifacts(
                stage_artifact_dir.as_deref(),
                &stage_request,
                &report.result,
            );
            JudgeStageReport {
                stage,
                request: stage_request,
                status: stage_status_from_execution_status(&report.result.status),
                artifact_dir: stage_artifact_dir,
                result: Some(report.result.clone()),
                compilation_result: None,
                artifacts,
                audit_events: report.audit_events,
                error: None,
            }
        }
        Err(error) => failed_stage_report(stage, stage_request, artifact_dir, error),
    }
}

async fn execute_judge_job_with_backend<B: ProtocolBackend>(
    backend: &B,
    request: JudgeJobRequest,
) -> Result<JudgeJobReport, ProtocolError> {
    request.validate()?;

    let mut audit_events = vec![AuditEvent {
        stage: "accepted".to_string(),
        message: "judge job accepted".to_string(),
    }];
    let mut previous_stage_artifacts = HashMap::new();

    let compile_report = if let Some(compile_request) = request.compile.clone() {
        let compile_artifact_dir = request.resolved_stage_artifact_dir(JudgeStageName::Compile);
        audit_events.push(stage_event(
            JudgeStageName::Compile,
            "started",
            "compile stage started",
        ));
        let report = execute_compile_stage(
            backend,
            &request.request_id,
            compile_request,
            compile_artifact_dir,
        )
        .await;
        if report.status == JudgeStageStatus::Completed {
            if let Some(artifact_dir) = report.artifact_dir.clone() {
                previous_stage_artifacts.insert(JudgeStageName::Compile, artifact_dir);
            }
            audit_events.push(stage_event(
                JudgeStageName::Compile,
                "completed",
                "compile stage completed",
            ));
        } else {
            audit_events.push(stage_event(
                JudgeStageName::Compile,
                "failed",
                "compile stage failed",
            ));
        }
        Some(report)
    } else {
        None
    };

    let run_report = if compile_report
        .as_ref()
        .is_some_and(|report| report.status != JudgeStageStatus::Completed)
    {
        let report = skipped_stage_report(
            JudgeStageName::Run,
            request.run.clone(),
            request.resolved_stage_artifact_dir(JudgeStageName::Run),
            "run stage skipped because compile stage did not complete successfully",
        );
        audit_events.push(stage_event(
            JudgeStageName::Run,
            "skipped",
            "run stage skipped",
        ));
        report
    } else {
        let run_artifact_dir = request.resolved_stage_artifact_dir(JudgeStageName::Run);
        audit_events.push(stage_event(
            JudgeStageName::Run,
            "started",
            "run stage started",
        ));
        let report = execute_execution_stage(
            backend,
            &request.request_id,
            JudgeStageName::Run,
            request.run.clone(),
            run_artifact_dir,
            &previous_stage_artifacts,
        )
        .await;
        if report.status == JudgeStageStatus::Completed {
            if let Some(artifact_dir) = report.artifact_dir.clone() {
                previous_stage_artifacts.insert(JudgeStageName::Run, artifact_dir);
            }
            audit_events.push(stage_event(
                JudgeStageName::Run,
                "completed",
                "run stage completed",
            ));
        } else {
            audit_events.push(stage_event(
                JudgeStageName::Run,
                "failed",
                "run stage failed",
            ));
        }
        report
    };

    let checker_report = if let Some(checker_request) = request.checker.clone() {
        if run_report.status != JudgeStageStatus::Completed {
            let report = skipped_stage_report(
                JudgeStageName::Checker,
                checker_request.clone(),
                request.resolved_stage_artifact_dir(JudgeStageName::Checker),
                "checker stage skipped because run stage did not complete successfully",
            );
            audit_events.push(stage_event(
                JudgeStageName::Checker,
                "skipped",
                "checker stage skipped",
            ));
            Some(report)
        } else {
            let checker_artifact_dir = request.resolved_stage_artifact_dir(JudgeStageName::Checker);
            audit_events.push(stage_event(
                JudgeStageName::Checker,
                "started",
                "checker stage started",
            ));
            let report = execute_execution_stage(
                backend,
                &request.request_id,
                JudgeStageName::Checker,
                checker_request,
                checker_artifact_dir,
                &previous_stage_artifacts,
            )
            .await;
            if report.status == JudgeStageStatus::Completed {
                audit_events.push(stage_event(
                    JudgeStageName::Checker,
                    "completed",
                    "checker stage completed",
                ));
            } else {
                audit_events.push(stage_event(
                    JudgeStageName::Checker,
                    "failed",
                    "checker stage failed",
                ));
            }
            Some(report)
        }
    } else {
        None
    };

    let status = judge_job_status_from_stage_reports(
        compile_report.as_ref(),
        &run_report,
        checker_report.as_ref(),
    );
    audit_events.push(AuditEvent {
        stage: "completed".to_string(),
        message: format!(
            "judge job finished with status `{}`",
            match status {
                JudgeJobStatus::Completed => "completed",
                JudgeJobStatus::Failed => "failed",
            }
        ),
    });

    Ok(JudgeJobReport {
        request,
        status,
        compile: compile_report,
        run: run_report,
        checker: checker_report,
        audit_events,
    })
}

fn error_detail_from_protocol_error(
    error: ProtocolError,
    fallback_request_id: Option<String>,
) -> ErrorDetail {
    ErrorDetail {
        code: error.code.to_string(),
        message: error.message,
        request_id: error.request_id.or(fallback_request_id),
    }
}

struct ExecutionTaskManager<B> {
    backend: Arc<B>,
    next_task_id: AtomicU64,
    tasks: Arc<RwLock<HashMap<String, ExecutionTaskResponse>>>,
}

impl<B> ExecutionTaskManager<B>
where
    B: ProtocolBackend,
{
    fn new(backend: Arc<B>) -> Self {
        Self {
            backend,
            next_task_id: AtomicU64::new(1),
            tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn submit(
        &self,
        request: ExecutionRequest,
    ) -> Result<ExecutionTaskAccepted, ProtocolError> {
        let request_id = request.request_id.clone();
        self.backend
            .validate_config(ValidateConfigRequest {
                config: request.config.clone(),
            })
            .await
            .map_err(|mut err| {
                if err.request_id.is_none() {
                    err.request_id = Some(request_id.clone());
                }
                err
            })?;

        let task_id = format!("exec-{}", self.next_task_id.fetch_add(1, Ordering::Relaxed));
        let accepted = ExecutionTaskAccepted {
            task_id: task_id.clone(),
            request_id: request_id.clone(),
            status: ExecutionTaskStatus::Accepted,
        };

        self.tasks.write().await.insert(
            task_id.clone(),
            ExecutionTaskResponse {
                task_id: task_id.clone(),
                request_id: request_id.clone(),
                status: ExecutionTaskStatus::Accepted,
                report: None,
                error: None,
            },
        );

        let backend = Arc::clone(&self.backend);
        let tasks = Arc::clone(&self.tasks);
        tokio::spawn(async move {
            update_task_status(&tasks, &task_id, ExecutionTaskStatus::Running, None, None).await;
            match backend.execute(request).await {
                Ok(report) => {
                    update_task_status(
                        &tasks,
                        &task_id,
                        ExecutionTaskStatus::Completed,
                        Some(report),
                        None,
                    )
                    .await;
                }
                Err(error) => {
                    let detail = error_detail_from_protocol_error(error, Some(request_id));
                    update_task_status(
                        &tasks,
                        &task_id,
                        ExecutionTaskStatus::Failed,
                        None,
                        Some(detail),
                    )
                    .await;
                }
            }
        });

        Ok(accepted)
    }

    async fn get(&self, task_id: &str) -> Option<ExecutionTaskResponse> {
        self.tasks.read().await.get(task_id).cloned()
    }
}

async fn update_task_status(
    tasks: &RwLock<HashMap<String, ExecutionTaskResponse>>,
    task_id: &str,
    status: ExecutionTaskStatus,
    report: Option<ExecutionReport>,
    error: Option<ErrorDetail>,
) {
    let mut guard = tasks.write().await;
    if let Some(task) = guard.get_mut(task_id) {
        task.status = status;
        task.report = report;
        task.error = error;
    }
}

pub fn build_router<B>(backend: B) -> Router
where
    B: ProtocolBackend,
{
    let backend = Arc::new(backend);
    let health_backend = Arc::clone(&backend);
    let capabilities_backend = Arc::clone(&backend);
    let validate_backend = Arc::clone(&backend);
    let execute_backend = Arc::clone(&backend);
    let judge_job_backend = Arc::clone(&backend);
    let async_submit_manager = Arc::new(ExecutionTaskManager::new(Arc::clone(&backend)));
    let async_status_manager = Arc::clone(&async_submit_manager);

    Router::new()
        .route(
            "/healthz",
            get(move || {
                let backend = Arc::clone(&health_backend);
                async move { Json(backend.health().await) }
            }),
        )
        .route(
            "/api/v1/capabilities",
            get(move || {
                let backend = Arc::clone(&capabilities_backend);
                async move { Json(backend.capabilities().await) }
            }),
        )
        .route(
            "/api/v1/config/validate",
            post(
                move |payload: Result<Json<ValidateConfigRequest>, JsonRejection>| {
                    let backend = Arc::clone(&validate_backend);
                    async move {
                        let Json(request) = payload.map_err(json_rejection_to_protocol_error)?;
                        backend.validate_config(request).await.map(Json)
                    }
                },
            ),
        )
        .route(
            "/api/v1/executions",
            post(
                move |payload: Result<Json<ExecutionRequest>, JsonRejection>| {
                    let backend = Arc::clone(&execute_backend);
                    async move {
                        let Json(request) = payload.map_err(json_rejection_to_protocol_error)?;
                        backend.execute(request).await.map(Json)
                    }
                },
            ),
        )
        .route(
            "/api/v1/judge-jobs",
            post(
                move |payload: Result<Json<JudgeJobRequest>, JsonRejection>| {
                    let backend = Arc::clone(&judge_job_backend);
                    async move {
                        let Json(request) = payload.map_err(json_rejection_to_protocol_error)?;
                        backend.execute_judge_job(request).await.map(Json)
                    }
                },
            ),
        )
        .route(
            "/api/v1/executions/async",
            post(
                move |payload: Result<Json<ExecutionRequest>, JsonRejection>| {
                    let manager = Arc::clone(&async_submit_manager);
                    async move {
                        let Json(request) = payload.map_err(json_rejection_to_protocol_error)?;
                        manager
                            .submit(request)
                            .await
                            .map(|accepted| (StatusCode::ACCEPTED, Json(accepted)))
                    }
                },
            ),
        )
        .route(
            "/api/v1/executions/{task_id}",
            get(move |AxumPath(task_id): AxumPath<String>| {
                let manager = Arc::clone(&async_status_manager);
                async move {
                    manager
                        .get(&task_id)
                        .await
                        .ok_or_else(|| task_not_found_error(&task_id))
                        .map(Json)
                }
            }),
        )
        .method_not_allowed_fallback(|| async { method_not_allowed_error() })
        .fallback(|| async { not_found_error() })
}

pub fn default_router() -> Router {
    build_router(SupervisorBackend)
}

pub async fn serve(addr: SocketAddr) -> std::io::Result<()> {
    info!(%addr, "starting sandbox protocol server");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, default_router()).await
}

#[derive(Debug, Clone, Default)]
pub struct SupervisorBackend;

impl ProtocolBackend for SupervisorBackend {
    fn health(&self) -> BackendFuture<HealthStatus> {
        Box::pin(async { HealthStatus::default() })
    }

    fn capabilities(&self) -> BackendFuture<CapabilitiesResponse> {
        Box::pin(async { CapabilitiesResponse::from(probe_namespace_support()) })
    }

    fn validate_config(
        &self,
        request: ValidateConfigRequest,
    ) -> BackendFuture<Result<ValidateConfigResponse, ProtocolError>> {
        Box::pin(async move {
            request.config.validate().map_err(ProtocolError::from)?;
            Ok(ValidateConfigResponse {
                valid: true,
                resource_limits: request.config.resource_limits(),
            })
        })
    }

    fn compile(
        &self,
        request: CompilationRequest,
    ) -> BackendFuture<Result<CompilationReport, ProtocolError>> {
        Box::pin(async move {
            let request_id = request.request_id.clone();
            request.config.validate().map_err(|err| {
                let mut mapped = ProtocolError::from(err);
                mapped.request_id = Some(request_id.clone());
                mapped
            })?;

            let compile_request = request.clone();
            let result = tokio::task::spawn_blocking(move || {
                compile(
                    &compile_request.config,
                    &CompileOptions {
                        argv_override: compile_request.command_override.clone(),
                        artifact_dir: compile_request.artifact_dir.clone(),
                        cgroup_root_override: None,
                        source_dir: compile_request.source_dir.clone(),
                        output_dir: compile_request.output_dir.clone(),
                    },
                )
            })
            .await
            .map_err(|err| {
                ProtocolError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    format!("sandbox compilation task failed to join: {err}"),
                    Some(request_id.clone()),
                )
            })?
            .map_err(|err| {
                let mut mapped = ProtocolError::from(err);
                mapped.request_id = Some(request_id.clone());
                mapped
            })?;

            Ok(CompilationReport {
                request: CompilationRequest {
                    artifact_dir: request.artifact_dir.or_else(|| {
                        Some(planned_artifact_dir(
                            &request.config,
                            &RunOptions {
                                argv_override: request.command_override.clone(),
                                artifact_dir: None,
                                cgroup_root_override: None,
                            },
                        ))
                    }),
                    source_dir: Some(result.source_dir.clone()),
                    output_dir: Some(result.output_dir.clone()),
                    ..request
                },
                result,
                audit_events: vec![
                    AuditEvent {
                        stage: "accepted".to_string(),
                        message: "compilation request accepted".to_string(),
                    },
                    AuditEvent {
                        stage: "completed".to_string(),
                        message: "compilation finished".to_string(),
                    },
                ],
            })
        })
    }

    fn execute(
        &self,
        request: ExecutionRequest,
    ) -> BackendFuture<Result<ExecutionReport, ProtocolError>> {
        Box::pin(async move {
            let request_id = request.request_id.clone();
            request.config.validate().map_err(|err| {
                let mut mapped = ProtocolError::from(err);
                mapped.request_id = Some(request_id.clone());
                mapped
            })?;

            let run_request = request.clone();
            let result = tokio::task::spawn_blocking(move || {
                run(
                    &run_request.config,
                    &RunOptions {
                        argv_override: run_request.command_override.clone(),
                        artifact_dir: run_request.artifact_dir.clone(),
                        cgroup_root_override: None,
                    },
                )
            })
            .await
            .map_err(|err| {
                ProtocolError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    format!("sandbox execution task failed to join: {err}"),
                    Some(request_id.clone()),
                )
            })?
            .map_err(|err| {
                let mut mapped = ProtocolError::from(err);
                mapped.request_id = Some(request_id.clone());
                mapped
            })?;
            let resolved_artifact_dir = request.artifact_dir.clone().or_else(|| {
                Some(planned_artifact_dir(
                    &request.config,
                    &RunOptions {
                        argv_override: request.command_override.clone(),
                        artifact_dir: None,
                        cgroup_root_override: None,
                    },
                ))
            });

            Ok(ExecutionReport {
                request: ExecutionRequest {
                    artifact_dir: resolved_artifact_dir,
                    ..request
                },
                result,
                audit_events: vec![
                    AuditEvent {
                        stage: "accepted".to_string(),
                        message: "execution request accepted".to_string(),
                    },
                    AuditEvent {
                        stage: "completed".to_string(),
                        message: "execution finished".to_string(),
                    },
                ],
            })
        })
    }

    fn execute_judge_job(
        &self,
        request: JudgeJobRequest,
    ) -> BackendFuture<Result<JudgeJobReport, ProtocolError>> {
        let backend = self.clone();
        Box::pin(async move { execute_judge_job_with_backend(&backend, request).await })
    }
}

impl From<NamespaceSupport> for CapabilitiesResponse {
    fn from(value: NamespaceSupport) -> Self {
        Self {
            user_namespace: CapabilityStatus {
                available: value.user_namespace,
                reason: value.user_reason,
            },
            mount_namespace: CapabilityStatus {
                available: value.mount_namespace,
                reason: value.mount_reason,
            },
            pid_namespace: CapabilityStatus {
                available: value.pid_namespace,
                reason: value.pid_reason,
            },
            network_namespace: CapabilityStatus {
                available: value.network_namespace,
                reason: value.network_reason,
            },
            ipc_namespace: CapabilityStatus {
                available: value.ipc_namespace,
                reason: value.ipc_reason,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use sandbox_core::{CompilationStatus, ExecutionStatus, ResourceUsage};
    use serde::de::DeserializeOwned;
    use std::fs;
    use std::sync::Mutex;
    use tokio::sync::Notify;
    use tower::util::ServiceExt;

    #[derive(Clone)]
    struct TestBackend;

    impl ProtocolBackend for TestBackend {
        fn health(&self) -> BackendFuture<HealthStatus> {
            Box::pin(async { HealthStatus::default() })
        }

        fn capabilities(&self) -> BackendFuture<CapabilitiesResponse> {
            Box::pin(async {
                CapabilitiesResponse {
                    user_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    mount_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    pid_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    network_namespace: CapabilityStatus {
                        available: false,
                        reason: Some("disabled in test".to_string()),
                    },
                    ipc_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                }
            })
        }

        fn validate_config(
            &self,
            request: ValidateConfigRequest,
        ) -> BackendFuture<Result<ValidateConfigResponse, ProtocolError>> {
            Box::pin(async move {
                request.config.validate().map_err(ProtocolError::from)?;
                Ok(ValidateConfigResponse {
                    valid: true,
                    resource_limits: request.config.resource_limits(),
                })
            })
        }

        fn compile(
            &self,
            request: CompilationRequest,
        ) -> BackendFuture<Result<CompilationReport, ProtocolError>> {
            Box::pin(async move {
                if request.request_id == "bad-compile" {
                    return Err(ProtocolError::new(
                        StatusCode::BAD_REQUEST,
                        "configuration",
                        "bad compile request",
                        Some(request.request_id),
                    ));
                }

                let artifact_dir = request
                    .artifact_dir
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("/tmp/test-compile-artifacts"));
                let output_dir = request
                    .output_dir
                    .clone()
                    .unwrap_or_else(|| artifact_dir.join("outputs"));
                fs::create_dir_all(&output_dir).unwrap();
                fs::write(output_dir.join("program.txt"), "compiled output\n").unwrap();
                fs::write(artifact_dir.join("stdout.log"), "compile stdout\n").unwrap();
                fs::write(artifact_dir.join("stderr.log"), "").unwrap();

                Ok(CompilationReport {
                    request: CompilationRequest {
                        artifact_dir: Some(artifact_dir.clone()),
                        source_dir: Some(
                            request
                                .source_dir
                                .clone()
                                .unwrap_or_else(|| PathBuf::from(".")),
                        ),
                        output_dir: Some(output_dir.clone()),
                        ..request.clone()
                    },
                    result: CompilationResult {
                        command: request
                            .command_override
                            .clone()
                            .unwrap_or_else(|| request.config.process.argv.clone()),
                        source_dir: request
                            .source_dir
                            .clone()
                            .unwrap_or_else(|| PathBuf::from(".")),
                        output_dir: output_dir.clone(),
                        outputs: vec![output_dir.join("program.txt")],
                        exit_code: Some(0),
                        term_signal: None,
                        usage: ResourceUsage {
                            cpu_time_ms: Some(1),
                            wall_time_ms: 2,
                            memory_peak_bytes: Some(3),
                        },
                        stdout_path: artifact_dir.join("stdout.log"),
                        stderr_path: artifact_dir.join("stderr.log"),
                        status: CompilationStatus::Ok,
                    },
                    audit_events: vec![AuditEvent {
                        stage: "completed".to_string(),
                        message: "compile finished".to_string(),
                    }],
                })
            })
        }

        fn execute(
            &self,
            request: ExecutionRequest,
        ) -> BackendFuture<Result<ExecutionReport, ProtocolError>> {
            Box::pin(async move {
                if request.request_id == "bad" {
                    return Err(ProtocolError::new(
                        StatusCode::BAD_REQUEST,
                        "configuration",
                        "bad request",
                        Some(request.request_id),
                    ));
                }

                let artifact_dir = request
                    .artifact_dir
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("/tmp/test-run-artifacts"));
                fs::create_dir_all(&artifact_dir).unwrap();
                let stdout_path = artifact_dir.join("stdout.log");
                let stderr_path = artifact_dir.join("stderr.log");
                let stdout_body = if let Some(stdin_path) = request.config.io.stdin_path.as_ref() {
                    fs::read_to_string(stdin_path).unwrap_or_else(|_| "stdin missing\n".to_string())
                } else {
                    "test stdout\n".to_string()
                };
                fs::write(&stdout_path, stdout_body).unwrap();
                fs::write(&stderr_path, "").unwrap();

                Ok(ExecutionReport {
                    request: ExecutionRequest {
                        artifact_dir: Some(artifact_dir.clone()),
                        ..request.clone()
                    },
                    result: ExecutionResult {
                        command: request
                            .command_override
                            .clone()
                            .unwrap_or_else(|| request.config.process.argv.clone()),
                        exit_code: Some(0),
                        term_signal: None,
                        usage: ResourceUsage {
                            cpu_time_ms: Some(1),
                            wall_time_ms: 2,
                            memory_peak_bytes: Some(3),
                        },
                        stdout_path,
                        stderr_path,
                        status: ExecutionStatus::Ok,
                    },
                    audit_events: vec![AuditEvent {
                        stage: "completed".to_string(),
                        message: "test finished".to_string(),
                    }],
                })
            })
        }

        fn execute_judge_job(
            &self,
            request: JudgeJobRequest,
        ) -> BackendFuture<Result<JudgeJobReport, ProtocolError>> {
            let backend = self.clone();
            Box::pin(async move { execute_judge_job_with_backend(&backend, request).await })
        }
    }

    fn sample_config() -> ExecutionConfig {
        ExecutionConfig::from_toml_str(
            r#"
[process]
argv = ["/bin/echo", "hello"]

[limits]
wall_time_ms = 1000

[filesystem]
enable_rootfs = false
"#,
        )
        .expect("config should parse")
    }

    fn sample_judge_job_request() -> JudgeJobRequest {
        JudgeJobRequest {
            request_id: "judge-run-001".to_string(),
            artifact_dir: Some("/tmp/sandbox-api/judge-run-001".into()),
            compile: None,
            run: JudgeStageRequest {
                config: sample_config(),
                command_override: Some(vec!["/bin/echo".to_string(), "judge".to_string()]),
                artifact_dir: None,
                inputs: JudgeStageInputs::default(),
            },
            checker: None,
        }
    }

    fn sample_multi_stage_judge_job_request() -> JudgeJobRequest {
        JudgeJobRequest {
            request_id: "judge-pipeline-001".to_string(),
            artifact_dir: Some("/tmp/sandbox-api/judge-pipeline-001".into()),
            compile: Some(JudgeStageRequest {
                config: sample_config(),
                command_override: Some(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "compile".to_string(),
                ]),
                artifact_dir: None,
                inputs: JudgeStageInputs::default(),
            }),
            run: JudgeStageRequest {
                config: sample_config(),
                command_override: Some(vec!["/bin/cat".to_string()]),
                artifact_dir: None,
                inputs: JudgeStageInputs {
                    stdin: Some(JudgeArtifactRef {
                        stage: JudgeStageName::Compile,
                        artifact_path: PathBuf::from("outputs/program.txt"),
                    }),
                    readonly_artifacts: Vec::new(),
                },
            },
            checker: Some(JudgeStageRequest {
                config: sample_config(),
                command_override: Some(vec!["/bin/cat".to_string()]),
                artifact_dir: None,
                inputs: JudgeStageInputs {
                    stdin: Some(JudgeArtifactRef {
                        stage: JudgeStageName::Run,
                        artifact_path: PathBuf::from("stdout.log"),
                    }),
                    readonly_artifacts: Vec::new(),
                },
            }),
        }
    }

    async fn response_json<T: DeserializeOwned>(response: Response) -> T {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        serde_json::from_slice(&bytes).expect("response body should be valid JSON")
    }

    async fn send(app: &Router, request: Request<Body>) -> Response {
        app.clone()
            .oneshot(request)
            .await
            .expect("router request should succeed")
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let app = build_router(TestBackend);
        let response = send(
            &app,
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: HealthStatus = response_json(response).await;
        assert_eq!(body.status, "ok");
        assert_eq!(body.service, "sandbox-protocol");
    }

    #[tokio::test]
    async fn capabilities_returns_backend_payload() {
        let app = build_router(TestBackend);
        let response = send(
            &app,
            Request::builder()
                .uri("/api/v1/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: CapabilitiesResponse = response_json(response).await;
        assert!(body.user_namespace.available);
        assert!(!body.network_namespace.available);
        assert_eq!(
            body.network_namespace.reason.as_deref(),
            Some("disabled in test")
        );
    }

    #[tokio::test]
    async fn validate_config_returns_limits() {
        let app = build_router(TestBackend);
        let payload = serde_json::to_vec(&ValidateConfigRequest {
            config: sample_config(),
        })
        .unwrap();
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/config/validate")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: ValidateConfigResponse = response_json(response).await;
        assert!(body.valid);
        assert_eq!(body.resource_limits, sample_config().resource_limits());
    }

    #[tokio::test]
    async fn validate_config_rejects_missing_json_content_type() {
        let app = build_router(TestBackend);
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/config/validate")
                .body(Body::from(
                    serde_json::to_vec(&ValidateConfigRequest {
                        config: sample_config(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "invalid_content_type");
        assert_eq!(
            body.error.message,
            "request content type must be application/json"
        );
        assert_eq!(body.error.request_id, None);
    }

    #[tokio::test]
    async fn execute_returns_report() {
        let app = build_router(TestBackend);
        let payload = serde_json::to_vec(&ExecutionRequest {
            request_id: "run-001".to_string(),
            config: sample_config(),
            command_override: Some(vec!["/bin/echo".to_string(), "override".to_string()]),
            artifact_dir: Some("/tmp/sandbox-api/run-001".into()),
        })
        .unwrap();
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: ExecutionReport = response_json(response).await;
        assert_eq!(body.request.request_id, "run-001");
        assert_eq!(
            body.result.command,
            vec!["/bin/echo".to_string(), "override".to_string()]
        );
        assert_eq!(body.result.status, ExecutionStatus::Ok);
        assert_eq!(body.audit_events.len(), 1);
        assert_eq!(body.audit_events[0].stage, "completed");
    }

    #[tokio::test]
    async fn judge_job_run_only_returns_report() {
        let app = build_router(TestBackend);
        let payload = serde_json::to_vec(&sample_judge_job_request()).unwrap();
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/judge-jobs")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: JudgeJobReport = response_json(response).await;
        assert_eq!(body.request.request_id, "judge-run-001");
        assert_eq!(body.status, JudgeJobStatus::Completed);
        assert!(body.compile.is_none());
        assert!(body.checker.is_none());
        assert_eq!(body.run.stage, JudgeStageName::Run);
        assert_eq!(body.run.status, JudgeStageStatus::Completed);
        assert_eq!(
            body.run.artifact_dir,
            Some(PathBuf::from("/tmp/sandbox-api/judge-run-001/run"))
        );
        assert_eq!(
            body.run
                .result
                .as_ref()
                .map(|result| result.command.clone())
                .unwrap(),
            vec!["/bin/echo".to_string(), "judge".to_string()]
        );
        assert_eq!(body.run.artifacts.len(), 2);
        assert_eq!(body.run.artifacts[0].kind, JudgeArtifactKind::Stdout);
        assert_eq!(body.run.artifacts[1].kind, JudgeArtifactKind::Stderr);
    }

    #[tokio::test]
    async fn judge_job_multi_stage_pipeline_returns_per_stage_reports() {
        let app = build_router(TestBackend);
        let request = sample_multi_stage_judge_job_request();
        let payload = serde_json::to_vec(&request).unwrap();
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/judge-jobs")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: JudgeJobReport = response_json(response).await;
        assert_eq!(body.status, JudgeJobStatus::Completed);
        assert_eq!(
            body.compile
                .as_ref()
                .and_then(|report| report.compilation_result.as_ref())
                .map(|result| result.status.clone()),
            Some(CompilationStatus::Ok)
        );
        assert_eq!(
            body.run.result.as_ref().map(|result| result.status.clone()),
            Some(ExecutionStatus::Ok)
        );
        assert_eq!(
            body.checker
                .as_ref()
                .and_then(|report| report.result.as_ref())
                .map(|result| result.status.clone()),
            Some(ExecutionStatus::Ok)
        );
        assert_eq!(
            body.compile
                .as_ref()
                .map(|report| report.artifact_dir.clone())
                .flatten(),
            Some(PathBuf::from("/tmp/sandbox-api/judge-pipeline-001/compile"))
        );
        assert_eq!(
            body.run.artifact_dir,
            Some(PathBuf::from("/tmp/sandbox-api/judge-pipeline-001/run"))
        );
        assert_eq!(
            body.checker
                .as_ref()
                .map(|report| report.artifact_dir.clone())
                .flatten(),
            Some(PathBuf::from("/tmp/sandbox-api/judge-pipeline-001/checker"))
        );
        assert!(
            body.audit_events
                .iter()
                .any(|event| event.stage == "compile_completed")
        );
        assert!(
            body.audit_events
                .iter()
                .any(|event| event.stage == "checker_completed")
        );
    }

    #[derive(Clone)]
    struct CompileFailureBackend {
        executed_stages: Arc<Mutex<Vec<String>>>,
    }

    impl CompileFailureBackend {
        fn new() -> Self {
            Self {
                executed_stages: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl ProtocolBackend for CompileFailureBackend {
        fn health(&self) -> BackendFuture<HealthStatus> {
            Box::pin(async { HealthStatus::default() })
        }

        fn capabilities(&self) -> BackendFuture<CapabilitiesResponse> {
            Box::pin(async {
                CapabilitiesResponse {
                    user_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    mount_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    pid_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    network_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    ipc_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                }
            })
        }

        fn validate_config(
            &self,
            request: ValidateConfigRequest,
        ) -> BackendFuture<Result<ValidateConfigResponse, ProtocolError>> {
            Box::pin(async move {
                request.config.validate().map_err(ProtocolError::from)?;
                Ok(ValidateConfigResponse {
                    valid: true,
                    resource_limits: request.config.resource_limits(),
                })
            })
        }

        fn compile(
            &self,
            request: CompilationRequest,
        ) -> BackendFuture<Result<CompilationReport, ProtocolError>> {
            let executed_stages = Arc::clone(&self.executed_stages);
            Box::pin(async move {
                executed_stages.lock().unwrap().push("compile".to_string());
                let artifact_dir = request.artifact_dir.clone().unwrap();
                let output_dir = request.output_dir.clone().unwrap();
                fs::create_dir_all(&output_dir).unwrap();
                fs::write(output_dir.join("program.txt"), "broken output\n").unwrap();
                fs::write(artifact_dir.join("stdout.log"), "").unwrap();
                fs::write(artifact_dir.join("stderr.log"), "compile failed\n").unwrap();

                Ok(CompilationReport {
                    request: request.clone(),
                    result: CompilationResult {
                        command: request.config.process.argv.clone(),
                        source_dir: request
                            .source_dir
                            .clone()
                            .unwrap_or_else(|| PathBuf::from(".")),
                        output_dir,
                        outputs: vec![artifact_dir.join("outputs/program.txt")],
                        exit_code: Some(1),
                        term_signal: None,
                        usage: ResourceUsage {
                            cpu_time_ms: Some(1),
                            wall_time_ms: 2,
                            memory_peak_bytes: Some(3),
                        },
                        stdout_path: artifact_dir.join("stdout.log"),
                        stderr_path: artifact_dir.join("stderr.log"),
                        status: CompilationStatus::CompilationFailed,
                    },
                    audit_events: vec![AuditEvent {
                        stage: "completed".to_string(),
                        message: "compile finished".to_string(),
                    }],
                })
            })
        }

        fn execute(
            &self,
            request: ExecutionRequest,
        ) -> BackendFuture<Result<ExecutionReport, ProtocolError>> {
            let executed_stages = Arc::clone(&self.executed_stages);
            Box::pin(async move {
                executed_stages.lock().unwrap().push(request.request_id);
                Err(ProtocolError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "execute should not be called after compile failure",
                    None,
                ))
            })
        }

        fn execute_judge_job(
            &self,
            request: JudgeJobRequest,
        ) -> BackendFuture<Result<JudgeJobReport, ProtocolError>> {
            let backend = self.clone();
            Box::pin(async move { execute_judge_job_with_backend(&backend, request).await })
        }
    }

    #[tokio::test]
    async fn judge_job_stops_after_compile_failure_and_skips_later_stages() {
        let backend = CompileFailureBackend::new();
        let app = build_router(backend.clone());
        let payload = serde_json::to_vec(&sample_multi_stage_judge_job_request()).unwrap();
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/judge-jobs")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: JudgeJobReport = response_json(response).await;
        assert_eq!(body.status, JudgeJobStatus::Failed);
        assert_eq!(
            body.compile.as_ref().map(|report| report.status),
            Some(JudgeStageStatus::Failed)
        );
        assert_eq!(body.run.status, JudgeStageStatus::Skipped);
        assert_eq!(
            body.checker.as_ref().map(|report| report.status),
            Some(JudgeStageStatus::Skipped)
        );
        assert_eq!(
            backend.executed_stages.lock().unwrap().as_slice(),
            ["compile"]
        );
    }

    #[tokio::test]
    async fn execute_rejects_malformed_json() {
        let app = build_router(TestBackend);
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions")
                .header("content-type", "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "invalid_json");
        assert_eq!(body.error.message, "request body contains invalid JSON");
        assert_eq!(body.error.request_id, None);
    }

    #[tokio::test]
    async fn execute_maps_backend_errors() {
        let app = build_router(TestBackend);
        let payload = serde_json::to_vec(&ExecutionRequest {
            request_id: "bad".to_string(),
            config: sample_config(),
            command_override: None,
            artifact_dir: None,
        })
        .unwrap();
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "configuration");
        assert_eq!(body.error.message, "bad request");
        assert_eq!(body.error.request_id.as_deref(), Some("bad"));
    }

    #[tokio::test]
    async fn unknown_route_returns_protocol_error() {
        let app = build_router(TestBackend);
        let response = send(
            &app,
            Request::builder()
                .uri("/api/v1/unknown")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "not_found");
        assert_eq!(body.error.message, "route not found");
        assert_eq!(body.error.request_id, None);
    }

    #[tokio::test]
    async fn unsupported_method_returns_protocol_error() {
        let app = build_router(TestBackend);
        let response = send(
            &app,
            Request::builder()
                .method("GET")
                .uri("/api/v1/executions")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "method_not_allowed");
        assert_eq!(body.error.message, "method not allowed for this route");
        assert_eq!(body.error.request_id, None);
    }

    #[derive(Clone)]
    struct GatedBackend {
        gate: Arc<Notify>,
        started: Arc<Notify>,
        fail: bool,
    }

    impl GatedBackend {
        fn success() -> Self {
            Self {
                gate: Arc::new(Notify::new()),
                started: Arc::new(Notify::new()),
                fail: false,
            }
        }

        fn failure() -> Self {
            Self {
                gate: Arc::new(Notify::new()),
                started: Arc::new(Notify::new()),
                fail: true,
            }
        }
    }

    impl ProtocolBackend for GatedBackend {
        fn health(&self) -> BackendFuture<HealthStatus> {
            Box::pin(async { HealthStatus::default() })
        }

        fn capabilities(&self) -> BackendFuture<CapabilitiesResponse> {
            Box::pin(async {
                CapabilitiesResponse {
                    user_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    mount_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    pid_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    network_namespace: CapabilityStatus {
                        available: false,
                        reason: Some("disabled in test".to_string()),
                    },
                    ipc_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                }
            })
        }

        fn validate_config(
            &self,
            request: ValidateConfigRequest,
        ) -> BackendFuture<Result<ValidateConfigResponse, ProtocolError>> {
            Box::pin(async move {
                request.config.validate().map_err(ProtocolError::from)?;
                Ok(ValidateConfigResponse {
                    valid: true,
                    resource_limits: request.config.resource_limits(),
                })
            })
        }

        fn execute(
            &self,
            request: ExecutionRequest,
        ) -> BackendFuture<Result<ExecutionReport, ProtocolError>> {
            let gate = Arc::clone(&self.gate);
            let started = Arc::clone(&self.started);
            let fail = self.fail;
            Box::pin(async move {
                started.notify_one();
                gate.notified().await;
                if fail {
                    return Err(ProtocolError::new(
                        StatusCode::CONFLICT,
                        "capability_unavailable",
                        "network namespace unavailable",
                        Some(request.request_id),
                    ));
                }

                Ok(ExecutionReport {
                    request: request.clone(),
                    result: ExecutionResult {
                        command: request
                            .command_override
                            .clone()
                            .unwrap_or_else(|| request.config.process.argv.clone()),
                        exit_code: Some(0),
                        term_signal: None,
                        usage: ResourceUsage {
                            cpu_time_ms: Some(1),
                            wall_time_ms: 2,
                            memory_peak_bytes: Some(3),
                        },
                        stdout_path: "stdout.log".into(),
                        stderr_path: "stderr.log".into(),
                        status: ExecutionStatus::Ok,
                    },
                    audit_events: vec![
                        AuditEvent {
                            stage: "accepted".to_string(),
                            message: "execution request accepted".to_string(),
                        },
                        AuditEvent {
                            stage: "completed".to_string(),
                            message: "execution finished".to_string(),
                        },
                    ],
                })
            })
        }
    }

    async fn fetch_task_response(app: &Router, task_id: &str) -> Response {
        send(
            app,
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/executions/{task_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn async_execute_returns_accepted_and_completed_status() {
        let backend = GatedBackend::success();
        let app = build_router(backend.clone());
        let payload = serde_json::to_vec(&ExecutionRequest {
            request_id: "async-run-001".to_string(),
            config: sample_config(),
            command_override: Some(vec!["/bin/echo".to_string(), "async".to_string()]),
            artifact_dir: Some("/tmp/sandbox-api/async-run-001".into()),
        })
        .unwrap();

        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions/async")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let accepted: ExecutionTaskAccepted = response_json(response).await;
        assert_eq!(accepted.request_id, "async-run-001");
        assert_eq!(accepted.status, ExecutionTaskStatus::Accepted);
        assert!(accepted.task_id.starts_with("exec-"));

        backend.started.notified().await;

        let running_response = fetch_task_response(&app, &accepted.task_id).await;
        assert_eq!(running_response.status(), StatusCode::OK);
        let running: ExecutionTaskResponse = response_json(running_response).await;
        assert_eq!(running.status, ExecutionTaskStatus::Running);
        assert!(running.report.is_none());
        assert!(running.error.is_none());

        backend.gate.notify_waiters();

        for _ in 0..20 {
            let completed_response = fetch_task_response(&app, &accepted.task_id).await;
            let completed: ExecutionTaskResponse = response_json(completed_response).await;
            if completed.status == ExecutionTaskStatus::Completed {
                assert_eq!(completed.request_id, "async-run-001");
                assert!(completed.error.is_none());
                assert_eq!(
                    completed
                        .report
                        .as_ref()
                        .map(|report| report.result.status.clone()),
                    Some(ExecutionStatus::Ok)
                );
                return;
            }
            tokio::task::yield_now().await;
        }

        panic!("async execution task did not complete in time");
    }

    #[tokio::test]
    async fn async_execute_persists_failures_in_task_status() {
        let backend = GatedBackend::failure();
        let app = build_router(backend.clone());
        let payload = serde_json::to_vec(&ExecutionRequest {
            request_id: "async-run-bad".to_string(),
            config: sample_config(),
            command_override: None,
            artifact_dir: None,
        })
        .unwrap();

        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions/async")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let accepted: ExecutionTaskAccepted = response_json(response).await;
        backend.started.notified().await;
        backend.gate.notify_waiters();

        for _ in 0..20 {
            let failed_response = fetch_task_response(&app, &accepted.task_id).await;
            let failed: ExecutionTaskResponse = response_json(failed_response).await;
            if failed.status == ExecutionTaskStatus::Failed {
                assert!(failed.report.is_none());
                assert_eq!(
                    failed.error.as_ref().map(|error| error.code.as_str()),
                    Some("capability_unavailable")
                );
                assert_eq!(
                    failed
                        .error
                        .as_ref()
                        .and_then(|error| error.request_id.as_deref()),
                    Some("async-run-bad")
                );
                return;
            }
            tokio::task::yield_now().await;
        }

        panic!("async execution task did not fail in time");
    }

    #[tokio::test]
    async fn async_status_returns_not_found_for_unknown_task() {
        let app = build_router(TestBackend);
        let response = fetch_task_response(&app, "missing-task").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "not_found");
        assert_eq!(
            body.error.message,
            "execution task `missing-task` was not found"
        );
        assert_eq!(body.error.request_id, None);
    }
}
