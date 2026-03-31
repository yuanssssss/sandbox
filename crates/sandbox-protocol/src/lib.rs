use std::collections::{HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_stream::stream;
use axum::body::Body as AxumBody;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State};
use axum::http::Request;
use axum::http::StatusCode;
use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
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
use tokio::sync::{RwLock, Semaphore, broadcast};
use tracing::info;

pub type BackendFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

#[derive(Debug, Clone)]
pub struct ProtocolServerOptions {
    pub auth_token: Option<String>,
    pub max_request_body_bytes: usize,
    pub max_concurrent_requests: usize,
}

impl Default for ProtocolServerOptions {
    fn default() -> Self {
        Self {
            auth_token: None,
            max_request_body_bytes: 1024 * 1024,
            max_concurrent_requests: 32,
        }
    }
}

#[derive(Debug, Clone)]
struct ApiMiddlewareState {
    auth_token: Option<Arc<str>>,
    max_request_body_bytes: usize,
    max_concurrent_requests: usize,
    semaphore: Arc<Semaphore>,
}

impl ApiMiddlewareState {
    fn from_options(options: &ProtocolServerOptions) -> Self {
        Self {
            auth_token: options.auth_token.clone().map(Arc::<str>::from),
            max_request_body_bytes: options.max_request_body_bytes,
            max_concurrent_requests: options.max_concurrent_requests,
            semaphore: Arc::new(Semaphore::new(options.max_concurrent_requests.max(1))),
        }
    }
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeJobArtifactIndexResponse {
    pub request_id: String,
    pub stages: Vec<JudgeStageArtifactIndex>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeStageArtifactIndex {
    pub stage: JudgeStageName,
    pub status: JudgeStageStatus,
    #[serde(default)]
    pub artifact_dir: Option<PathBuf>,
    pub artifacts: Vec<JudgeArtifactEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JudgeArtifactEntry {
    pub path: PathBuf,
    pub kind: JudgeArtifactKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
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
pub struct JudgeJobTaskAccepted {
    pub task_id: String,
    pub request_id: String,
    pub status: ExecutionTaskStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeJobTaskResponse {
    pub task_id: String,
    pub request_id: String,
    pub status: ExecutionTaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<JudgeJobReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JudgeJobTaskEvent {
    pub sequence: u64,
    pub task_id: String,
    pub request_id: String,
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ExecutionTaskStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    pub message: String,
}

impl JudgeJobTaskEvent {
    fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            Some(ExecutionTaskStatus::Completed | ExecutionTaskStatus::Failed)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionTaskEvent {
    pub sequence: u64,
    pub task_id: String,
    pub request_id: String,
    pub status: ExecutionTaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    pub message: String,
}

impl ExecutionTaskEvent {
    fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            ExecutionTaskStatus::Completed | ExecutionTaskStatus::Failed
        )
    }
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

#[derive(Debug, Clone, Deserialize)]
struct ArtifactFileQuery {
    path: PathBuf,
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

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProtocolError {}

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

fn judge_job_task_not_found_error(task_id: &str) -> ProtocolError {
    ProtocolError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        format!("judge job task `{task_id}` was not found"),
        None,
    )
}

fn async_task_capacity_exceeded_error(max_tasks: usize, request_id: &str) -> ProtocolError {
    ProtocolError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "task_capacity_exceeded",
        format!(
            "async execution task capacity exceeded: at most {max_tasks} retained tasks are allowed"
        ),
        Some(request_id.to_string()),
    )
}

fn unauthorized_error() -> ProtocolError {
    ProtocolError::new(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "missing or invalid bearer token",
        None,
    )
}

fn request_too_large_error(limit: usize) -> ProtocolError {
    ProtocolError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_too_large",
        format!("request body exceeds the configured limit of {limit} bytes"),
        None,
    )
}

fn concurrency_limit_exceeded_error(limit: usize) -> ProtocolError {
    ProtocolError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "concurrency_limit_exceeded",
        format!(
            "server concurrency limit exceeded: at most {limit} in-flight requests are allowed"
        ),
        None,
    )
}

fn judge_job_not_found_error(request_id: &str) -> ProtocolError {
    ProtocolError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        format!("judge job `{request_id}` was not found"),
        None,
    )
}

fn artifact_stage_not_found_error(request_id: &str, stage: &str) -> ProtocolError {
    ProtocolError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        format!("judge job `{request_id}` does not contain stage `{stage}`"),
        None,
    )
}

fn missing_artifact_dir_error(request_id: &str, stage: JudgeStageName) -> ProtocolError {
    ProtocolError::new(
        StatusCode::CONFLICT,
        "missing_artifact",
        format!(
            "judge job `{request_id}` stage `{}` has no materialized artifact directory",
            stage.as_str()
        ),
        Some(request_id.to_string()),
    )
}

fn unsupported_artifact_path_error(
    request_id: &str,
    stage: JudgeStageName,
    path: &Path,
) -> ProtocolError {
    ProtocolError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        format!(
            "judge job `{request_id}` stage `{}` does not expose artifact `{}`",
            stage.as_str(),
            path.display()
        ),
        Some(request_id.to_string()),
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

fn stage_report_by_name(
    report: &JudgeJobReport,
    stage: JudgeStageName,
) -> Option<&JudgeStageReport> {
    match stage {
        JudgeStageName::Compile => report.compile.as_ref(),
        JudgeStageName::Run => Some(&report.run),
        JudgeStageName::Checker => report.checker.as_ref(),
    }
}

fn parse_stage_name(raw: &str) -> Result<JudgeStageName, ProtocolError> {
    match raw {
        "compile" => Ok(JudgeStageName::Compile),
        "run" => Ok(JudgeStageName::Run),
        "checker" => Ok(JudgeStageName::Checker),
        _ => Err(ProtocolError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("unknown judge stage `{raw}`"),
            None,
        )),
    }
}

fn relative_path_within_root(root: &Path, path: &Path) -> Option<PathBuf> {
    path.strip_prefix(root).ok().map(PathBuf::from)
}

fn discover_output_directory_entries(
    artifact_root: &Path,
    directory: &Path,
    entries: &mut HashMap<PathBuf, JudgeArtifactEntry>,
) -> Result<(), ProtocolError> {
    if !directory.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(directory).map_err(|err| {
        ProtocolError::from(SandboxError::io("reading artifact output directory", err))
    })? {
        let entry = entry.map_err(|err| {
            ProtocolError::from(SandboxError::io("reading artifact output entry", err))
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|err| {
            ProtocolError::from(SandboxError::io("reading artifact output entry type", err))
        })?;
        let Some(relative_path) = relative_path_within_root(artifact_root, &path) else {
            continue;
        };

        let metadata = entry.metadata().map_err(|err| {
            ProtocolError::from(SandboxError::io("reading artifact metadata", err))
        })?;
        let kind = if file_type.is_dir() {
            JudgeArtifactKind::Directory
        } else {
            JudgeArtifactKind::File
        };
        entries
            .entry(relative_path.clone())
            .or_insert(JudgeArtifactEntry {
                path: relative_path.clone(),
                kind,
                size_bytes: file_type.is_file().then_some(metadata.len()),
            });

        if file_type.is_dir() {
            discover_output_directory_entries(artifact_root, &path, entries)?;
        }
    }

    Ok(())
}

fn build_stage_artifact_entries(
    stage_report: &JudgeStageReport,
) -> Result<Vec<JudgeArtifactEntry>, ProtocolError> {
    let Some(artifact_root) = stage_report.artifact_dir.as_ref() else {
        return Ok(Vec::new());
    };

    let mut entries = HashMap::new();
    for artifact in &stage_report.artifacts {
        let Some(relative_path) = relative_path_within_root(artifact_root, &artifact.path) else {
            continue;
        };
        let size_bytes = fs::metadata(&artifact.path)
            .ok()
            .and_then(|metadata| metadata.is_file().then_some(metadata.len()));
        entries
            .entry(relative_path.clone())
            .or_insert(JudgeArtifactEntry {
                path: relative_path.clone(),
                kind: artifact.kind,
                size_bytes,
            });

        if artifact.kind == JudgeArtifactKind::OutputDirectory {
            discover_output_directory_entries(artifact_root, &artifact.path, &mut entries)?;
        }
    }

    let mut values = entries.into_values().collect::<Vec<_>>();
    values.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(values)
}

fn build_judge_job_artifact_index(
    report: &JudgeJobReport,
) -> Result<JudgeJobArtifactIndexResponse, ProtocolError> {
    let mut stages = Vec::new();
    for stage in [
        JudgeStageName::Compile,
        JudgeStageName::Run,
        JudgeStageName::Checker,
    ] {
        if let Some(stage_report) = stage_report_by_name(report, stage) {
            stages.push(JudgeStageArtifactIndex {
                stage,
                status: stage_report.status,
                artifact_dir: stage_report.artifact_dir.clone(),
                artifacts: build_stage_artifact_entries(stage_report)?,
            });
        }
    }

    Ok(JudgeJobArtifactIndexResponse {
        request_id: report.request.request_id.clone(),
        stages,
    })
}

fn resolve_downloadable_stage_file(
    report: &JudgeJobReport,
    stage: JudgeStageName,
    requested_path: &Path,
) -> Result<PathBuf, ProtocolError> {
    validate_relative_artifact_path(&report.request.request_id, stage, requested_path)?;

    let stage_report = stage_report_by_name(report, stage).ok_or_else(|| {
        artifact_stage_not_found_error(&report.request.request_id, stage.as_str())
    })?;
    let artifact_root = stage_report
        .artifact_dir
        .as_ref()
        .ok_or_else(|| missing_artifact_dir_error(&report.request.request_id, stage))?;
    let entries = build_stage_artifact_entries(stage_report)?;
    let allowed = entries.iter().any(|entry| entry.path == requested_path);
    if !allowed {
        return Err(unsupported_artifact_path_error(
            &report.request.request_id,
            stage,
            requested_path,
        ));
    }

    let full_path = artifact_root.join(requested_path);
    if !full_path.starts_with(artifact_root) {
        return Err(unsupported_artifact_path_error(
            &report.request.request_id,
            stage,
            requested_path,
        ));
    }
    if !full_path.exists() {
        return Err(ProtocolError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!(
                "artifact `{}` for judge job `{}` stage `{}` no longer exists on disk",
                requested_path.display(),
                report.request.request_id,
                stage.as_str()
            ),
            Some(report.request.request_id.clone()),
        ));
    }

    Ok(full_path)
}

fn content_type_for_artifact(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("log") | Some("txt") | Some("out") | Some("err") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn authorization_matches_expected(header: Option<&HeaderValue>, expected_token: &str) -> bool {
    let Some(header) = header else {
        return false;
    };
    let Ok(raw) = header.to_str() else {
        return false;
    };
    let Some(token) = raw.strip_prefix("Bearer ") else {
        return false;
    };
    token == expected_token
}

async fn api_guard_middleware(
    State(state): State<ApiMiddlewareState>,
    request: Request<AxumBody>,
    next: Next,
) -> Result<Response, ProtocolError> {
    if let Some(expected_token) = state.auth_token.as_deref() {
        if !authorization_matches_expected(request.headers().get(AUTHORIZATION), expected_token) {
            return Err(unauthorized_error());
        }
    }

    if let Some(content_length) = request.headers().get(CONTENT_LENGTH) {
        if let Ok(raw) = content_length.to_str() {
            if let Ok(length) = raw.parse::<usize>() {
                if length > state.max_request_body_bytes {
                    return Err(request_too_large_error(state.max_request_body_bytes));
                }
            }
        }
    }

    let permit = state
        .semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| concurrency_limit_exceeded_error(state.max_concurrent_requests))?;
    let response = next.run(request).await;
    drop(permit);
    Ok(response)
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

fn execution_task_event_message(status: ExecutionTaskStatus) -> &'static str {
    match status {
        ExecutionTaskStatus::Accepted => "execution task accepted",
        ExecutionTaskStatus::Running => "execution task running",
        ExecutionTaskStatus::Completed => "execution task completed",
        ExecutionTaskStatus::Failed => "execution task failed",
    }
}

fn execution_task_sse_event(event: &ExecutionTaskEvent) -> Result<Event, ProtocolError> {
    Event::default()
        .event("task_status")
        .id(event.sequence.to_string())
        .json_data(event)
        .map_err(|err| {
            ProtocolError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("failed to serialize execution task event: {err}"),
                Some(event.request_id.clone()),
            )
        })
}

fn judge_job_task_event_message(status: ExecutionTaskStatus) -> &'static str {
    match status {
        ExecutionTaskStatus::Accepted => "judge job task accepted",
        ExecutionTaskStatus::Running => "judge job task running",
        ExecutionTaskStatus::Completed => "judge job task completed",
        ExecutionTaskStatus::Failed => "judge job task failed",
    }
}

fn judge_job_task_sse_event(event: &JudgeJobTaskEvent) -> Result<Event, ProtocolError> {
    Event::default()
        .event(&event.event_type)
        .id(event.sequence.to_string())
        .json_data(event)
        .map_err(|err| {
            ProtocolError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                format!("failed to serialize judge job task event: {err}"),
                Some(event.request_id.clone()),
            )
        })
}

struct ExecutionTaskManager<B> {
    backend: Arc<B>,
    next_task_id: AtomicU64,
    retention: AsyncTaskRetentionPolicy,
    tasks: Arc<RwLock<HashMap<String, StoredExecutionTask>>>,
}

#[derive(Debug, Clone, Copy)]
struct AsyncTaskRetentionPolicy {
    completed_ttl: Duration,
    max_tasks: usize,
}

impl Default for AsyncTaskRetentionPolicy {
    fn default() -> Self {
        Self {
            completed_ttl: Duration::from_secs(5 * 60),
            max_tasks: 1_024,
        }
    }
}

#[derive(Debug, Clone)]
struct StoredExecutionTask {
    response: ExecutionTaskResponse,
    completed_at: Option<Instant>,
    next_event_sequence: u64,
    event_history: Vec<ExecutionTaskEvent>,
    event_sender: broadcast::Sender<ExecutionTaskEvent>,
}

struct JudgeJobTaskManager<B> {
    backend: Arc<B>,
    next_task_id: AtomicU64,
    retention: AsyncTaskRetentionPolicy,
    store: Arc<JudgeJobStore>,
    tasks: Arc<RwLock<HashMap<String, StoredJudgeJobTask>>>,
}

#[derive(Debug, Clone)]
struct StoredJudgeJobTask {
    response: JudgeJobTaskResponse,
    completed_at: Option<Instant>,
    next_event_sequence: u64,
    event_history: Vec<JudgeJobTaskEvent>,
    event_sender: broadcast::Sender<JudgeJobTaskEvent>,
}

impl<B> ExecutionTaskManager<B>
where
    B: ProtocolBackend,
{
    fn new(backend: Arc<B>) -> Self {
        Self::with_policy(backend, AsyncTaskRetentionPolicy::default())
    }

    fn with_policy(backend: Arc<B>, retention: AsyncTaskRetentionPolicy) -> Self {
        Self {
            backend,
            next_task_id: AtomicU64::new(1),
            retention,
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
        let (event_sender, _) = broadcast::channel(16);
        let accepted_event = ExecutionTaskEvent {
            sequence: 0,
            task_id: task_id.clone(),
            request_id: request_id.clone(),
            status: ExecutionTaskStatus::Accepted,
            stage: Some("execution".to_string()),
            message: "execution task accepted".to_string(),
        };

        let mut tasks = self.tasks.write().await;
        prune_expired_tasks_locked(&mut tasks, self.retention, Instant::now());
        if tasks.len() >= self.retention.max_tasks {
            return Err(async_task_capacity_exceeded_error(
                self.retention.max_tasks,
                &request_id,
            ));
        }
        tasks.insert(
            task_id.clone(),
            StoredExecutionTask {
                response: ExecutionTaskResponse {
                    task_id: task_id.clone(),
                    request_id: request_id.clone(),
                    status: ExecutionTaskStatus::Accepted,
                    report: None,
                    error: None,
                },
                completed_at: None,
                next_event_sequence: 1,
                event_history: vec![accepted_event],
                event_sender,
            },
        );
        drop(tasks);

        let backend = Arc::clone(&self.backend);
        let tasks = Arc::clone(&self.tasks);
        let retention = self.retention;
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
            prune_expired_tasks_with_policy(&tasks, retention).await;
        });

        Ok(accepted)
    }

    async fn get(&self, task_id: &str) -> Option<ExecutionTaskResponse> {
        self.prune_expired_tasks().await;
        self.tasks
            .read()
            .await
            .get(task_id)
            .map(|task| task.response.clone())
    }

    async fn subscribe(
        &self,
        task_id: &str,
    ) -> Result<
        (
            Vec<ExecutionTaskEvent>,
            broadcast::Receiver<ExecutionTaskEvent>,
        ),
        ProtocolError,
    > {
        self.prune_expired_tasks().await;
        let tasks = self.tasks.read().await;
        let task = tasks
            .get(task_id)
            .ok_or_else(|| task_not_found_error(task_id))?;
        Ok((task.event_history.clone(), task.event_sender.subscribe()))
    }

    async fn prune_expired_tasks(&self) {
        prune_expired_tasks_with_policy(&self.tasks, self.retention).await;
    }
}

impl<B> JudgeJobTaskManager<B>
where
    B: ProtocolBackend,
{
    fn new(backend: Arc<B>, store: Arc<JudgeJobStore>) -> Self {
        Self::with_policy(backend, store, AsyncTaskRetentionPolicy::default())
    }

    fn with_policy(
        backend: Arc<B>,
        store: Arc<JudgeJobStore>,
        retention: AsyncTaskRetentionPolicy,
    ) -> Self {
        Self {
            backend,
            next_task_id: AtomicU64::new(1),
            retention,
            store,
            tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn submit(
        &self,
        request: JudgeJobRequest,
    ) -> Result<JudgeJobTaskAccepted, ProtocolError> {
        request.validate()?;
        let request_id = request.request_id.clone();
        let task_id = format!(
            "judge-{}",
            self.next_task_id.fetch_add(1, Ordering::Relaxed)
        );
        let accepted = JudgeJobTaskAccepted {
            task_id: task_id.clone(),
            request_id: request_id.clone(),
            status: ExecutionTaskStatus::Accepted,
        };
        let (event_sender, _) = broadcast::channel(32);
        let accepted_event = JudgeJobTaskEvent {
            sequence: 0,
            task_id: task_id.clone(),
            request_id: request_id.clone(),
            event_type: "task_status".to_string(),
            status: Some(ExecutionTaskStatus::Accepted),
            stage: None,
            message: judge_job_task_event_message(ExecutionTaskStatus::Accepted).to_string(),
        };

        let mut tasks = self.tasks.write().await;
        prune_expired_judge_job_tasks_locked(&mut tasks, self.retention, Instant::now());
        if tasks.len() >= self.retention.max_tasks {
            return Err(async_task_capacity_exceeded_error(
                self.retention.max_tasks,
                &request_id,
            ));
        }
        tasks.insert(
            task_id.clone(),
            StoredJudgeJobTask {
                response: JudgeJobTaskResponse {
                    task_id: task_id.clone(),
                    request_id: request_id.clone(),
                    status: ExecutionTaskStatus::Accepted,
                    report: None,
                    error: None,
                },
                completed_at: None,
                next_event_sequence: 1,
                event_history: vec![accepted_event],
                event_sender,
            },
        );
        drop(tasks);

        let backend = Arc::clone(&self.backend);
        let store = Arc::clone(&self.store);
        let tasks = Arc::clone(&self.tasks);
        let retention = self.retention;
        tokio::spawn(async move {
            update_judge_job_task_status(
                &tasks,
                &task_id,
                ExecutionTaskStatus::Running,
                None,
                None,
            )
            .await;
            match backend.execute_judge_job(request).await {
                Ok(report) => {
                    store.insert(report.clone()).await;
                    append_judge_job_audit_events(&tasks, &task_id, &report.audit_events).await;
                    update_judge_job_task_status(
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
                    update_judge_job_task_status(
                        &tasks,
                        &task_id,
                        ExecutionTaskStatus::Failed,
                        None,
                        Some(detail),
                    )
                    .await;
                }
            }
            prune_expired_judge_job_tasks_with_policy(&tasks, retention).await;
        });

        Ok(accepted)
    }

    async fn get(&self, task_id: &str) -> Option<JudgeJobTaskResponse> {
        self.prune_expired_tasks().await;
        self.tasks
            .read()
            .await
            .get(task_id)
            .map(|task| task.response.clone())
    }

    async fn subscribe(
        &self,
        task_id: &str,
    ) -> Result<
        (
            Vec<JudgeJobTaskEvent>,
            broadcast::Receiver<JudgeJobTaskEvent>,
        ),
        ProtocolError,
    > {
        self.prune_expired_tasks().await;
        let tasks = self.tasks.read().await;
        let task = tasks
            .get(task_id)
            .ok_or_else(|| judge_job_task_not_found_error(task_id))?;
        Ok((task.event_history.clone(), task.event_sender.subscribe()))
    }

    async fn prune_expired_tasks(&self) {
        prune_expired_judge_job_tasks_with_policy(&self.tasks, self.retention).await;
    }
}

#[derive(Debug, Default)]
struct JudgeJobStore {
    retention: JudgeJobStoreRetentionPolicy,
    jobs: Arc<RwLock<HashMap<String, StoredJudgeJobReport>>>,
}

impl JudgeJobStore {
    fn new() -> Self {
        Self::with_policy(JudgeJobStoreRetentionPolicy::default())
    }

    fn with_policy(retention: JudgeJobStoreRetentionPolicy) -> Self {
        Self {
            retention,
            jobs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn insert(&self, report: JudgeJobReport) {
        let now = Instant::now();
        let mut jobs = self.jobs.write().await;
        prune_expired_judge_job_reports_locked(&mut jobs, self.retention, now);
        evict_judge_job_reports_to_capacity(&mut jobs, self.retention.max_jobs);
        jobs.insert(
            report.request.request_id.clone(),
            StoredJudgeJobReport {
                report,
                stored_at: now,
            },
        );
    }

    async fn get(&self, request_id: &str) -> Option<JudgeJobReport> {
        let now = Instant::now();
        let mut jobs = self.jobs.write().await;
        prune_expired_judge_job_reports_locked(&mut jobs, self.retention, now);
        jobs.get(request_id).map(|entry| entry.report.clone())
    }
}

#[derive(Debug, Clone, Copy)]
struct JudgeJobStoreRetentionPolicy {
    ttl: Duration,
    max_jobs: usize,
}

impl Default for JudgeJobStoreRetentionPolicy {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(5 * 60),
            max_jobs: 1_024,
        }
    }
}

#[derive(Debug, Clone)]
struct StoredJudgeJobReport {
    report: JudgeJobReport,
    stored_at: Instant,
}

async fn update_task_status(
    tasks: &RwLock<HashMap<String, StoredExecutionTask>>,
    task_id: &str,
    status: ExecutionTaskStatus,
    report: Option<ExecutionReport>,
    error: Option<ErrorDetail>,
) {
    let mut guard = tasks.write().await;
    if let Some(task) = guard.get_mut(task_id) {
        task.response.status = status;
        task.response.report = report;
        task.response.error = error;
        let event = ExecutionTaskEvent {
            sequence: task.next_event_sequence,
            task_id: task.response.task_id.clone(),
            request_id: task.response.request_id.clone(),
            status,
            stage: Some("execution".to_string()),
            message: execution_task_event_message(status).to_string(),
        };
        task.next_event_sequence += 1;
        task.event_history.push(event.clone());
        let _ = task.event_sender.send(event);
        task.completed_at = matches!(
            status,
            ExecutionTaskStatus::Completed | ExecutionTaskStatus::Failed
        )
        .then_some(Instant::now());
    }
}

async fn update_judge_job_task_status(
    tasks: &RwLock<HashMap<String, StoredJudgeJobTask>>,
    task_id: &str,
    status: ExecutionTaskStatus,
    report: Option<JudgeJobReport>,
    error: Option<ErrorDetail>,
) {
    let mut guard = tasks.write().await;
    if let Some(task) = guard.get_mut(task_id) {
        task.response.status = status;
        task.response.report = report;
        task.response.error = error;
        let event = JudgeJobTaskEvent {
            sequence: task.next_event_sequence,
            task_id: task.response.task_id.clone(),
            request_id: task.response.request_id.clone(),
            event_type: "task_status".to_string(),
            status: Some(status),
            stage: None,
            message: judge_job_task_event_message(status).to_string(),
        };
        task.next_event_sequence += 1;
        task.event_history.push(event.clone());
        let _ = task.event_sender.send(event);
        task.completed_at = matches!(
            status,
            ExecutionTaskStatus::Completed | ExecutionTaskStatus::Failed
        )
        .then_some(Instant::now());
    }
}

async fn append_judge_job_audit_events(
    tasks: &RwLock<HashMap<String, StoredJudgeJobTask>>,
    task_id: &str,
    audit_events: &[AuditEvent],
) {
    let mut guard = tasks.write().await;
    if let Some(task) = guard.get_mut(task_id) {
        for audit_event in audit_events {
            let event = JudgeJobTaskEvent {
                sequence: task.next_event_sequence,
                task_id: task.response.task_id.clone(),
                request_id: task.response.request_id.clone(),
                event_type: "stage".to_string(),
                status: None,
                stage: Some(audit_event.stage.clone()),
                message: audit_event.message.clone(),
            };
            task.next_event_sequence += 1;
            task.event_history.push(event.clone());
            let _ = task.event_sender.send(event);
        }
    }
}

async fn prune_expired_tasks_with_policy(
    tasks: &RwLock<HashMap<String, StoredExecutionTask>>,
    retention: AsyncTaskRetentionPolicy,
) {
    let now = Instant::now();
    let mut guard = tasks.write().await;
    prune_expired_tasks_locked(&mut guard, retention, now);
}

fn prune_expired_tasks_locked(
    tasks: &mut HashMap<String, StoredExecutionTask>,
    retention: AsyncTaskRetentionPolicy,
    now: Instant,
) {
    tasks.retain(|_, task| {
        task.completed_at
            .map(|completed_at| now.duration_since(completed_at) < retention.completed_ttl)
            .unwrap_or(true)
    });
}

async fn prune_expired_judge_job_tasks_with_policy(
    tasks: &RwLock<HashMap<String, StoredJudgeJobTask>>,
    retention: AsyncTaskRetentionPolicy,
) {
    let now = Instant::now();
    let mut guard = tasks.write().await;
    prune_expired_judge_job_tasks_locked(&mut guard, retention, now);
}

fn prune_expired_judge_job_tasks_locked(
    tasks: &mut HashMap<String, StoredJudgeJobTask>,
    retention: AsyncTaskRetentionPolicy,
    now: Instant,
) {
    tasks.retain(|_, task| {
        task.completed_at
            .map(|completed_at| now.duration_since(completed_at) < retention.completed_ttl)
            .unwrap_or(true)
    });
}

fn prune_expired_judge_job_reports_locked(
    jobs: &mut HashMap<String, StoredJudgeJobReport>,
    retention: JudgeJobStoreRetentionPolicy,
    now: Instant,
) {
    jobs.retain(|_, entry| now.duration_since(entry.stored_at) < retention.ttl);
}

fn evict_judge_job_reports_to_capacity(
    jobs: &mut HashMap<String, StoredJudgeJobReport>,
    max_jobs: usize,
) {
    if max_jobs == 0 {
        jobs.clear();
        return;
    }

    while jobs.len() >= max_jobs {
        let Some(oldest_key) = jobs
            .iter()
            .min_by_key(|(_, entry)| entry.stored_at)
            .map(|(request_id, _)| request_id.clone())
        else {
            break;
        };
        jobs.remove(&oldest_key);
    }
}

pub fn build_router<B>(backend: B) -> Router
where
    B: ProtocolBackend,
{
    build_router_with_options(backend, ProtocolServerOptions::default())
}

pub fn build_router_with_options<B>(backend: B, options: ProtocolServerOptions) -> Router
where
    B: ProtocolBackend,
{
    let backend = Arc::new(backend);
    let api_middleware_state = ApiMiddlewareState::from_options(&options);
    let health_backend = Arc::clone(&backend);
    let capabilities_backend = Arc::clone(&backend);
    let validate_backend = Arc::clone(&backend);
    let execute_backend = Arc::clone(&backend);
    let judge_job_backend = Arc::clone(&backend);
    let judge_job_store = Arc::new(JudgeJobStore::new());
    let judge_job_submit_store = Arc::clone(&judge_job_store);
    let judge_job_index_store = Arc::clone(&judge_job_store);
    let judge_job_file_store = Arc::clone(&judge_job_store);
    let async_judge_job_manager = Arc::new(JudgeJobTaskManager::new(
        Arc::clone(&backend),
        Arc::clone(&judge_job_store),
    ));
    let async_judge_job_submit_manager = Arc::clone(&async_judge_job_manager);
    let async_judge_job_status_manager = Arc::clone(&async_judge_job_manager);
    let async_judge_job_events_manager = Arc::clone(&async_judge_job_manager);
    let async_submit_manager = Arc::new(ExecutionTaskManager::new(Arc::clone(&backend)));
    let async_status_manager = Arc::clone(&async_submit_manager);
    let async_events_manager = Arc::clone(&async_submit_manager);

    let api_router = Router::new()
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
                    let store = Arc::clone(&judge_job_submit_store);
                    async move {
                        let Json(request) = payload.map_err(json_rejection_to_protocol_error)?;
                        let report = backend.execute_judge_job(request).await?;
                        store.insert(report.clone()).await;
                        Ok::<Json<JudgeJobReport>, ProtocolError>(Json(report))
                    }
                },
            ),
        )
        .route(
            "/api/v1/judge-jobs/async",
            post(
                move |payload: Result<Json<JudgeJobRequest>, JsonRejection>| {
                    let manager = Arc::clone(&async_judge_job_submit_manager);
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
            "/api/v1/judge-jobs/tasks/{task_id}",
            get(move |AxumPath(task_id): AxumPath<String>| {
                let manager = Arc::clone(&async_judge_job_status_manager);
                async move {
                    manager
                        .get(&task_id)
                        .await
                        .ok_or_else(|| judge_job_task_not_found_error(&task_id))
                        .map(Json)
                }
            }),
        )
        .route(
            "/api/v1/judge-jobs/tasks/{task_id}/events",
            get(move |AxumPath(task_id): AxumPath<String>| {
                let manager = Arc::clone(&async_judge_job_events_manager);
                async move {
                    let (history, mut receiver) = manager.subscribe(&task_id).await?;
                    let stream = stream! {
                        for event in history {
                            let terminal = event.is_terminal();
                            yield judge_job_task_sse_event(&event);
                            if terminal {
                                return;
                            }
                        }

                        loop {
                            match receiver.recv().await {
                                Ok(event) => {
                                    let terminal = event.is_terminal();
                                    yield judge_job_task_sse_event(&event);
                                    if terminal {
                                        break;
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => {
                                    continue;
                                }
                                Err(broadcast::error::RecvError::Closed) => {
                                    break;
                                }
                            }
                        }
                    };
                    Ok::<_, ProtocolError>(Sse::new(stream).keep_alive(KeepAlive::default()))
                }
            }),
        )
        .route(
            "/api/v1/judge-jobs/{request_id}/artifacts",
            get(move |AxumPath(request_id): AxumPath<String>| {
                let store = Arc::clone(&judge_job_index_store);
                async move {
                    let report = store
                        .get(&request_id)
                        .await
                        .ok_or_else(|| judge_job_not_found_error(&request_id))?;
                    build_judge_job_artifact_index(&report).map(Json)
                }
            }),
        )
        .route(
            "/api/v1/judge-jobs/{request_id}/artifacts/{stage}/file",
            get(
                move |AxumPath((request_id, stage)): AxumPath<(String, String)>,
                      Query(query): Query<ArtifactFileQuery>| {
                    let store = Arc::clone(&judge_job_file_store);
                    async move {
                        let stage = parse_stage_name(&stage)?;
                        let report = store
                            .get(&request_id)
                            .await
                            .ok_or_else(|| judge_job_not_found_error(&request_id))?;
                        let full_path =
                            resolve_downloadable_stage_file(&report, stage, &query.path)?;
                        let body = fs::read(&full_path).map_err(|err| {
                            ProtocolError::from(SandboxError::io("reading artifact file", err))
                        })?;
                        let content_type =
                            HeaderValue::from_static(content_type_for_artifact(&full_path));
                        Ok::<_, ProtocolError>(([(CONTENT_TYPE, content_type)], body))
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
            "/api/v1/executions/{task_id}/events",
            get(move |AxumPath(task_id): AxumPath<String>| {
                let manager = Arc::clone(&async_events_manager);
                async move {
                    let (history, mut receiver) = manager.subscribe(&task_id).await?;
                    let stream = stream! {
                        for event in history {
                            let terminal = event.is_terminal();
                            yield execution_task_sse_event(&event);
                            if terminal {
                                return;
                            }
                        }

                        loop {
                            match receiver.recv().await {
                                Ok(event) => {
                                    let terminal = event.is_terminal();
                                    yield execution_task_sse_event(&event);
                                    if terminal {
                                        break;
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => {
                                    continue;
                                }
                                Err(broadcast::error::RecvError::Closed) => {
                                    break;
                                }
                            }
                        }
                    };
                    Ok::<_, ProtocolError>(Sse::new(stream).keep_alive(KeepAlive::default()))
                }
            }),
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
        .layer(DefaultBodyLimit::max(options.max_request_body_bytes))
        .route_layer(middleware::from_fn_with_state(
            api_middleware_state,
            api_guard_middleware,
        ));

    Router::new()
        .route(
            "/healthz",
            get(move || {
                let backend = Arc::clone(&health_backend);
                async move { Json(backend.health().await) }
            }),
        )
        .merge(api_router)
        .method_not_allowed_fallback(|| async { method_not_allowed_error() })
        .fallback(|| async { not_found_error() })
}

pub fn default_router() -> Router {
    build_router_with_options(SupervisorBackend, ProtocolServerOptions::default())
}

pub async fn serve(addr: SocketAddr) -> std::io::Result<()> {
    serve_with_options(addr, ProtocolServerOptions::default()).await
}

pub async fn serve_with_options(
    addr: SocketAddr,
    options: ProtocolServerOptions,
) -> std::io::Result<()> {
    info!(%addr, "starting sandbox protocol server");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        build_router_with_options(SupervisorBackend, options),
    )
    .await
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
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
        let artifact_dir = unique_test_artifact_dir("judge-run");
        JudgeJobRequest {
            request_id: "judge-run-001".to_string(),
            artifact_dir: Some(artifact_dir),
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
        let artifact_dir = unique_test_artifact_dir("judge-pipeline");
        JudgeJobRequest {
            request_id: "judge-pipeline-001".to_string(),
            artifact_dir: Some(artifact_dir),
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

    fn unique_test_artifact_dir(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("sandbox-protocol-{prefix}-{stamp}"))
    }

    fn sample_execution_request(request_id: &str) -> ExecutionRequest {
        ExecutionRequest {
            request_id: request_id.to_string(),
            config: sample_config(),
            command_override: None,
            artifact_dir: None,
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
        let request = sample_judge_job_request();
        let expected_artifact_dir = request.artifact_dir.clone().unwrap().join("run");
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
        assert_eq!(body.request.request_id, "judge-run-001");
        assert_eq!(body.status, JudgeJobStatus::Completed);
        assert!(body.compile.is_none());
        assert!(body.checker.is_none());
        assert_eq!(body.run.stage, JudgeStageName::Run);
        assert_eq!(body.run.status, JudgeStageStatus::Completed);
        assert_eq!(body.run.artifact_dir, Some(expected_artifact_dir));
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
        let artifact_root = request.artifact_dir.clone().unwrap();
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
            Some(artifact_root.join("compile"))
        );
        assert_eq!(body.run.artifact_dir, Some(artifact_root.join("run")));
        assert_eq!(
            body.checker
                .as_ref()
                .map(|report| report.artifact_dir.clone())
                .flatten(),
            Some(artifact_root.join("checker"))
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

    #[tokio::test]
    async fn judge_job_artifact_index_lists_stage_files() {
        let app = build_router(TestBackend);
        let request = sample_multi_stage_judge_job_request();
        let payload = serde_json::to_vec(&request).unwrap();
        let submit_response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/judge-jobs")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;
        assert_eq!(submit_response.status(), StatusCode::OK);

        let response = send(
            &app,
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/judge-jobs/{}/artifacts",
                    request.request_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: JudgeJobArtifactIndexResponse = response_json(response).await;
        assert_eq!(body.request_id, request.request_id);
        assert_eq!(body.stages.len(), 3);
        let compile_stage = body
            .stages
            .iter()
            .find(|stage| stage.stage == JudgeStageName::Compile)
            .unwrap();
        assert!(
            compile_stage
                .artifacts
                .iter()
                .any(|entry| entry.path == PathBuf::from("stdout.log"))
        );
        assert!(
            compile_stage
                .artifacts
                .iter()
                .any(|entry| entry.path == PathBuf::from("outputs/program.txt"))
        );
    }

    #[tokio::test]
    async fn judge_job_artifact_download_reads_stdout_and_output_files() {
        let app = build_router(TestBackend);
        let request = sample_multi_stage_judge_job_request();
        let payload = serde_json::to_vec(&request).unwrap();
        let submit_response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/judge-jobs")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;
        assert_eq!(submit_response.status(), StatusCode::OK);

        let stdout_response = send(
            &app,
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/judge-jobs/{}/artifacts/run/file?path=stdout.log",
                    request.request_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(stdout_response.status(), StatusCode::OK);
        let stdout_bytes = to_bytes(stdout_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8(stdout_bytes.to_vec()).unwrap(),
            "compiled output\n"
        );

        let output_response = send(
            &app,
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/judge-jobs/{}/artifacts/compile/file?path=outputs/program.txt",
                    request.request_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(output_response.status(), StatusCode::OK);
        let output_bytes = to_bytes(output_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8(output_bytes.to_vec()).unwrap(),
            "compiled output\n"
        );
    }

    #[tokio::test]
    async fn judge_job_artifact_download_rejects_path_escape() {
        let app = build_router(TestBackend);
        let request = sample_multi_stage_judge_job_request();
        let payload = serde_json::to_vec(&request).unwrap();
        let submit_response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/judge-jobs")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;
        assert_eq!(submit_response.status(), StatusCode::OK);

        let response = send(
            &app,
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/judge-jobs/{}/artifacts/compile/file?path=../secret",
                    request.request_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "invalid_request");
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

    #[tokio::test]
    async fn healthz_remains_accessible_when_auth_is_enabled() {
        let app = build_router_with_options(
            TestBackend,
            ProtocolServerOptions {
                auth_token: Some("secret-token".to_string()),
                ..ProtocolServerOptions::default()
            },
        );
        let response = send(
            &app,
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_routes_require_bearer_auth_when_configured() {
        let app = build_router_with_options(
            TestBackend,
            ProtocolServerOptions {
                auth_token: Some("secret-token".to_string()),
                ..ProtocolServerOptions::default()
            },
        );
        let payload = serde_json::to_vec(&ExecutionRequest {
            request_id: "auth-run-001".to_string(),
            config: sample_config(),
            command_override: None,
            artifact_dir: None,
        })
        .unwrap();

        let unauthorized_response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions")
                .header("content-type", "application/json")
                .body(Body::from(payload.clone()))
                .unwrap(),
        )
        .await;
        assert_eq!(unauthorized_response.status(), StatusCode::UNAUTHORIZED);
        let unauthorized_body: ErrorResponse = response_json(unauthorized_response).await;
        assert_eq!(unauthorized_body.error.code, "unauthorized");

        let authorized_response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions")
                .header("content-type", "application/json")
                .header("authorization", "Bearer secret-token")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;
        assert_eq!(authorized_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn body_limit_rejects_large_requests() {
        let app = build_router_with_options(
            TestBackend,
            ProtocolServerOptions {
                max_request_body_bytes: 16,
                ..ProtocolServerOptions::default()
            },
        );
        let payload = vec![b'a'; 128];
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions")
                .header("content-type", "application/json")
                .header("content-length", payload.len().to_string())
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "request_too_large");
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

        fn execute_judge_job(
            &self,
            request: JudgeJobRequest,
        ) -> BackendFuture<Result<JudgeJobReport, ProtocolError>> {
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

                let artifact_dir = request.resolved_stage_artifact_dir(JudgeStageName::Run);
                let command = request
                    .run
                    .command_override
                    .clone()
                    .unwrap_or_else(|| request.run.config.process.argv.clone());
                Ok(JudgeJobReport {
                    request: request.clone(),
                    status: JudgeJobStatus::Completed,
                    compile: None,
                    run: JudgeStageReport {
                        stage: JudgeStageName::Run,
                        request: request.run.clone(),
                        status: JudgeStageStatus::Completed,
                        artifact_dir: Some(artifact_dir.clone()),
                        result: Some(ExecutionResult {
                            command,
                            exit_code: Some(0),
                            term_signal: None,
                            usage: ResourceUsage {
                                cpu_time_ms: Some(1),
                                wall_time_ms: 2,
                                memory_peak_bytes: Some(3),
                            },
                            stdout_path: artifact_dir.join("stdout.log"),
                            stderr_path: artifact_dir.join("stderr.log"),
                            status: ExecutionStatus::Ok,
                        }),
                        compilation_result: None,
                        artifacts: vec![
                            JudgeStageArtifact {
                                name: "stdout".to_string(),
                                kind: JudgeArtifactKind::Stdout,
                                path: artifact_dir.join("stdout.log"),
                            },
                            JudgeStageArtifact {
                                name: "stderr".to_string(),
                                kind: JudgeArtifactKind::Stderr,
                                path: artifact_dir.join("stderr.log"),
                            },
                        ],
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
                        error: None,
                    },
                    checker: None,
                    audit_events: vec![
                        AuditEvent {
                            stage: "accepted".to_string(),
                            message: "judge job accepted".to_string(),
                        },
                        AuditEvent {
                            stage: "completed".to_string(),
                            message: "judge job finished with status `completed`".to_string(),
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

    async fn fetch_task_events_response(app: &Router, task_id: &str) -> Response {
        send(
            app,
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/executions/{task_id}/events"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn fetch_judge_job_task_response(app: &Router, task_id: &str) -> Response {
        send(
            app,
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/judge-jobs/tasks/{task_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn fetch_judge_job_task_events_response(app: &Router, task_id: &str) -> Response {
        send(
            app,
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/judge-jobs/tasks/{task_id}/events"))
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
    async fn concurrency_limit_rejects_parallel_api_requests() {
        let backend = GatedBackend::success();
        let app = build_router_with_options(
            backend.clone(),
            ProtocolServerOptions {
                max_concurrent_requests: 1,
                ..ProtocolServerOptions::default()
            },
        );
        let payload = serde_json::to_vec(&ExecutionRequest {
            request_id: "concurrency-run-001".to_string(),
            config: sample_config(),
            command_override: None,
            artifact_dir: None,
        })
        .unwrap();

        let app_for_first = app.clone();
        let first_request = Request::builder()
            .method("POST")
            .uri("/api/v1/executions")
            .header("content-type", "application/json")
            .body(Body::from(payload.clone()))
            .unwrap();
        let first_handle = tokio::spawn(async move {
            app_for_first
                .oneshot(first_request)
                .await
                .expect("first request should execute")
        });

        backend.started.notified().await;

        let second_response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(second_response.status(), StatusCode::TOO_MANY_REQUESTS);
        let second_body: ErrorResponse = response_json(second_response).await;
        assert_eq!(second_body.error.code, "concurrency_limit_exceeded");

        backend.gate.notify_waiters();
        let first_response = first_handle.await.expect("first request task should join");
        assert_eq!(first_response.status(), StatusCode::OK);
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
    async fn async_judge_job_returns_accepted_and_completed_status() {
        let backend = GatedBackend::success();
        let app = build_router(backend.clone());
        let payload = serde_json::to_vec(&sample_judge_job_request()).unwrap();

        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/judge-jobs/async")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let accepted: JudgeJobTaskAccepted = response_json(response).await;
        assert_eq!(accepted.request_id, "judge-run-001");
        assert_eq!(accepted.status, ExecutionTaskStatus::Accepted);
        assert!(accepted.task_id.starts_with("judge-"));

        backend.started.notified().await;

        let running_response = fetch_judge_job_task_response(&app, &accepted.task_id).await;
        assert_eq!(running_response.status(), StatusCode::OK);
        let running: JudgeJobTaskResponse = response_json(running_response).await;
        assert_eq!(running.status, ExecutionTaskStatus::Running);
        assert!(running.report.is_none());
        assert!(running.error.is_none());

        backend.gate.notify_waiters();

        for _ in 0..20 {
            let completed_response = fetch_judge_job_task_response(&app, &accepted.task_id).await;
            let completed: JudgeJobTaskResponse = response_json(completed_response).await;
            if completed.status == ExecutionTaskStatus::Completed {
                assert_eq!(completed.request_id, "judge-run-001");
                assert!(completed.error.is_none());
                assert_eq!(
                    completed.report.as_ref().map(|report| report.status),
                    Some(JudgeJobStatus::Completed)
                );

                let artifacts_response = send(
                    &app,
                    Request::builder()
                        .method("GET")
                        .uri("/api/v1/judge-jobs/judge-run-001/artifacts")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await;
                assert_eq!(artifacts_response.status(), StatusCode::OK);
                return;
            }
            tokio::task::yield_now().await;
        }

        panic!("async judge job task did not complete in time");
    }

    #[tokio::test]
    async fn async_judge_job_persists_failures_in_task_status() {
        let backend = GatedBackend::failure();
        let app = build_router(backend.clone());
        let payload = serde_json::to_vec(&sample_judge_job_request()).unwrap();

        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/judge-jobs/async")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let accepted: JudgeJobTaskAccepted = response_json(response).await;
        backend.started.notified().await;
        backend.gate.notify_waiters();

        for _ in 0..20 {
            let failed_response = fetch_judge_job_task_response(&app, &accepted.task_id).await;
            let failed: JudgeJobTaskResponse = response_json(failed_response).await;
            if failed.status == ExecutionTaskStatus::Failed {
                assert!(failed.report.is_none());
                assert_eq!(
                    failed.error.as_ref().map(|error| error.code.as_str()),
                    Some("capability_unavailable")
                );
                return;
            }
            tokio::task::yield_now().await;
        }

        panic!("async judge job task did not fail in time");
    }

    #[tokio::test]
    async fn async_task_manager_prunes_completed_tasks_after_ttl() {
        let backend = Arc::new(GatedBackend::success());
        let manager = ExecutionTaskManager::with_policy(
            Arc::clone(&backend),
            AsyncTaskRetentionPolicy {
                completed_ttl: Duration::from_millis(20),
                max_tasks: 4,
            },
        );

        let accepted = manager
            .submit(sample_execution_request("async-expire-001"))
            .await
            .expect("submission should succeed");
        backend.started.notified().await;
        backend.gate.notify_waiters();

        for _ in 0..20 {
            if manager
                .get(&accepted.task_id)
                .await
                .is_some_and(|task| task.status == ExecutionTaskStatus::Completed)
            {
                break;
            }
            tokio::task::yield_now().await;
        }

        thread::sleep(Duration::from_millis(30));
        assert!(manager.get(&accepted.task_id).await.is_none());
    }

    #[tokio::test]
    async fn async_task_manager_rejects_new_submissions_when_capacity_is_reached() {
        let backend = Arc::new(GatedBackend::success());
        let manager = ExecutionTaskManager::with_policy(
            Arc::clone(&backend),
            AsyncTaskRetentionPolicy {
                completed_ttl: Duration::from_secs(60),
                max_tasks: 1,
            },
        );

        let _accepted = manager
            .submit(sample_execution_request("async-capacity-001"))
            .await
            .expect("first submission should succeed");
        backend.started.notified().await;

        let error = manager
            .submit(sample_execution_request("async-capacity-002"))
            .await
            .expect_err("second submission should be rejected");

        assert_eq!(error.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.code, "task_capacity_exceeded");
        assert_eq!(error.request_id.as_deref(), Some("async-capacity-002"));

        backend.gate.notify_waiters();
    }

    #[tokio::test]
    async fn async_task_manager_accepts_new_submissions_after_expired_cleanup() {
        let backend = Arc::new(GatedBackend::success());
        let manager = ExecutionTaskManager::with_policy(
            Arc::clone(&backend),
            AsyncTaskRetentionPolicy {
                completed_ttl: Duration::from_millis(20),
                max_tasks: 1,
            },
        );

        let accepted = manager
            .submit(sample_execution_request("async-reuse-001"))
            .await
            .expect("first submission should succeed");
        backend.started.notified().await;
        backend.gate.notify_waiters();

        for _ in 0..20 {
            if manager
                .get(&accepted.task_id)
                .await
                .is_some_and(|task| task.status == ExecutionTaskStatus::Completed)
            {
                break;
            }
            tokio::task::yield_now().await;
        }

        thread::sleep(Duration::from_millis(30));

        let accepted_second = manager
            .submit(sample_execution_request("async-reuse-002"))
            .await
            .expect("expired task should have been cleaned up");
        assert_ne!(accepted.task_id, accepted_second.task_id);
    }

    #[tokio::test]
    async fn judge_job_store_prunes_reports_after_ttl() {
        let store = JudgeJobStore::with_policy(JudgeJobStoreRetentionPolicy {
            ttl: Duration::from_millis(20),
            max_jobs: 4,
        });
        let request = sample_judge_job_request();
        let request_id = request.request_id.clone();
        let report = JudgeJobReport {
            request: request.clone(),
            status: JudgeJobStatus::Completed,
            compile: None,
            run: JudgeStageReport {
                stage: JudgeStageName::Run,
                request: request.run,
                status: JudgeStageStatus::Completed,
                artifact_dir: Some(unique_test_artifact_dir("judge-store-ttl")),
                result: None,
                compilation_result: None,
                artifacts: Vec::new(),
                audit_events: Vec::new(),
                error: None,
            },
            checker: None,
            audit_events: Vec::new(),
        };
        store.insert(report).await;

        assert!(store.get(&request_id).await.is_some());
        thread::sleep(Duration::from_millis(30));
        assert!(store.get(&request_id).await.is_none());
    }

    #[tokio::test]
    async fn judge_job_store_evicts_oldest_reports_when_capacity_is_reached() {
        let store = JudgeJobStore::with_policy(JudgeJobStoreRetentionPolicy {
            ttl: Duration::from_secs(60),
            max_jobs: 2,
        });

        for request_id in ["judge-store-001", "judge-store-002", "judge-store-003"] {
            let request = JudgeJobRequest {
                request_id: request_id.to_string(),
                artifact_dir: Some(unique_test_artifact_dir(request_id)),
                compile: None,
                run: JudgeStageRequest {
                    config: sample_config(),
                    command_override: None,
                    artifact_dir: None,
                    inputs: JudgeStageInputs::default(),
                },
                checker: None,
            };
            let report = JudgeJobReport {
                request: request.clone(),
                status: JudgeJobStatus::Completed,
                compile: None,
                run: JudgeStageReport {
                    stage: JudgeStageName::Run,
                    request: request.run,
                    status: JudgeStageStatus::Completed,
                    artifact_dir: Some(unique_test_artifact_dir(request_id)),
                    result: None,
                    compilation_result: None,
                    artifacts: Vec::new(),
                    audit_events: Vec::new(),
                    error: None,
                },
                checker: None,
                audit_events: Vec::new(),
            };
            store.insert(report).await;
            thread::sleep(Duration::from_millis(5));
        }

        assert!(store.get("judge-store-001").await.is_none());
        assert!(store.get("judge-store-002").await.is_some());
        assert!(store.get("judge-store-003").await.is_some());
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

    #[tokio::test]
    async fn async_events_stream_replays_status_transitions_until_completion() {
        let backend = GatedBackend::success();
        let app = build_router(backend.clone());
        let payload = serde_json::to_vec(&ExecutionRequest {
            request_id: "async-stream-001".to_string(),
            config: sample_config(),
            command_override: Some(vec!["/bin/echo".to_string(), "stream".to_string()]),
            artifact_dir: Some("/tmp/sandbox-api/async-stream-001".into()),
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

        let events_response = fetch_task_events_response(&app, &accepted.task_id).await;
        assert_eq!(events_response.status(), StatusCode::OK);

        backend.gate.notify_waiters();

        let bytes = to_bytes(events_response.into_body(), usize::MAX)
            .await
            .expect("sse body should be readable");
        let body = String::from_utf8(bytes.to_vec()).expect("sse body should be utf-8");

        assert!(body.contains("event: task_status"));
        assert!(body.contains("\"status\":\"accepted\""));
        assert!(body.contains("\"status\":\"running\""));
        assert!(body.contains("\"status\":\"completed\""));
    }

    #[tokio::test]
    async fn async_events_returns_not_found_for_unknown_task() {
        let app = build_router(TestBackend);
        let response = fetch_task_events_response(&app, "missing-task").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "not_found");
        assert_eq!(
            body.error.message,
            "execution task `missing-task` was not found"
        );
    }

    #[tokio::test]
    async fn async_judge_job_events_stream_replays_status_and_stage_events() {
        let app = build_router(TestBackend);
        let payload = serde_json::to_vec(&sample_multi_stage_judge_job_request()).unwrap();

        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/judge-jobs/async")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let accepted: JudgeJobTaskAccepted = response_json(response).await;

        for _ in 0..20 {
            let completed_response = fetch_judge_job_task_response(&app, &accepted.task_id).await;
            let completed: JudgeJobTaskResponse = response_json(completed_response).await;
            if completed.status == ExecutionTaskStatus::Completed {
                break;
            }
            tokio::task::yield_now().await;
        }

        let events_response = fetch_judge_job_task_events_response(&app, &accepted.task_id).await;
        assert_eq!(events_response.status(), StatusCode::OK);
        let bytes = to_bytes(events_response.into_body(), usize::MAX)
            .await
            .expect("judge job sse body should be readable");
        let body = String::from_utf8(bytes.to_vec()).expect("judge job sse body should be utf-8");

        assert!(body.contains("event: task_status"));
        assert!(body.contains("event: stage"));
        assert!(body.contains("\"status\":\"accepted\""));
        assert!(body.contains("\"status\":\"running\""));
        assert!(body.contains("\"status\":\"completed\""));
        assert!(body.contains("\"stage\":\"compile_started\""));
        assert!(body.contains("\"stage\":\"completed\""));
    }

    #[tokio::test]
    async fn async_judge_job_status_returns_not_found_for_unknown_task() {
        let app = build_router(TestBackend);
        let response = fetch_judge_job_task_response(&app, "missing-task").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "not_found");
        assert_eq!(
            body.error.message,
            "judge job task `missing-task` was not found"
        );
    }

    #[tokio::test]
    async fn async_judge_job_events_returns_not_found_for_unknown_task() {
        let app = build_router(TestBackend);
        let response = fetch_judge_job_task_events_response(&app, "missing-task").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "not_found");
        assert_eq!(
            body.error.message,
            "judge job task `missing-task` was not found"
        );
    }
}
